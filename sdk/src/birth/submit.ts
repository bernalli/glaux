import {
  encodeAbiParameters,
  encodeFunctionData,
  keccak256,
  type Address,
  type Hex,
  type PublicClient,
} from "viem";
import { sendRawTransaction } from "viem/actions";
import { privateKeyToAddress, signTransaction } from "viem/accounts";
import { recoverAuthorizationAddress } from "viem/utils";
import { IMPL, IMPL_CODE_HASH, ROUTER, designator } from "../core/constants.js";
import { initDigest } from "../core/digests.js";
import { decodeInitData } from "../core/encoding.js";
import { assertRecoversTo } from "./blob.js";
import type { BirthBlob } from "../core/types.js";
import {
  BirthGasEstimationError,
  BirthPostconditionError,
  BirthTransactionRevertedError,
  ImplementationCodeHashMismatchError,
  ImplementationNotDeployedError,
  InvalidBirthBlobError,
} from "../errors.js";
import { assertExpectedChainId } from "../execute/direct.js";
import { preflightFreshAccount } from "./preflight.js";

const INITIALIZE_ABI = [
  {
    type: "function",
    name: "initialize",
    stateMutability: "nonpayable",
    inputs: [
      { name: "implementation", type: "address" },
      { name: "expectedCodeHash", type: "bytes32" },
      { name: "initData", type: "bytes" },
      { name: "salt", type: "bytes32" },
      { name: "s", type: "uint256" },
    ],
    outputs: [],
  },
] as const;

const BIRTH_READBACK_ABI = [
  {
    type: "function",
    name: "implementation",
    stateMutability: "view",
    inputs: [],
    outputs: [{ type: "address" }],
  },
  {
    type: "function",
    name: "getSlot",
    stateMutability: "view",
    inputs: [{ name: "index", type: "uint8" }],
    outputs: [
      { name: "verifierType", type: "uint8" },
      { name: "data", type: "bytes" },
    ],
  },
] as const;

/**
 * A real birth runs three possession-proof verifications and, when a P-256
 * factor is present, the verifier probe on top — nothing that does the job
 * costs less than this. An estimate below it means the node priced a call to
 * an account that is not delegated yet: the delegation and the call ride in
 * the SAME type-4 transaction, so a node that ignores the authorization list
 * sees a plain EOA and answers for a value transfer with calldata (~47k).
 * Trusting that number sends a transaction that runs out of gas mid-birth.
 * Ported from `scripts/submit_birth.py`'s `MIN_PLAUSIBLE_BIRTH_GAS`.
 */
const MIN_PLAUSIBLE_BIRTH_GAS = 200_000n;

function buildInitializeCalldata(blob: BirthBlob): Hex {
  return encodeFunctionData({
    abi: INITIALIZE_ABI,
    functionName: "initialize",
    args: [blob.implementation, blob.expectedCodeHash, blob.initData, blob.salt, BigInt(blob.authorization.s)],
  });
}

/** Rebuilds the viem `authorizationList` entry `signTransaction`/`estimateGas` expect from a blob. */
function toAuthorizationListEntry(blob: BirthBlob) {
  return {
    address: blob.authorization.address,
    chainId: blob.authorization.chainId,
    nonce: blob.authorization.nonce,
    r: blob.authorization.r,
    s: blob.authorization.s,
    yParity: blob.authorization.yParity,
  } as const;
}

export interface SubmitBirthResult {
  readonly account: Address;
  readonly txHash: Hex;
}

async function assertCanonicalBlob(blob: BirthBlob): Promise<void> {
  if (blob.router.toLowerCase() !== ROUTER.toLowerCase()) throw new InvalidBirthBlobError("router");
  if (blob.implementation.toLowerCase() !== IMPL.toLowerCase()) throw new InvalidBirthBlobError("implementation");
  if (blob.authorization.address.toLowerCase() !== blob.router.toLowerCase()) {
    throw new InvalidBirthBlobError("authorization target");
  }
  if (blob.authorization.chainId !== 0) {
    throw new InvalidBirthBlobError("authorization chain id");
  }
  // EIP-7702 validates the tuple's nonce against the authority's CURRENT
  // account nonce, so only nonce 0 is universally replayable: a birth key is
  // generated for one blob and never sends a transaction of its own, which
  // means every chain it has not reached yet sees it at nonce 0. Applying the
  // tuple bumps that authority's nonce to 1, which is exactly what makes the
  // blob single-use per chain while still replayable on every chain it has not
  // reached. A tuple signed for any other nonce is broadcastable, at best, on
  // the single chain that happens to match — the opposite of the chain-agnostic
  // blob this whole design rests on, and silently so, since the delegation is
  // simply skipped where it does not match. `./blob.ts` writes 0; an imported
  // blob must be checked.
  if (blob.authorization.nonce !== 0) {
    throw new InvalidBirthBlobError("authorization nonce");
  }
  let authorizationSigner: Address;
  try {
    authorizationSigner = await recoverAuthorizationAddress({ authorization: blob.authorization });
  } catch {
    throw new InvalidBirthBlobError("authorization signer");
  }
  if (authorizationSigner.toLowerCase() !== blob.account.toLowerCase()) {
    throw new InvalidBirthBlobError("authorization signer");
  }
  // Caller-supplied hex, compared case-insensitively like the addresses above:
  // `keccak256` and the canonical constant are lower-case, but an upper-case
  // hash off the wire names the same 32 bytes and must not be refused.
  if (blob.expectedCodeHash.toLowerCase() !== IMPL_CODE_HASH) {
    throw new ImplementationCodeHashMismatchError(blob.expectedCodeHash);
  }
  // Everything above establishes only that the blob agrees with itself: that
  // `account` really is what this tuple recovers to. The router does not check
  // that — it rebuilds the proof from the birth configuration and recovers with
  // a fixed v = 27. A blob can therefore be perfectly self-consistent and still
  // be one `initialize` refuses, and refusal is not free: EIP-7702 applies the
  // authorization regardless, so the address is left delegated, unborn, and —
  // having no key — beyond repair. Re-run the router's own authentication here,
  // before the relayer spends anything.
  const digest = initDigest(blob.router, blob.implementation, blob.expectedCodeHash, blob.initData);
  const expectedR = keccak256(
    encodeAbiParameters([{ type: "bytes32" }, { type: "bytes32" }], [digest, blob.salt]),
  );
  if (blob.authorization.r.toLowerCase() !== expectedR) {
    throw new InvalidBirthBlobError("authorization r");
  }
  if (blob.authorization.yParity !== 0) {
    throw new InvalidBirthBlobError("authorization parity");
  }
  if (!assertRecoversTo(digest, blob.salt, blob.authorization.s, blob.account)) {
    throw new InvalidBirthBlobError("authorization rootless proof");
  }
}

async function assertLiveImplementationHash(client: PublicClient, blob: BirthBlob): Promise<void> {
  let code: Hex | undefined;
  try {
    code = await client.getCode({ address: IMPL });
  } catch {
    throw new ImplementationNotDeployedError(IMPL);
  }
  if (code === undefined || code === "0x") throw new ImplementationNotDeployedError(IMPL);
  const liveHash = keccak256(code);
  if (liveHash !== IMPL_CODE_HASH || liveHash !== blob.expectedCodeHash.toLowerCase()) {
    throw new ImplementationCodeHashMismatchError(liveHash);
  }
}

async function assertBirthReadback(client: PublicClient, blob: BirthBlob): Promise<void> {
  let expectedSlots: readonly { readonly verifierType: number; readonly data: Hex }[];
  try {
    [expectedSlots] = decodeInitData(blob.initData);
  } catch {
    throw new BirthPostconditionError("the blob init data could not be decoded for readback");
  }
  try {
    const code = await client.getCode({ address: blob.account });
    if (code?.toLowerCase() !== designator()) throw new BirthPostconditionError("account code is not the canonical delegation designator");
    const implementation = await client.readContract({
      address: blob.account,
      abi: BIRTH_READBACK_ABI,
      functionName: "implementation",
    });
    if (implementation.toLowerCase() !== IMPL.toLowerCase()) {
      throw new BirthPostconditionError("installed implementation differs from the canonical implementation");
    }
    for (let index = 0; index < 3; index += 1) {
      const [verifierType, data] = await client.readContract({
        address: blob.account,
        abi: BIRTH_READBACK_ABI,
        functionName: "getSlot",
        args: [index],
      });
      const expected = expectedSlots[index]!;
      if (verifierType !== expected.verifierType || data.toLowerCase() !== expected.data.toLowerCase()) {
        throw new BirthPostconditionError(`installed factor slot ${index} differs from the blob`);
      }
    }
  } catch (error) {
    if (error instanceof BirthPostconditionError) throw error;
    throw new BirthPostconditionError("account state could not be read back");
  }
}

/**
 * Builds, signs, sends, and confirms the single EIP-7702 type-4 transaction
 * that births `blob.account` — port of `scripts/submit_birth.py:submit_birth`.
 * Runs `preflightFreshAccount` first (against the canonical router this SDK
 * always signs for), so a caller never has to remember to call it separately.
 *
 * `relayer` (a private key) only pays gas: submission is permissionless, the
 * relayer never needs to hold the birth key, and the same blob can be
 * broadcast by anyone, on any chain, exactly once.
 *
 * Gas is estimated WITH the authorization list attached — see
 * `MIN_PLAUSIBLE_BIRTH_GAS`'s documentation for why an estimate taken
 * without it is not trustworthy for a type-4 transaction against an
 * undelegated account. An implausibly cheap answer or an estimation failure
 * means the node may have ignored the authorization list, so this function
 * refuses to broadcast rather than silently substituting a fixed gas limit.
 *
 * @throws {BirthPreflightError} if `blob.account` is not a pristine EOA.
 * @throws {BirthGasEstimationError} if the authorization-aware estimate is
 * unavailable or implausibly low.
 * @throws {BirthTransactionRevertedError} if the transaction is mined but
 * initialization reverts.
 */
export async function submitBirth(
  client: PublicClient,
  relayer: Hex,
  blob: BirthBlob,
  expectedChainId: number,
): Promise<SubmitBirthResult> {
  await assertExpectedChainId(client, expectedChainId);
  const chainId = expectedChainId;
  await assertCanonicalBlob(blob);
  await preflightFreshAccount(client, blob.account);

  const relayerAddress = privateKeyToAddress(relayer);
  const data = buildInitializeCalldata(blob);
  const authorizationList = [toAuthorizationListEntry(blob)] as const;

  const [nonce, latestBlock, gasPrice, priorityFee] = await Promise.all([
    client.getTransactionCount({ address: relayerAddress }),
    client.getBlock(),
    client.getGasPrice(),
    client.estimateMaxPriorityFeePerGas(),
  ]);
  const baseFee = latestBlock.baseFeePerGas ?? gasPrice;
  const maxFeePerGas = baseFee * 2n + priorityFee;

  let estimate: bigint;
  try {
    estimate = await client.estimateGas({
      account: relayerAddress,
      to: blob.account,
      data,
      authorizationList,
    });
  } catch {
    throw new BirthGasEstimationError();
  }
  if (typeof estimate !== "bigint" || estimate < MIN_PLAUSIBLE_BIRTH_GAS) {
    throw new BirthGasEstimationError();
  }
  await assertLiveImplementationHash(client, blob);
  const gas = (estimate * 3n) / 2n + 100_000n;

  const signedTransaction = await signTransaction({
    privateKey: relayer,
    transaction: {
      chainId,
      nonce,
      to: blob.account,
      value: 0n,
      gas,
      maxFeePerGas,
      maxPriorityFeePerGas: priorityFee,
      data,
      authorizationList,
    },
  });

  const txHash = await sendRawTransaction(client, { serializedTransaction: signedTransaction });
  const receipt = await client.waitForTransactionReceipt({ hash: txHash });
  if (receipt.status !== "success") throw new BirthTransactionRevertedError(txHash);

  await assertBirthReadback(client, blob);

  return { account: blob.account, txHash };
}
