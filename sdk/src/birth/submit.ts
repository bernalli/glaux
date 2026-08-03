import { encodeFunctionData, type Address, type Hex, type PublicClient } from "viem";
import { sendRawTransaction } from "viem/actions";
import { privateKeyToAddress, signTransaction } from "viem/accounts";
import type { BirthBlob } from "../core/types.js";
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
      { name: "birthSig", type: "bytes" },
    ],
    outputs: [],
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

/**
 * Enough for the worst case observed: a chain that answers P-256 with a
 * Solidity verifier at 0x100 rather than a precompile, where birth costs
 * ~1.4M gas. Unused gas is refunded; only the relayer's balance has to cover
 * the limit. Ported from `scripts/submit_birth.py`'s `FALLBACK_BIRTH_GAS`.
 */
const FALLBACK_BIRTH_GAS = 3_000_000n;

function buildInitializeCalldata(blob: BirthBlob): Hex {
  return encodeFunctionData({
    abi: INITIALIZE_ABI,
    functionName: "initialize",
    args: [blob.implementation, blob.expectedCodeHash, blob.initData, blob.birthSig],
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
 * undelegated account — and an implausibly cheap answer (or an estimate that
 * throws outright, which some nodes do pre-delegation) is treated as a node
 * that ignored the field rather than as a cheap birth.
 *
 * @throws {BirthPreflightError} if `blob.account` is not a pristine EOA.
 */
export async function submitBirth(
  client: PublicClient,
  relayer: Hex,
  blob: BirthBlob,
): Promise<SubmitBirthResult> {
  await preflightFreshAccount(client, blob.account);

  const relayerAddress = privateKeyToAddress(relayer);
  const data = buildInitializeCalldata(blob);
  const authorizationList = [toAuthorizationListEntry(blob)] as const;

  const [chainId, nonce, latestBlock, gasPrice, priorityFee] = await Promise.all([
    client.getChainId(),
    client.getTransactionCount({ address: relayerAddress }),
    client.getBlock(),
    client.getGasPrice(),
    client.estimateMaxPriorityFeePerGas(),
  ]);
  const baseFee = latestBlock.baseFeePerGas ?? gasPrice;
  const maxFeePerGas = baseFee * 2n + priorityFee;

  let estimate = 0n;
  try {
    estimate = await client.estimateGas({
      account: relayerAddress,
      to: blob.account,
      data,
      authorizationList,
    });
  } catch {
    estimate = 0n;
  }
  const gas = estimate >= MIN_PLAUSIBLE_BIRTH_GAS ? (estimate * 3n) / 2n + 100_000n : FALLBACK_BIRTH_GAS;

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
  await client.waitForTransactionReceipt({ hash: txHash });

  return { account: blob.account, txHash };
}
