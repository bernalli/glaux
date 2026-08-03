import {
  BaseError,
  ContractFunctionRevertedError,
  encodeFunctionData,
  type Address,
  type Hex,
  type PublicClient,
} from "viem";
import { sendRawTransaction } from "viem/actions";
import { privateKeyToAddress, signTransaction } from "viem/accounts";
import { execDigest } from "../core/digests.js";
import { encodeSlotSig } from "../core/encoding.js";
import type { Call, SlotSig } from "../core/types.js";
import type { Signer } from "../signers/signer.js";
import {
  ExecutionExpiredError,
  ExecutionGasEstimationError,
  ExecutionRevertedError,
  ExecutionTransactionRevertedError,
  OperationExpiredError,
  UnrecognizedSignerError,
} from "../errors.js";

const CALL_TUPLE_COMPONENTS = [
  { name: "to", type: "address" },
  { name: "value", type: "uint256" },
  { name: "data", type: "bytes" },
] as const;

const SLOT_SIG_TUPLE_COMPONENTS = [
  { name: "slotIndex", type: "uint8" },
  { name: "signature", type: "bytes" },
] as const;

/**
 * The slice of `GlauxAccount`'s ABI this module needs: `executeWithSigs`
 * itself (`src/GlauxAccount.sol:247`, argument order `(calls, validUntil,
 * sigs)` verbatim), `execNonce`/`getSlot` for building a signature against
 * live chain state, and the custom errors `executeWithSigs` can revert with
 * (`src/GlauxStorage.sol:113-131`) so a pre-flight simulation can decode the
 * real revert reason instead of merely observing a revert.
 */
const GLAUX_ACCOUNT_ABI = [
  {
    type: "function",
    name: "executeWithSigs",
    stateMutability: "payable",
    inputs: [
      { name: "calls", type: "tuple[]", components: CALL_TUPLE_COMPONENTS },
      { name: "validUntil", type: "uint48" },
      { name: "sigs", type: "tuple[2]", components: SLOT_SIG_TUPLE_COMPONENTS },
    ],
    outputs: [],
  },
  {
    type: "function",
    name: "execNonce",
    stateMutability: "view",
    inputs: [],
    outputs: [{ type: "uint64" }],
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
  {
    type: "error",
    name: "OperationExpired",
    inputs: [
      { name: "validUntil", type: "uint48" },
      { name: "blockTimestamp", type: "uint256" },
    ],
  },
  { type: "error", name: "NotInitialized", inputs: [] },
  { type: "error", name: "InvalidSignature", inputs: [] },
  {
    type: "error",
    name: "CallFailed",
    inputs: [
      { name: "index", type: "uint256" },
      { name: "revertData", type: "bytes" },
    ],
  },
] as const;

/** The result of `signExecution`: everything `submitExecution` needs to broadcast. */
export interface SignedExecution {
  readonly account: Address;
  readonly calls: readonly Call[];
  readonly validUntil: number;
  /** `execNonce()` this execution was signed against — for the caller's own bookkeeping only. */
  readonly nonce: bigint;
  readonly sigs: readonly [SlotSig, SlotSig];
}

export interface SignExecutionParams {
  readonly account: Address;
  readonly client: PublicClient;
  readonly calls: readonly Call[];
  readonly validUntil: number;
  /** Exactly two of the account's three factor signers — the 2-of-3 quorum for this operation. */
  readonly signers: readonly [Signer, Signer];
}

interface FactorSlotReadback {
  readonly verifierType: number;
  readonly data: Hex;
}

async function readAllSlots(client: PublicClient, account: Address): Promise<readonly FactorSlotReadback[]> {
  const slots = await Promise.all(
    [0, 1, 2].map((index) =>
      client.readContract({
        address: account,
        abi: GLAUX_ACCOUNT_ABI,
        functionName: "getSlot",
        args: [index],
      }),
    ),
  );
  return slots.map(([verifierType, data]) => ({ verifierType, data }));
}

/**
 * Finds which of the account's three installed slots `signer` occupies, by
 * comparing key material rather than trusting a caller-supplied index — see
 * `UnrecognizedSignerError`'s documentation for why.
 */
function matchSlotIndex(slots: readonly FactorSlotReadback[], signer: Signer): number {
  const keyData = signer.keyData().toLowerCase();
  const index = slots.findIndex(
    (slot) => slot.verifierType === signer.verifierType && slot.data.toLowerCase() === keyData,
  );
  if (index === -1) {
    throw new UnrecognizedSignerError();
  }
  return index;
}

/**
 * Signs a direct `executeWithSigs` batch for the 2-of-3 quorum in `signers`.
 * Reads `execNonce()` and the account's three installed factor slots live
 * from `client` — a caller can never pass a stale nonce, and slot indices are
 * derived from the account's actual state rather than assumed from factor
 * ordering (see `UnrecognizedSignerError`).
 *
 * `validUntil === 0` is rejected BEFORE any RPC call: `execDigest` already
 * throws for it, but that throw happens after the nonce/slot reads this
 * function would otherwise issue first, so the check is duplicated here,
 * ahead of them, to guarantee "no request issued" for a zero deadline.
 *
 * @throws {OperationExpiredError} if `validUntil === 0`.
 * @throws {UnrecognizedSignerError} if a signer's key material matches none
 * of the account's three installed slots.
 */
export async function signExecution(params: SignExecutionParams): Promise<SignedExecution> {
  const { account, client, calls, validUntil, signers } = params;
  if (validUntil === 0) {
    throw new OperationExpiredError();
  }

  const [chainId, nonce, slots] = await Promise.all([
    client.getChainId(),
    client.readContract({ address: account, abi: GLAUX_ACCOUNT_ABI, functionName: "execNonce" }),
    readAllSlots(client, account),
  ]);

  const slotIndices = signers.map((signer) => matchSlotIndex(slots, signer)) as [number, number];
  const digest = execDigest(account, BigInt(chainId), nonce, calls, validUntil);
  const signatures = await Promise.all(signers.map((signer) => signer.sign(digest)));

  const sigs: [SlotSig, SlotSig] = [
    { slotIndex: slotIndices[0], signature: signatures[0]! },
    { slotIndex: slotIndices[1], signature: signatures[1]! },
  ];

  return { account, calls, validUntil, nonce, sigs };
}

/**
 * Appends a `Call` transferring `amount` to `relayer` at the end of `calls` —
 * a batch helper so the ACCOUNT economically refunds the gas its relayer
 * fronted, while the relayer still mechanically pays and submits the
 * transaction. The refund rides inside the same signed, quorum-approved
 * batch as every other call: it is authorized exactly like any other spend,
 * never separately.
 */
export function withRelayerRefund(calls: readonly Call[], relayer: Address, amount: bigint): Call[] {
  return [...calls, { to: relayer, value: amount, data: "0x" }];
}

function toExecuteArgs(signed: SignedExecution) {
  return [
    signed.calls,
    signed.validUntil,
    [
      { slotIndex: signed.sigs[0].slotIndex, signature: encodeSlotSig(signed.sigs[0]) },
      { slotIndex: signed.sigs[1].slotIndex, signature: encodeSlotSig(signed.sigs[1]) },
    ],
  ] as const;
}

/**
 * Turns a failed `simulateContract` call into a typed Glaux error. Walks the
 * error's cause chain (viem wraps the decoded revert inside
 * `ContractFunctionExecutionError`) for a `ContractFunctionRevertedError`,
 * whose `.data` is the ABI-decoded custom error when the ABI recognizes it.
 */
function toExecutionError(error: unknown): Error {
  if (error instanceof BaseError) {
    const revertError = error.walk(
      (candidate) => candidate instanceof ContractFunctionRevertedError,
    ) as ContractFunctionRevertedError | null;
    if (revertError?.data?.errorName === "OperationExpired") {
      const [validUntil, blockTimestamp] = revertError.data.args as readonly [number, bigint];
      return new ExecutionExpiredError(validUntil, blockTimestamp);
    }
    if (revertError !== null) {
      const reason = revertError?.data?.errorName ?? revertError?.reason ?? revertError?.shortMessage;
      return new ExecutionRevertedError(reason ?? error.shortMessage);
    }
  }
  return new ExecutionRevertedError(error instanceof Error ? error.message : String(error));
}

/**
 * Submits a signed `executeWithSigs` batch, paid for by `relayer` — a
 * private key that only fronts gas, never a factor key. Submission is
 * permissionless: any relayer holding a validly-signed `SignedExecution` can
 * broadcast it.
 *
 * Simulates first (an `eth_call`, nothing broadcast) so a revert is decoded
 * against the account's own ABI into a typed error BEFORE spending gas on a
 * doomed transaction — see `ExecutionExpiredError`/`ExecutionRevertedError`.
 * Only after the simulation succeeds does this build, sign, and send the
 * real transaction, then requires `receipt.status === "success"`: a mined
 * but reverted transaction (for example a state change between simulation
 * and inclusion) is never reported as success.
 *
 * @throws {ExecutionExpiredError} if the contract reverts `OperationExpired`.
 * @throws {ExecutionRevertedError} if the simulation reverts for any other decodable reason.
 * @throws {ExecutionGasEstimationError} if a gas estimate cannot be obtained after a successful simulation.
 * @throws {ExecutionTransactionRevertedError} if the mined transaction's receipt reports failure.
 */
export async function submitExecution(
  client: PublicClient,
  relayer: Hex,
  signed: SignedExecution,
): Promise<Hex> {
  const relayerAddress = privateKeyToAddress(relayer);
  const args = toExecuteArgs(signed);

  try {
    await client.simulateContract({
      address: signed.account,
      abi: GLAUX_ACCOUNT_ABI,
      functionName: "executeWithSigs",
      args,
      account: relayerAddress,
    });
  } catch (error) {
    throw toExecutionError(error);
  }

  const data = encodeFunctionData({ abi: GLAUX_ACCOUNT_ABI, functionName: "executeWithSigs", args });

  const [chainId, nonce, latestBlock, gasPrice, priorityFee] = await Promise.all([
    client.getChainId(),
    client.getTransactionCount({ address: relayerAddress }),
    client.getBlock(),
    client.getGasPrice(),
    client.estimateMaxPriorityFeePerGas(),
  ]);

  let estimate: bigint;
  try {
    estimate = await client.estimateGas({ account: relayerAddress, to: signed.account, data });
  } catch {
    throw new ExecutionGasEstimationError();
  }
  if (typeof estimate !== "bigint") {
    throw new ExecutionGasEstimationError();
  }
  const gas = (estimate * 3n) / 2n + 50_000n;
  const baseFee = latestBlock.baseFeePerGas ?? gasPrice;
  const maxFeePerGas = baseFee * 2n + priorityFee;

  const signedTransaction = await signTransaction({
    privateKey: relayer,
    transaction: {
      chainId,
      nonce,
      to: signed.account,
      value: 0n,
      gas,
      maxFeePerGas,
      maxPriorityFeePerGas: priorityFee,
      data,
    },
  });

  const txHash = await sendRawTransaction(client, { serializedTransaction: signedTransaction });
  const receipt = await client.waitForTransactionReceipt({ hash: txHash });
  if (receipt.status !== "success") {
    throw new ExecutionTransactionRevertedError(txHash);
  }
  return txHash;
}
