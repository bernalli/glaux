import {
  BaseError,
  ContractFunctionRevertedError,
  ContractFunctionZeroDataError,
  encodeFunctionData,
  keccak256,
  stringToBytes,
  toHex,
  type Address,
  type Hex,
  type Log,
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
  ExecutionAccountNotBornError,
  ExecutionRevertedError,
  ExecutionSimulationError,
  ExecutionStateReadError,
  ExecutionTransactionRevertedError,
  ChainIdMismatchError,
  DuplicateExecutionSignerError,
  ExecutionNonceMismatchError,
  ExecutionValidityWindowError,
  OperationAlreadyExpiredError,
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

const EXECUTION_STORAGE_SLOT = BigInt(keccak256(stringToBytes("glaux.account.v1.storage")));
const UINT64_MAX = (1n << 64n) - 1n;

/**
 * Safe-by-default lifetime for newly signed direct and ERC-4337 operations.
 * Callers must explicitly raise the per-call ceiling for a longer-lived
 * operation; see `docs/client-guidance.md` before doing so.
 */
export const DEFAULT_EXECUTION_VALIDITY_WINDOW_SECONDS = 60 * 60;

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
  /** Chain selected by the caller, independently of the RPC endpoint. */
  readonly expectedChainId: number;
  readonly calls: readonly Call[];
  readonly validUntil: number;
  /**
   * Optional nonce obtained independently of `client`. When supplied it must
   * equal both same-block RPC views before either factor is asked to sign.
   */
  readonly expectedNonce?: bigint;
  /**
   * Maximum seconds from the local clock that `validUntil` may name. Defaults
   * to one hour; raising it is an explicit acceptance of a longer replay window.
   */
  readonly maxValidityWindowSeconds?: number;
  /** Exactly two of the account's three factor signers — the 2-of-3 quorum for this operation. */
  readonly signers: readonly [Signer, Signer];
}

/** Exported for reuse by `../execute/userop.js`'s own slot reads. */
export interface FactorSlotReadback {
  readonly verifierType: number;
  readonly data: Hex;
}

function isHexBytes(value: unknown): value is Hex {
  return typeof value === "string" && /^0x(?:[0-9a-fA-F]{2})*$/u.test(value);
}

function isUint(value: unknown, max: number): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 && value <= max;
}

function isExecutionNonce(value: unknown): value is bigint {
  return typeof value === "bigint" && value >= 0n && value <= UINT64_MAX;
}

function isStorageWord(value: unknown): value is Hex {
  return isHexBytes(value) && value.length === 66;
}

/**
 * Applies the local-clock lifetime policy shared by both execution paths.
 * The clock is intentionally not read from `client`: an RPC that can lie
 * about a future nonce could lie about its block timestamp as well.
 */
export function assertExecutionValidityWindow(
  validUntil: number,
  maxValidityWindowSeconds = DEFAULT_EXECUTION_VALIDITY_WINDOW_SECONDS,
): void {
  if (!Number.isSafeInteger(maxValidityWindowSeconds) || maxValidityWindowSeconds <= 0) {
    throw new RangeError("maxValidityWindowSeconds must be a positive safe integer.");
  }
  const now = Math.floor(Date.now() / 1000);
  // The lower bound the window check on its own leaves open: an operation whose
  // deadline is already at or behind the local clock passes any ceiling test yet
  // is dead on arrival at the contract (`block.timestamp > validUntil`). Refusing
  // it here keeps a quorum signature — and, on the relayed paths, gas — from being
  // spent on a transaction guaranteed to revert.
  if (validUntil <= now) {
    throw new OperationAlreadyExpiredError(validUntil, now);
  }
  const latestAllowed = now + maxValidityWindowSeconds;
  if (!Number.isSafeInteger(latestAllowed)) {
    throw new RangeError("maxValidityWindowSeconds produces an unsafe timestamp.");
  }
  if (validUntil > latestAllowed) {
    throw new ExecutionValidityWindowError(validUntil, latestAllowed, maxValidityWindowSeconds);
  }
}

function toStateReadError(
  error: unknown,
  target: ExecutionStateReadError["target"],
  slotIndex?: number,
): ExecutionStateReadError {
  return error instanceof ExecutionStateReadError ? error : new ExecutionStateReadError(target, slotIndex);
}

/**
 * `readContract` reports an `eth_call` with no return bytes as this error.
 * Keep it separate while resolving a snapshot: it may mean a just-confirmed
 * account birth is newer than a previously cached block number, whereas a
 * transport error remains unknown state and must fail closed immediately.
 */
class EmptyExecutionStateReadError extends Error {
  readonly target: ExecutionStateReadError["target"];
  readonly slotIndex: number | undefined;

  constructor(target: ExecutionStateReadError["target"], slotIndex?: number) {
    super("direct-execution contract read returned no data");
    this.target = target;
    this.slotIndex = slotIndex;
  }
}

function isZeroDataContractRead(error: unknown): boolean {
  return (
    error instanceof ContractFunctionZeroDataError ||
    (error instanceof BaseError &&
      error.walk((candidate) => candidate instanceof ContractFunctionZeroDataError) !== null)
  );
}

/** Exported for ERC-4337's own same-block nonce cross-check. */
export async function readSnapshotBlockNumber(client: PublicClient): Promise<bigint> {
  try {
    // Viem caches this action for the polling interval by default. A cached
    // height can predate a transaction whose receipt the caller already
    // observed, so it is not a suitable execution snapshot.
    const blockNumber: unknown = await client.getBlockNumber({ cacheTime: 0 });
    if (typeof blockNumber !== "bigint" || blockNumber < 0n) {
      throw new ExecutionStateReadError("block number");
    }
    return blockNumber;
  } catch (error) {
    throw toStateReadError(error, "block number");
  }
}

/** Exported for reuse by `../execute/userop.js`'s own chain-id read on submission. */
export async function readChainId(client: PublicClient): Promise<number> {
  try {
    const chainId: unknown = await client.getChainId();
    if (!isUint(chainId, Number.MAX_SAFE_INTEGER)) {
      throw new ExecutionStateReadError("chain id");
    }
    return chainId;
  } catch (error) {
    throw toStateReadError(error, "chain id");
  }
}

/**
 * Reads the endpoint's chain id and compares it with the caller's selection.
 * Returns the CALLER's value, never the endpoint's: the two are equal by the
 * time this returns, but nothing an RPC said may reach a signed digest, and a
 * later reader of `signExecution` must not have to re-derive that they are.
 */
export async function assertExpectedChainId(client: PublicClient, expectedChainId: number): Promise<number> {
  const actual = await readChainId(client);
  if (actual !== expectedChainId) throw new ChainIdMismatchError(expectedChainId, actual);
  return expectedChainId;
}

async function readExecutionNonce(client: PublicClient, account: Address, blockNumber: bigint): Promise<bigint> {
  try {
    const nonce: unknown = await client.readContract({
      address: account,
      abi: GLAUX_ACCOUNT_ABI,
      functionName: "execNonce",
      blockNumber,
    });
    if (nonce === undefined) throw new EmptyExecutionStateReadError("execution nonce");
    if (!isExecutionNonce(nonce)) throw new ExecutionStateReadError("execution nonce");
    return nonce;
  } catch (error) {
    if (error instanceof EmptyExecutionStateReadError) throw error;
    if (isZeroDataContractRead(error)) throw new EmptyExecutionStateReadError("execution nonce");
    throw toStateReadError(error, "execution nonce");
  }
}

async function readRawExecutionNonce(client: PublicClient, account: Address, blockNumber: bigint): Promise<bigint> {
  try {
    const header: unknown = await client.getStorageAt({
      address: account,
      slot: toHex(EXECUTION_STORAGE_SLOT, { size: 32 }),
      blockNumber,
    });
    if (!isStorageWord(header)) throw new ExecutionStateReadError("execution nonce");
    return (BigInt(header) >> 72n) & UINT64_MAX;
  } catch (error) {
    throw toStateReadError(error, "execution nonce");
  }
}

async function readFactorSlot(
  client: PublicClient,
  account: Address,
  index: number,
  blockNumber: bigint,
): Promise<FactorSlotReadback> {
  try {
    const result: unknown = await client.readContract({
      address: account,
      abi: GLAUX_ACCOUNT_ABI,
      functionName: "getSlot",
      args: [index],
      blockNumber,
    });
    if (result === undefined) throw new EmptyExecutionStateReadError("factor slot", index);
    if (!Array.isArray(result) || result.length !== 2 || !isUint(result[0], 255) || !isHexBytes(result[1])) {
      throw new ExecutionStateReadError("factor slot", index);
    }
    return { verifierType: result[0], data: result[1] };
  } catch (error) {
    if (error instanceof EmptyExecutionStateReadError) throw error;
    if (isZeroDataContractRead(error)) throw new EmptyExecutionStateReadError("factor slot", index);
    throw toStateReadError(error, "factor slot", index);
  }
}

async function readAllSlots(
  client: PublicClient,
  account: Address,
  blockNumber: bigint,
): Promise<readonly FactorSlotReadback[]> {
  const slots: FactorSlotReadback[] = [];
  for (const index of [0, 1, 2]) {
    slots.push(await readFactorSlot(client, account, index, blockNumber));
  }
  return slots;
}

async function accountHasCodeAtSnapshot(client: PublicClient, account: Address, blockNumber: bigint): Promise<boolean> {
  try {
    const code: unknown = await client.getCode({ address: account, blockNumber });
    if (code === undefined || code === "0x") return false;
    if (!isHexBytes(code)) throw new ExecutionStateReadError("account code");
    return true;
  } catch (error) {
    throw toStateReadError(error, "account code");
  }
}

/**
 * Reads all factor slots at one freshly resolved block. A no-data response is
 * treated specially only to distinguish a just-born account whose provider
 * head lagged from an actually unreadable response: resolve one more
 * uncached height, then either return one coherent snapshot or fail closed.
 *
 * Exported for `../execute/userop.js`: its signature's `SlotSig.slotIndex`
 * fields have the same wire-level trust boundary as direct execution, so the
 * two paths must share both strict slot decoding and the fresh pinned-read
 * discipline.
 */
export async function readFactorSlotsAtFreshSnapshot(
  client: PublicClient,
  account: Address,
): Promise<readonly FactorSlotReadback[]> {
  let blockNumber = await readSnapshotBlockNumber(client);

  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      return await readAllSlots(client, account, blockNumber);
    } catch (error) {
      if (!(error instanceof EmptyExecutionStateReadError)) throw error;

      if (await accountHasCodeAtSnapshot(client, account, blockNumber)) {
        throw new ExecutionStateReadError(error.target, error.slotIndex);
      }
      if (attempt === 1) {
        throw new ExecutionAccountNotBornError(account, blockNumber);
      }
      blockNumber = await readSnapshotBlockNumber(client);
    }
  }

  throw new ExecutionStateReadError("factor slot");
}

interface ExecutionStateSnapshot {
  readonly nonce: bigint;
  readonly slots: readonly FactorSlotReadback[];
}

/**
 * Reads the nonce and all factor slots at one freshly resolved block. If that
 * block has no account code, resolve one more uncached height and start the
 * entire read set again. This accommodates a provider/client head race after
 * a confirmed birth without retrying an unreadable RPC response or mixing
 * values from two snapshots.
 */
async function readExecutionState(client: PublicClient, account: Address): Promise<ExecutionStateSnapshot> {
  let blockNumber = await readSnapshotBlockNumber(client);

  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      const nonce = await readExecutionNonce(client, account, blockNumber);
      const rawNonce = await readRawExecutionNonce(client, account, blockNumber);
      if (nonce !== rawNonce) {
        throw new ExecutionNonceMismatchError("direct", "raw storage", rawNonce, nonce);
      }
      const slots = await readAllSlots(client, account, blockNumber);
      return { nonce, slots };
    } catch (error) {
      if (!(error instanceof EmptyExecutionStateReadError)) throw error;

      if (await accountHasCodeAtSnapshot(client, account, blockNumber)) {
        throw new ExecutionStateReadError(error.target, error.slotIndex);
      }
      if (attempt === 1) {
        throw new ExecutionAccountNotBornError(account, blockNumber);
      }
      blockNumber = await readSnapshotBlockNumber(client);
    }
  }

  throw new ExecutionStateReadError("execution nonce");
}

/** Exported for reuse by `../execute/userop.js`'s own `handleOps` broadcast. */
export async function readRelayerNonce(client: PublicClient, relayer: Address): Promise<number> {
  try {
    const nonce: unknown = await client.getTransactionCount({ address: relayer });
    if (!isUint(nonce, Number.MAX_SAFE_INTEGER)) {
      throw new ExecutionStateReadError("relayer transaction nonce");
    }
    return nonce;
  } catch (error) {
    throw toStateReadError(error, "relayer transaction nonce");
  }
}

/** Exported for reuse by `../execute/userop.js`'s own fee-field estimation. */
export interface LatestBlockReadback {
  readonly baseFeePerGas: bigint | null;
}

export async function readLatestBlock(client: PublicClient): Promise<LatestBlockReadback> {
  try {
    const block: unknown = await client.getBlock();
    if (
      typeof block !== "object" ||
      block === null ||
      !("baseFeePerGas" in block) ||
      (block.baseFeePerGas !== null && (typeof block.baseFeePerGas !== "bigint" || block.baseFeePerGas < 0n))
    ) {
      throw new ExecutionStateReadError("latest block");
    }
    return { baseFeePerGas: block.baseFeePerGas };
  } catch (error) {
    throw toStateReadError(error, "latest block");
  }
}

/** Exported for reuse by `../execute/userop.js`'s own fee-field estimation. */
export async function readNonNegativeFee(
  read: () => Promise<bigint>,
  target: "gas price" | "priority fee",
): Promise<bigint> {
  try {
    const fee: unknown = await read();
    if (typeof fee !== "bigint" || fee < 0n) throw new ExecutionStateReadError(target);
    return fee;
  } catch (error) {
    throw toStateReadError(error, target);
  }
}

/** Exported for reuse by `../execute/userop.js`'s own `handleOps` broadcast. */
export interface ExecutionReceiptReadback {
  readonly status: "success" | "reverted";
  readonly logs: readonly Log[];
}

/**
 * Reads one mined transaction receipt and verifies the two pieces SDK
 * execution paths need from it: a known status and a present log array.
 * Exported so the ERC-4337 path can decode its operation outcome from this
 * exact receipt rather than racing a second receipt read.
 */
export async function readExecutionReceiptWithLogs(
  client: PublicClient,
  txHash: Hex,
): Promise<ExecutionReceiptReadback> {
  try {
    const receipt: unknown = await client.waitForTransactionReceipt({ hash: txHash });
    if (
      typeof receipt !== "object" ||
      receipt === null ||
      !("status" in receipt) ||
      !("logs" in receipt) ||
      !Array.isArray(receipt.logs)
    ) {
      throw new ExecutionStateReadError("transaction receipt");
    }
    if (receipt.status === "success" || receipt.status === "reverted") {
      return { status: receipt.status, logs: receipt.logs as readonly Log[] };
    }
    throw new ExecutionStateReadError("transaction receipt");
  } catch (error) {
    throw toStateReadError(error, "transaction receipt");
  }
}

/**
 * Status-only receipt read retained unchanged for direct execution callers.
 * Direct execution never consumes receipt logs, so an absent log array must
 * not alter its established receipt-status behaviour.
 */
export async function readExecutionReceipt(client: PublicClient, txHash: Hex): Promise<"success" | "reverted"> {
  try {
    const receipt: unknown = await client.waitForTransactionReceipt({ hash: txHash });
    if (typeof receipt !== "object" || receipt === null || !("status" in receipt)) {
      throw new ExecutionStateReadError("transaction receipt");
    }
    if (receipt.status === "success" || receipt.status === "reverted") return receipt.status;
    throw new ExecutionStateReadError("transaction receipt");
  } catch (error) {
    throw toStateReadError(error, "transaction receipt");
  }
}

/**
 * Finds which of the account's three installed slots `signer` occupies, by
 * comparing key material rather than trusting a caller-supplied index — see
 * `UnrecognizedSignerError`'s documentation for why. Exported for reuse by
 * `../execute/userop.js`'s own quorum-to-slot resolution: the ERC-4337
 * signature blob carries the identical `SlotSig.slotIndex` wire field, so it
 * needs the identical never-trust-a-caller-index guarantee.
 */
export function matchSlotIndex(slots: readonly FactorSlotReadback[], signer: Signer): number {
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
 * Reads `execNonce()`, the same pinned block's raw Glaux header word, and the
 * account's three installed factor slots live from `client`. Getter/raw nonce
 * disagreement fails before signing, as does an optional independently
 * obtained `expectedNonce`. Slot indices are derived from the account's
 * reported state rather than assumed from factor ordering.
 *
 * The raw check is a consistency tripwire, not an RPC authenticity proof: a
 * fully hostile endpoint can forge getter and storage replies consistently.
 * The local-clock validity ceiling bounds how long such a harvested
 * future-nonce blob can become useful, but replay remains possible inside
 * that window unless `expectedNonce` comes from an independent trusted view.
 *
 * `validUntil === 0` is rejected BEFORE any RPC call: `execDigest` already
 * throws for it, but that throw happens after the nonce/slot reads this
 * function would otherwise issue first, so the check is duplicated here,
 * ahead of them, to guarantee "no request issued" for a zero deadline.
 *
 * @throws {OperationExpiredError} if `validUntil === 0`.
 * @throws {ExecutionValidityWindowError} if the deadline exceeds the local ceiling.
 * @throws {ExecutionNonceMismatchError} if nonce views disagree.
 * @throws {ExecutionStateReadError} if the snapshot, nonce, or a factor slot
 * cannot be read in a well-formed response.
 * @throws {ExecutionAccountNotBornError} if the account has no code at a
 * freshly resolved execution snapshot.
 * @throws {UnrecognizedSignerError} if a signer's key material matches none
 * of the account's three installed slots.
 * @throws {DuplicateExecutionSignerError} if both signers occupy one slot.
 */
export async function signExecution(params: SignExecutionParams): Promise<SignedExecution> {
  const {
    account,
    client,
    calls,
    validUntil,
    signers,
    expectedChainId,
    expectedNonce,
    maxValidityWindowSeconds,
  } = params;
  if (validUntil === 0) {
    throw new OperationExpiredError();
  }
  assertExecutionValidityWindow(validUntil, maxValidityWindowSeconds);

  const chainId = await assertExpectedChainId(client, expectedChainId);
  const { nonce, slots } = await readExecutionState(client, account);
  if (expectedNonce !== undefined && nonce !== expectedNonce) {
    throw new ExecutionNonceMismatchError("direct", "caller expectation", expectedNonce, nonce);
  }

  const slotIndices = signers.map((signer) => matchSlotIndex(slots, signer)) as [number, number];
  if (slotIndices[0] === slotIndices[1]) {
    throw new DuplicateExecutionSignerError(slotIndices[0]);
  }
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
 * @throws {ExecutionSimulationError} if simulation cannot be confirmed.
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
    const simulation: unknown = await client.simulateContract({
      address: signed.account,
      abi: GLAUX_ACCOUNT_ABI,
      functionName: "executeWithSigs",
      args,
      account: relayerAddress,
    });
    if (
      typeof simulation !== "object" ||
      simulation === null ||
      !("request" in simulation) ||
      typeof simulation.request !== "object" ||
      simulation.request === null
    ) {
      throw new ExecutionSimulationError();
    }
  } catch (error) {
    if (error instanceof ExecutionSimulationError) throw error;
    if (error instanceof BaseError) {
      const revertError = error.walk(
        (candidate) => candidate instanceof ContractFunctionRevertedError,
      ) as ContractFunctionRevertedError | null;
      if (revertError !== null) throw toExecutionError(error);
    }
    throw new ExecutionSimulationError();
  }

  const data = encodeFunctionData({ abi: GLAUX_ACCOUNT_ABI, functionName: "executeWithSigs", args });

  const [chainId, nonce, latestBlock, gasPrice, priorityFee] = await Promise.all([
    readChainId(client),
    readRelayerNonce(client, relayerAddress),
    readLatestBlock(client),
    readNonNegativeFee(() => client.getGasPrice(), "gas price"),
    readNonNegativeFee(() => client.estimateMaxPriorityFeePerGas(), "priority fee"),
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
  const receiptStatus = await readExecutionReceipt(client, txHash);
  if (receiptStatus !== "success") {
    throw new ExecutionTransactionRevertedError(txHash);
  }
  return txHash;
}
