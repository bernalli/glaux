import {
  BaseError,
  ContractFunctionRevertedError,
  decodeEventLog,
  encodeAbiParameters,
  encodeFunctionData,
  encodePacked,
  keccak256,
  type Address,
  type Hex,
  type Log,
  type PublicClient,
} from "viem";
import { sendRawTransaction } from "viem/actions";
import { privateKeyToAddress, signTransaction } from "viem/accounts";
import { ENTRYPOINT } from "../core/constants.js";
import { userOpDigest } from "../core/digests.js";
import { encodeUserOpSignature } from "../core/encoding.js";
import type { Call, SlotSig } from "../core/types.js";
import type { Signer } from "../signers/signer.js";
import {
  ExecutionStateReadError,
  ExecutionNonceMismatchError,
  OperationExpiredError,
  DuplicateExecutionSignerError,
  UserOpEventNotFoundError,
  UserOpExecutionFailedError,
  UserOpFailedError,
  UserOpGasEstimationError,
  UserOpGasValueOutOfRangeError,
  UserOpSimulationError,
  UserOpSubmissionRevertedError,
  UserOpTransactionRevertedError,
} from "../errors.js";
import {
  assertFeeWithinBaseline,
  assertUserOpCost,
  fetchFeeBaseline,
  userOpMaxFeePerGas,
  type FeeBaseline,
} from "../gas/feeGuard.js";
import {
  matchSlotIndex,
  assertExecutionValidityWindow,
  readChainId,
  readExecutionReceiptWithLogs,
  readFactorSlotsAtFreshSnapshot,
  readLatestBlock,
  readNonNegativeFee,
  readRelayerNonce,
  readSnapshotBlockNumber,
  type FactorSlotReadback,
} from "./direct.js";

const CALL_TUPLE_COMPONENTS = [
  { name: "to", type: "address" },
  { name: "value", type: "uint256" },
  { name: "data", type: "bytes" },
] as const;

const PACKED_USER_OP_COMPONENTS = [
  { name: "sender", type: "address" },
  { name: "nonce", type: "uint256" },
  { name: "initCode", type: "bytes" },
  { name: "callData", type: "bytes" },
  { name: "accountGasLimits", type: "bytes32" },
  { name: "preVerificationGas", type: "uint256" },
  { name: "gasFees", type: "bytes32" },
  { name: "paymasterAndData", type: "bytes" },
  { name: "signature", type: "bytes" },
] as const;

/**
 * The slice of `GlauxAccount`'s ABI this module needs to build
 * `executeFromEntryPoint` calldata (`src/GlauxAccount.sol:316`) and read
 * installed factor slots (`getSlot`, shared with `../execute/direct.js`'s
 * quorum resolution).
 */
const GLAUX_ACCOUNT_ABI = [
  {
    type: "function",
    name: "executeFromEntryPoint",
    stateMutability: "nonpayable",
    inputs: [{ name: "calls", type: "tuple[]", components: CALL_TUPLE_COMPONENTS }],
    outputs: [],
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
 * The slice of the vendored ERC-4337 EntryPoint v0.7's ABI
 * (`lib/account-abstraction/contracts/interfaces/IEntryPoint.sol`) this
 * module needs: `getNonce` (per-account, per-key sequence — `key = 0`, the
 * simple non-2D-nonce lane), `getUserOpHash` (the on-chain cross-check
 * `userop.e2e.test.ts` verifies `computeUserOpHash` against byte-for-byte),
 * `handleOps` (the test-path submission with no bundler), `balanceOf` (the
 * account's EntryPoint deposit, read by the e2e test to prove exactly where
 * the self-funded prefund's unspent remainder ends up), and the custom
 * errors/event `handleOps` can revert or emit, so a pre-flight simulation can
 * decode the EntryPoint's own real revert reason and the real cost of a
 * successful call can be read from its own event, never inferred.
 */
const ENTRYPOINT_ABI = [
  {
    type: "function",
    name: "getNonce",
    stateMutability: "view",
    inputs: [
      { name: "sender", type: "address" },
      { name: "key", type: "uint192" },
    ],
    outputs: [{ name: "nonce", type: "uint256" }],
  },
  {
    type: "function",
    name: "getUserOpHash",
    stateMutability: "view",
    inputs: [{ name: "userOp", type: "tuple", components: PACKED_USER_OP_COMPONENTS }],
    outputs: [{ type: "bytes32" }],
  },
  {
    type: "function",
    name: "handleOps",
    stateMutability: "nonpayable",
    inputs: [
      { name: "ops", type: "tuple[]", components: PACKED_USER_OP_COMPONENTS },
      { name: "beneficiary", type: "address" },
    ],
    outputs: [],
  },
  {
    type: "function",
    name: "balanceOf",
    stateMutability: "view",
    inputs: [{ name: "account", type: "address" }],
    outputs: [{ type: "uint256" }],
  },
  {
    type: "error",
    name: "FailedOp",
    inputs: [
      { name: "opIndex", type: "uint256" },
      { name: "reason", type: "string" },
    ],
  },
  {
    type: "error",
    name: "FailedOpWithRevert",
    inputs: [
      { name: "opIndex", type: "uint256" },
      { name: "reason", type: "string" },
      { name: "inner", type: "bytes" },
    ],
  },
  {
    type: "event",
    name: "UserOperationEvent",
    inputs: [
      { name: "userOpHash", type: "bytes32", indexed: true },
      { name: "sender", type: "address", indexed: true },
      { name: "paymaster", type: "address", indexed: true },
      { name: "nonce", type: "uint256", indexed: false },
      { name: "success", type: "bool", indexed: false },
      { name: "actualGasCost", type: "uint256", indexed: false },
      { name: "actualGasUsed", type: "uint256", indexed: false },
    ],
  },
] as const;

/**
 * Mirrors `PackedUserOperation`
 * (`lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol`)
 * field-for-field, plus one SDK-only decoration: `validUntil` is not part of
 * the on-chain struct (it travels inside `signature`, ABI-encoded ahead of
 * the `SlotSig[2]` — see `encodeUserOpSignature`,
 * `../core/encoding.js`), but `buildUserOp` and `signUserOp` need to carry it
 * from one call to the next without a caller re-supplying it, exactly as
 * `SignedExecution.validUntil` (`./direct.js`) carries the analogous value
 * for the direct path. `submitUserOpDirect`'s ABI encoding reads only the
 * nine named struct fields below, so the extra property never reaches the
 * chain.
 */
export interface PackedUserOperation {
  readonly sender: Address;
  readonly nonce: bigint;
  readonly initCode: Hex;
  readonly callData: Hex;
  readonly accountGasLimits: Hex;
  readonly preVerificationGas: bigint;
  readonly gasFees: Hex;
  readonly paymasterAndData: Hex;
  readonly signature: Hex;
  readonly validUntil: number;
}

export interface BuildUserOpParams {
  readonly account: Address;
  readonly client: PublicClient;
  readonly calls: readonly Call[];
  readonly validUntil: number;
  /** Optional nonce obtained independently of this RPC endpoint. */
  readonly expectedNonce?: bigint;
  /** Local-clock validity ceiling; defaults to one hour. */
  readonly maxValidityWindowSeconds?: number;
}

// Matches `EntryPoint4337.t.sol`'s own `_packedOp` budget for Glaux's
// two-ecrecover-plus-self-fund verification path: generous enough that a
// real `validateUserOp` call never runs out of gas, without pretending to be
// a tight, bundler-grade estimate (Task 11 owns that).
const VERIFICATION_GAS_LIMIT = 600_000n;
// Fixed until Task 11's bundler adds a real calldata-cost/overhead
// calculator; this path has no bundler yet, only a direct test submission.
const PRE_VERIFICATION_GAS = 100_000n;
// Same headroom heuristic `./direct.js`'s `submitExecution` already uses for
// its own gas estimate: 50% margin plus a flat buffer, not a tight bound —
// deliberately leaves slack so the EntryPoint's post-execution refund
// (`_postExecution`, `lib/account-abstraction/contracts/core/EntryPoint.sol:685-750`)
// is meaningfully non-zero rather than coincidentally near-zero.
const CALL_GAS_BUFFER_NUMERATOR = 3n;
const CALL_GAS_BUFFER_DENOMINATOR = 2n;
const CALL_GAS_BUFFER_FLAT = 50_000n;
const ENTRYPOINT_GAS_VALUE_MAX = (1n << 120n) - 1n;

function requireEntryPointGasValue(field: string, value: bigint): bigint {
  if (value < 0n || value > ENTRYPOINT_GAS_VALUE_MAX) {
    throw new UserOpGasValueOutOfRangeError(field, value, ENTRYPOINT_GAS_VALUE_MAX);
  }
  return value;
}

// EntryPoint v0.7's inheritance layout puts `StakeManager.deposits` at slot
// zero and `NonceManager.nonceSequenceNumber` at slot one. This is pinned to
// the vendored canonical EntryPoint this module targets, not a generic 4337
// storage-layout assumption.
const ENTRYPOINT_NONCE_SEQUENCE_SLOT = 1n;

function entryPointNonceStorageSlot(account: Address): Hex {
  const perAccountMapping = keccak256(
    encodeAbiParameters(
      [{ type: "address" }, { type: "uint256" }],
      [account, ENTRYPOINT_NONCE_SEQUENCE_SLOT],
    ),
  );
  return keccak256(
    encodeAbiParameters(
      [{ type: "uint192" }, { type: "bytes32" }],
      [0n, perAccountMapping],
    ),
  );
}

async function readEntryPointNonce(client: PublicClient, account: Address): Promise<bigint> {
  const blockNumber = await readSnapshotBlockNumber(client);
  let nonce: unknown;
  let rawNonce: unknown;
  try {
    nonce = await client.readContract({
      address: ENTRYPOINT,
      abi: ENTRYPOINT_ABI,
      functionName: "getNonce",
      args: [account, 0n],
      blockNumber,
    });
    rawNonce = await client.getStorageAt({
      address: ENTRYPOINT,
      slot: entryPointNonceStorageSlot(account),
      blockNumber,
    });
  } catch (error) {
    throw error instanceof ExecutionStateReadError ? error : new ExecutionStateReadError("entrypoint nonce");
  }
  if (typeof nonce !== "bigint" || nonce < 0n) {
    throw new ExecutionStateReadError("entrypoint nonce");
  }
  if (typeof rawNonce !== "string" || !/^0x[0-9a-fA-F]{64}$/u.test(rawNonce)) {
    throw new ExecutionStateReadError("entrypoint nonce");
  }
  const decodedRawNonce = BigInt(rawNonce);
  if (nonce !== decodedRawNonce) {
    // This catches inconsistent lies and node bugs. It is NOT proof against a
    // fully hostile endpoint, which can forge the getter and raw word alike.
    throw new ExecutionNonceMismatchError("erc4337", "raw storage", decodedRawNonce, nonce);
  }
  return nonce;
}

async function estimateCallGas(client: PublicClient, account: Address, callData: Hex): Promise<bigint> {
  let estimate: unknown;
  try {
    // Simulated as a call FROM the EntryPoint: `executeFromEntryPoint`
    // (`src/GlauxAccount.sol:316`) only accepts `msg.sender == ENTRYPOINT`,
    // and real execution is likewise invoked with the EntryPoint as caller
    // (`EntryPoint._executeUserOp`'s self-call through `innerHandleOp`).
    estimate = await client.estimateGas({ account: ENTRYPOINT, to: account, data: callData });
  } catch {
    throw new UserOpGasEstimationError();
  }
  if (typeof estimate !== "bigint" || estimate < 0n) {
    throw new UserOpGasEstimationError();
  }
  return estimate;
}

/**
 * Builds an unsigned `PackedUserOperation` for a self-funded ERC-4337 batch:
 * `callData` invokes `executeFromEntryPoint(calls)`, `nonce` is read live
 * from the canonical EntryPoint (`getNonce(account, 0)` — the plain
 * sequential lane, key `0`) and cross-checked against that same block's raw
 * `nonceSequenceNumber` mapping word. The gas fields are estimated/bounded
 * rather than assumed. `signature` is the placeholder `"0x"` until
 * `signUserOp` fills it in.
 *
 * Getter/raw agreement catches node bugs and inconsistent lies, not a fully
 * hostile endpoint that forges both. The default local-clock deadline ceiling
 * narrows that endpoint's future-nonce replay window; an independently sourced
 * `expectedNonce` is required to authenticate the nonce itself.
 *
 * `validUntil` is rejected at `0` BEFORE any RPC call — same client-side
 * refusal `../core/digests.js`'s `userOpDigest` and `../core/encoding.js`'s
 * `encodeUserOpSignature` enforce later, just earlier, matching
 * `signExecution`'s (`./direct.js`) rationale for duplicating the check
 * ahead of its own reads.
 *
 * @throws {OperationExpiredError} if `validUntil === 0`.
 * @throws {ExecutionValidityWindowError} if the deadline exceeds the local ceiling.
 * @throws {ExecutionNonceMismatchError} if nonce views disagree.
 * @throws {ExecutionStateReadError} if the EntryPoint nonce or a fee field
 * cannot be read in a well-formed response.
 * @throws {UserOpGasEstimationError} if `executeFromEntryPoint`'s call gas
 * cannot be estimated.
 */
export async function buildUserOp(params: BuildUserOpParams): Promise<PackedUserOperation> {
  const { account, client, calls, validUntil, expectedNonce, maxValidityWindowSeconds } = params;
  if (validUntil === 0) {
    throw new OperationExpiredError();
  }
  assertExecutionValidityWindow(validUntil, maxValidityWindowSeconds);

  const callData = encodeFunctionData({
    abi: GLAUX_ACCOUNT_ABI,
    functionName: "executeFromEntryPoint",
    args: [calls],
  });

  const [nonce, latestBlock, gasPrice, priorityFee, callGasEstimate] = await Promise.all([
    readEntryPointNonce(client, account),
    readLatestBlock(client),
    readNonNegativeFee(() => client.getGasPrice(), "gas price"),
    readNonNegativeFee(() => client.estimateMaxPriorityFeePerGas(), "priority fee"),
    estimateCallGas(client, account, callData),
  ]);
  if (expectedNonce !== undefined && nonce !== expectedNonce) {
    throw new ExecutionNonceMismatchError("erc4337", "caller expectation", expectedNonce, nonce);
  }

  const callGasLimit = (callGasEstimate * CALL_GAS_BUFFER_NUMERATOR) / CALL_GAS_BUFFER_DENOMINATOR + CALL_GAS_BUFFER_FLAT;
  const baseFee = latestBlock.baseFeePerGas ?? gasPrice;
  const maxFeePerGas = baseFee * 2n + priorityFee;

  requireEntryPointGasValue("verificationGasLimit", VERIFICATION_GAS_LIMIT);
  requireEntryPointGasValue("callGasLimit", callGasLimit);
  requireEntryPointGasValue("preVerificationGas", PRE_VERIFICATION_GAS);
  requireEntryPointGasValue("maxPriorityFeePerGas", priorityFee);
  requireEntryPointGasValue("maxFeePerGas", maxFeePerGas);

  return {
    sender: account,
    nonce,
    initCode: "0x",
    callData,
    // `(verificationGasLimit, callGasLimit)`, high-then-low 128 bits — the
    // exact order `UserOperationLib.unpackUints` (`lib/account-abstraction/
    // contracts/core/UserOperationLib.sol:74-78`) expects, matching
    // `EntryPoint4337.t.sol`'s own `_packedOp`.
    accountGasLimits: encodePacked(["uint128", "uint128"], [VERIFICATION_GAS_LIMIT, callGasLimit]),
    preVerificationGas: PRE_VERIFICATION_GAS,
    // `(maxPriorityFeePerGas, maxFeePerGas)`, same high-then-low order.
    gasFees: encodePacked(["uint128", "uint128"], [priorityFee, maxFeePerGas]),
    paymasterAndData: "0x",
    signature: "0x",
    validUntil,
  };
}

function encodeUserOpForHash(op: PackedUserOperation): Hex {
  return encodeAbiParameters(
    [
      { type: "address" },
      { type: "uint256" },
      { type: "bytes32" },
      { type: "bytes32" },
      { type: "bytes32" },
      { type: "uint256" },
      { type: "bytes32" },
      { type: "bytes32" },
    ],
    [
      op.sender,
      op.nonce,
      keccak256(op.initCode),
      keccak256(op.callData),
      op.accountGasLimits,
      op.preVerificationGas,
      op.gasFees,
      keccak256(op.paymasterAndData),
    ],
  );
}

/**
 * Replicates ERC-4337 EntryPoint v0.7's own `getUserOpHash` exactly, derived
 * from the vendored source rather than assumed:
 * `UserOperationLib.encode`/`hash`
 * (`lib/account-abstraction/contracts/core/UserOperationLib.sol:54-72,134-138`)
 * ABI-encodes `(sender, nonce, keccak256(initCode), keccak256(callData),
 * accountGasLimits, preVerificationGas, gasFees, keccak256(paymasterAndData))`
 * — hashing the three dynamic-length fields rather than embedding them raw —
 * and keccaks that; `EntryPoint.getUserOpHash`
 * (`lib/account-abstraction/contracts/core/EntryPoint.sol:363-368`) then
 * wraps that inner hash with `abi.encode(innerHash, address(this),
 * block.chainid)` and keccaks again, binding the EntryPoint's own address
 * and the chain id. `signature` never participates (both here and on-chain).
 * `userop.e2e.test.ts` cross-checks this against the real, etched
 * EntryPoint's own `getUserOpHash` call.
 */
export function computeUserOpHash(op: PackedUserOperation, entryPoint: Address, chainId: bigint): Hex {
  const inner = keccak256(encodeUserOpForHash(op));
  return keccak256(
    encodeAbiParameters([{ type: "bytes32" }, { type: "address" }, { type: "uint256" }], [inner, entryPoint, chainId]),
  );
}

/**
 * Reads `getUserOpHash(op)` directly from a live EntryPoint contract — the
 * on-chain source of truth `computeUserOpHash` is cross-checked against.
 *
 * @throws {ExecutionStateReadError} if the RPC response is absent or malformed.
 */
export async function fetchUserOpHash(
  client: PublicClient,
  entryPoint: Address,
  op: PackedUserOperation,
): Promise<Hex> {
  let hash: unknown;
  try {
    hash = await client.readContract({
      address: entryPoint,
      abi: ENTRYPOINT_ABI,
      functionName: "getUserOpHash",
      args: [op],
    });
  } catch (error) {
    throw error instanceof ExecutionStateReadError ? error : new ExecutionStateReadError("userOp hash");
  }
  if (typeof hash !== "string" || !/^0x[0-9a-fA-F]{64}$/u.test(hash)) {
    throw new ExecutionStateReadError("userOp hash");
  }
  return hash as Hex;
}

/**
 * Reads the account's three installed factor slots through direct execution's
 * strict fresh-snapshot helper. The `SlotSig.slotIndex` wire fields have the
 * same trust boundary on both paths, so accepting a mixed-block snapshot (or
 * malformed uint8/bytes return) here would be just as unsafe as direct
 * execution.
 */
async function readAccountSlots(client: PublicClient, account: Address): Promise<readonly FactorSlotReadback[]> {
  return readFactorSlotsAtFreshSnapshot(client, account);
}

export interface SignUserOpParams {
  /** As returned by `buildUserOp` — carries `validUntil` and the placeholder `signature`. */
  readonly op: PackedUserOperation;
  readonly entryPoint: Address;
  readonly chainId: bigint;
  readonly client: PublicClient;
  /**
   * The most this operation may ever charge the account, in wei. Mandatory,
   * and deliberately so: every gas and fee field of a user operation is
   * proposed by an endpoint, and a signature over them authorizes the
   * EntryPoint to spend the whole product. A caller that has not decided what
   * that operation is worth cannot delegate the decision to a default.
   */
  readonly maxCostWei: bigint;
  /**
   * Fee baseline to judge `maxFeePerGas` against. Supply one read from a
   * SECOND, independent endpoint (`docs/client-guidance.md`) whenever the
   * value at stake justifies it; when omitted, it is read from `client` —
   * useful, but it lets one endpoint both propose the fee and vouch for it.
   */
  readonly feeBaseline?: FeeBaseline;
  /** How far above the baseline lane a fee may sit; defaults to `DEFAULT_FEE_SANITY_MULTIPLE` (`../gas/feeGuard.js`). */
  readonly feeSanityMultiple?: bigint;
  /** Optional independently obtained nonce, checked before live slot reads. */
  readonly expectedNonce?: bigint;
  /** Local-clock validity ceiling; defaults to one hour. */
  readonly maxValidityWindowSeconds?: number;
  /** Exactly two of the account's three factor signers — the 2-of-3 quorum for this operation. */
  readonly signers: readonly [Signer, Signer];
}

/**
 * Signs `op` for the 2-of-3 quorum in `signers`: computes `userOpHash`
 * exactly as EntryPoint v0.7 does (`computeUserOpHash`, using the caller-
 * supplied `entryPoint`/`chainId` rather than re-deriving them, so the digest
 * matches whichever EntryPoint the caller intends to submit through), then
 * `userOpDigest`/`encodeUserOpSignature` (`../core/digests.js`,
 * `../core/encoding.js`) produce the `abi.encode(validUntil, SlotSig[2])`
 * blob `GlauxAccount.validateUserOp` decodes.
 *
 * Like `signExecution` (`./direct.js`), slot indices are resolved from the
 * account's LIVE installed factor slots rather than assumed from signer
 * order — `SlotSig.slotIndex` is a wire field the contract trusts verbatim,
 * so guessing it would risk emitting a signature blob the contract is
 * guaranteed to reject after a key rotation the caller doesn't know about.
 *
 * `op.validUntil === 0` is rejected BEFORE any RPC call, mirroring
 * `buildUserOp`'s and `signExecution`'s duplicated check ahead of their own reads.
 *
 * The gas and fee fields are checked here, at the last moment before a
 * signature exists, and not where they were built: `buildUserOp` is only one
 * of the ways an operation reaches this function — an ERC-7677 paymaster
 * decorates it in between (`../gas/policy.js`), and a caller may hand over an
 * operation this SDK never built at all. This is the single choke point every
 * one of those paths crosses, so it is the only place a bound is worth
 * anything. `maxCostWei` is enforced first because it needs no chain state:
 * an operation nobody would pay for is refused without spending a round trip.
 *
 * @throws {OperationExpiredError} if `op.validUntil === 0`.
 * @throws {ExecutionValidityWindowError} if the deadline exceeds the local ceiling.
 * @throws {ExecutionNonceMismatchError} if `expectedNonce` disagrees with the operation.
 * @throws {UserOpCostExceedsCapError} if the operation could charge the account
 * more than `maxCostWei`.
 * @throws {MalformedPaymasterFieldError} if `paymasterAndData` cannot be priced.
 * @throws {FeeBaselineReadError} if no baseline was supplied and none can be read.
 * @throws {FeeExceedsBaselineError} if `maxFeePerGas` is beyond what the baseline justifies.
 * @throws {ExecutionStateReadError} if a factor slot cannot be read in a well-formed response.
 * @throws {UnrecognizedSignerError} if a signer's key material matches none
 * of the account's three installed slots.
 * @throws {DuplicateExecutionSignerError} if both signers occupy one slot.
 */
export async function signUserOp(params: SignUserOpParams): Promise<PackedUserOperation> {
  const {
    op: suppliedOp,
    entryPoint,
    chainId,
    client,
    signers,
    expectedNonce,
    maxValidityWindowSeconds,
    maxCostWei,
    feeBaseline,
    feeSanityMultiple,
  } = params;
  // Everything from here on reads THIS copy, never the caller's object. The
  // guards below are separated from the hashing by two awaits, and the argument
  // stays reachable and mutable throughout them: checking a cost on an object
  // someone else can still edit, then hashing that same object, bounds nothing.
  // A snapshot makes the values that were checked and the values that get
  // signed the same values by construction.
  const op: PackedUserOperation = {
    sender: suppliedOp.sender,
    nonce: suppliedOp.nonce,
    initCode: suppliedOp.initCode,
    callData: suppliedOp.callData,
    accountGasLimits: suppliedOp.accountGasLimits,
    preVerificationGas: suppliedOp.preVerificationGas,
    gasFees: suppliedOp.gasFees,
    paymasterAndData: suppliedOp.paymasterAndData,
    signature: suppliedOp.signature,
    validUntil: suppliedOp.validUntil,
  };

  if (op.validUntil === 0) {
    throw new OperationExpiredError();
  }
  assertExecutionValidityWindow(op.validUntil, maxValidityWindowSeconds);
  if (expectedNonce !== undefined && op.nonce !== expectedNonce) {
    throw new ExecutionNonceMismatchError("erc4337", "caller expectation", expectedNonce, op.nonce);
  }

  assertUserOpCost(op, maxCostWei);
  const baseline = feeBaseline ?? (await fetchFeeBaseline(client));
  assertFeeWithinBaseline(userOpMaxFeePerGas(op), baseline, feeSanityMultiple);

  const userOpHash = computeUserOpHash(op, entryPoint, chainId);
  const slots = await readAccountSlots(client, op.sender);
  const slotIndices = signers.map((signer) => matchSlotIndex(slots, signer)) as [number, number];
  if (slotIndices[0] === slotIndices[1]) {
    throw new DuplicateExecutionSignerError(slotIndices[0]);
  }

  const digest = userOpDigest(op.sender, userOpHash, op.validUntil);
  const signatures = await Promise.all(signers.map((signer) => signer.sign(digest)));
  const sigs: [SlotSig, SlotSig] = [
    { slotIndex: slotIndices[0], signature: signatures[0]! },
    { slotIndex: slotIndices[1], signature: signatures[1]! },
  ];

  return { ...op, signature: encodeUserOpSignature(op.validUntil, sigs) };
}

/**
 * Turns a failed `simulateContract` call into a typed Glaux error. Walks the
 * error's cause chain for a `ContractFunctionRevertedError`, whose `.data`
 * is the ABI-decoded custom error when the ABI recognizes it — the
 * EntryPoint's own `FailedOp`/`FailedOpWithRevert`
 * (`lib/account-abstraction/contracts/interfaces/IEntryPoint.sol`).
 */
function toUserOpError(revertError: ContractFunctionRevertedError, outer: BaseError): Error {
  if (revertError.data?.errorName === "FailedOp") {
    const [opIndex, reason] = revertError.data.args as readonly [bigint, string];
    return new UserOpFailedError(opIndex, reason);
  }
  if (revertError.data?.errorName === "FailedOpWithRevert") {
    const [opIndex, reason] = revertError.data.args as readonly [bigint, string, Hex];
    return new UserOpFailedError(opIndex, reason);
  }
  const reason = revertError.data?.errorName ?? revertError.reason ?? revertError.shortMessage;
  return new UserOpSubmissionRevertedError(reason ?? outer.shortMessage);
}

/**
 * Submits a signed `PackedUserOperation` straight to the canonical EntryPoint's
 * `handleOps` — the "no bundler yet" test path this task ships (a real
 * bundler, and its own submission function, arrive in Task 11). `relayer` is
 * a private key that only fronts the `handleOps` transaction's OWN L1 gas and
 * receives `beneficiary`'s compensation; unlike the direct path
 * (`./direct.js`'s `submitExecution`), the ACCOUNT itself pays for its
 * operation's cost via `validateUserOp`'s self-funding transfer, not the
 * relayer — that is the whole point of this task's self-funded design.
 *
 * Simulates first (an `eth_call`, nothing broadcast) so a revert is decoded
 * against the EntryPoint's own ABI into a typed error BEFORE spending gas on
 * a doomed transaction, mirroring `submitExecution`'s pattern. Only after the
 * simulation succeeds does this build, sign, and send the real transaction,
 * then requires `receipt.status === "success"`.
 *
 * @throws {UserOpFailedError} if the EntryPoint reverts `FailedOp`/`FailedOpWithRevert`.
 * @throws {UserOpSubmissionRevertedError} if the simulation reverts for any other decodable reason.
 * @throws {UserOpSimulationError} if simulation cannot be confirmed.
 * @throws {ExecutionStateReadError} if a fee field, the relayer's nonce, or the chain id cannot be read.
 * @throws {UserOpGasEstimationError} if a gas estimate cannot be obtained after a successful simulation.
 * @throws {UserOpTransactionRevertedError} if the mined transaction's receipt reports failure.
 */
export async function submitUserOpDirect(
  client: PublicClient,
  relayer: Hex,
  beneficiary: Address,
  op: PackedUserOperation,
): Promise<Hex> {
  const relayerAddress = privateKeyToAddress(relayer);
  const ops = [op];

  try {
    const simulation: unknown = await client.simulateContract({
      address: ENTRYPOINT,
      abi: ENTRYPOINT_ABI,
      functionName: "handleOps",
      args: [ops, beneficiary],
      account: relayerAddress,
    });
    if (
      typeof simulation !== "object" ||
      simulation === null ||
      !("request" in simulation) ||
      typeof simulation.request !== "object" ||
      simulation.request === null
    ) {
      throw new UserOpSimulationError();
    }
  } catch (error) {
    if (error instanceof UserOpSimulationError) throw error;
    if (error instanceof BaseError) {
      const revertError = error.walk(
        (candidate) => candidate instanceof ContractFunctionRevertedError,
      ) as ContractFunctionRevertedError | null;
      if (revertError !== null) throw toUserOpError(revertError, error);
    }
    throw new UserOpSimulationError();
  }

  const data = encodeFunctionData({ abi: ENTRYPOINT_ABI, functionName: "handleOps", args: [ops, beneficiary] });

  const [chainId, nonce, latestBlock, gasPrice, priorityFee] = await Promise.all([
    readChainId(client),
    readRelayerNonce(client, relayerAddress),
    readLatestBlock(client),
    readNonNegativeFee(() => client.getGasPrice(), "gas price"),
    readNonNegativeFee(() => client.estimateMaxPriorityFeePerGas(), "priority fee"),
  ]);

  let estimate: unknown;
  try {
    estimate = await client.estimateGas({ account: relayerAddress, to: ENTRYPOINT, data });
  } catch {
    throw new UserOpGasEstimationError();
  }
  if (typeof estimate !== "bigint") {
    throw new UserOpGasEstimationError();
  }
  const gas = (estimate * 3n) / 2n + 50_000n;
  const baseFee = latestBlock.baseFeePerGas ?? gasPrice;
  const maxFeePerGas = baseFee * 2n + priorityFee;

  const signedTransaction = await signTransaction({
    privateKey: relayer,
    transaction: {
      chainId,
      nonce,
      to: ENTRYPOINT,
      value: 0n,
      gas,
      maxFeePerGas,
      maxPriorityFeePerGas: priorityFee,
      data,
    },
  });

  const txHash = await sendRawTransaction(client, { serializedTransaction: signedTransaction });
  const receipt = await readExecutionReceiptWithLogs(client, txHash);
  if (receipt.status !== "success") {
    throw new UserOpTransactionRevertedError(txHash);
  }
  const userOpHash = computeUserOpHash(op, ENTRYPOINT, BigInt(chainId));
  const event = extractUserOperationEvent(receipt.logs, userOpHash, txHash);
  if (!event.success) {
    throw new UserOpExecutionFailedError(txHash, userOpHash);
  }
  return txHash;
}

export interface UserOperationEventData {
  readonly success: boolean;
  readonly actualGasCost: bigint;
  readonly actualGasUsed: bigint;
}

/**
 * Reads the EntryPoint's own `UserOperationEvent` for `userOpHash` out of a
 * transaction's logs — "read the event; do not infer": a `handleOps` call
 * can batch multiple operations, and its receipt's aggregate `gasUsed` is
 * never this one operation's real cost. `actualGasCost` here is the exact
 * value `_postExecution`
 * (`lib/account-abstraction/contracts/core/EntryPoint.sol:685-750`) computed
 * and is what the account was actually charged.
 *
 * @throws {UserOpEventNotFoundError} if no matching event is found — an
 * absent event means the real cost is unknown, never assumed to be zero.
 */
export function extractUserOperationEvent(
  logs: readonly Log[],
  userOpHash: Hex,
  txHash?: Hex,
): UserOperationEventData {
  for (const log of logs) {
    if (typeof log.address !== "string" || log.address.toLowerCase() !== ENTRYPOINT.toLowerCase()) continue;
    try {
      const decoded = decodeEventLog({
        abi: ENTRYPOINT_ABI,
        data: log.data,
        topics: log.topics,
      });
      if (decoded.eventName === "UserOperationEvent" && decoded.args.userOpHash === userOpHash) {
        return {
          success: decoded.args.success,
          actualGasCost: decoded.args.actualGasCost,
          actualGasUsed: decoded.args.actualGasUsed,
        };
      }
    } catch {
      continue;
    }
  }
  throw new UserOpEventNotFoundError(userOpHash, txHash);
}

/**
 * Reads the account's ERC-4337 deposit balance held inside the EntryPoint
 * (`StakeManager.balanceOf`) — distinct from the account's native balance.
 * The e2e test uses this to prove exactly where the self-funded prefund's
 * unspent remainder ends up (credited back as a deposit, never returned to
 * native balance in the same operation — see `_postExecution`).
 *
 * @throws {ExecutionStateReadError} if the RPC response is absent or malformed.
 */
export async function fetchEntryPointDeposit(
  client: PublicClient,
  entryPoint: Address,
  account: Address,
): Promise<bigint> {
  let deposit: unknown;
  try {
    deposit = await client.readContract({
      address: entryPoint,
      abi: ENTRYPOINT_ABI,
      functionName: "balanceOf",
      args: [account],
    });
  } catch (error) {
    throw error instanceof ExecutionStateReadError ? error : new ExecutionStateReadError("entrypoint deposit");
  }
  if (typeof deposit !== "bigint" || deposit < 0n) {
    throw new ExecutionStateReadError("entrypoint deposit");
  }
  return deposit;
}
