import type { Address, Hex } from "viem";

/**
 * Thrown when a caller supplies `validUntil === 0` to an operation digest or
 * signature encoder.
 *
 * The ERC-4337 EntryPoint packs `validUntil` into the returned `validationData`
 * and reads a packed value of `0` as "no expiry" rather than as a timestamp.
 * `GlauxAccount.validateUserOp` already refuses to validate a user operation whose
 * signed `validUntil` is `0` (`decoded && validUntil != 0 && ...`), so a client
 * that built such a signature anyway would only discover it is unusable after a
 * round trip through a bundler. Failing at build time is strictly earlier.
 *
 * Zero is unusable on every Glaux operation path: direct execution reverts it
 * as expired, ERC-4337 returns signature-validation failure, and ERC-1271
 * returns its invalid sentinel. Rejecting it while building prevents clients
 * from producing a signature the contract cannot use.
 */
export class OperationExpiredError extends Error {
  constructor() {
    super(
      "validUntil must not be 0: Glaux rejects it on every operation path.",
    );
    this.name = "OperationExpiredError";
  }
}

/**
 * Thrown before signing when an operation deadline exceeds the SDK's
 * caller-selected validity ceiling.
 *
 * The default ceiling is deliberately measured from the client's local
 * clock, not an RPC-supplied block timestamp: its job is to bound how long a
 * future-nonce signature harvested by a hostile endpoint can become useful.
 * It cannot prevent replay inside the accepted window.
 */
export class ExecutionValidityWindowError extends Error {
  readonly validUntil: number;
  readonly latestAllowed: number;
  readonly maxValidityWindowSeconds: number;

  constructor(validUntil: number, latestAllowed: number, maxValidityWindowSeconds: number) {
    super(
      `validUntil ${validUntil} exceeds the locally enforced execution ceiling ${latestAllowed} ` +
        `(${maxValidityWindowSeconds} seconds from now); refusing to sign a longer-lived operation.`,
    );
    this.name = "ExecutionValidityWindowError";
    this.validUntil = validUntil;
    this.latestAllowed = latestAllowed;
    this.maxValidityWindowSeconds = maxValidityWindowSeconds;
  }
}

/**
 * Thrown before signing when an operation's deadline is already at or behind
 * the client's local clock. The contract evaluates `block.timestamp > validUntil`
 * and rejects any operation whose deadline the next block will have passed, so
 * signing one that is already expired only spends a quorum signature — and, on
 * the relayed paths, gas — on a transaction guaranteed to revert. Distinct from
 * {@link OperationExpiredError} (the `validUntil === 0` case) and from
 * {@link ExecutionExpiredError} (the contract's own on-chain rejection, decoded
 * from real revert data). Like {@link ExecutionValidityWindowError}, the bound is
 * the client's local clock, not an RPC-supplied block timestamp.
 */
export class OperationAlreadyExpiredError extends Error {
  readonly validUntil: number;
  readonly now: number;

  constructor(validUntil: number, now: number) {
    super(
      `validUntil ${validUntil} is at or before the current time ${now}; ` +
        "refusing to sign an already-expired operation.",
    );
    this.name = "OperationAlreadyExpiredError";
    this.validUntil = validUntil;
    this.now = now;
  }
}

/**
 * Thrown when a signer is asked to sign something other than the `bytes32`
 * digest the Glaux contracts verify.
 */
export class InvalidDigestLengthError extends Error {
  constructor() {
    super("digest must be exactly 32 bytes.");
    this.name = "InvalidDigestLengthError";
  }
}

/**
 * Thrown when a possession proof is requested for a factor slot that Glaux
 * does not have.
 */
export class InvalidSlotIndexError extends Error {
  constructor() {
    super("slot index must be an integer from 0 through 2.");
    this.name = "InvalidSlotIndexError";
  }
}

/**
 * Thrown when local P-256 signer material is not a valid 32-byte scalar.
 */
export class InvalidP256PrivateKeyError extends Error {
  constructor() {
    super("P-256 private key must be a 32-byte scalar in the curve order.");
    this.name = "InvalidP256PrivateKeyError";
  }
}

/**
 * Thrown when `buildBirthBlob` cannot read a deployed implementation from the
 * chain named by `chainRpc`.
 *
 * `docs/client-guidance.md`'s Birth section is explicit that `expectedCodeHash`
 * must come from a deployment the caller has verified, never assumed from a
 * local build artifact. Reading an empty account's code and hashing it would
 * silently produce `keccak256("")` rather than fail: a value that can never
 * match a real `implementation.codehash`, so a blob built against it would be
 * permanently unusable — and a birth blob cannot be revoked or rebuilt into
 * the same account, because the account address is derived from the very
 * configuration a rebuild would change. The failure has to happen here.
 */
export class ImplementationNotDeployedError extends Error {
  constructor(implementation: Address) {
    super(
      `no code at implementation address ${implementation} on the given chain; deploy it before building a birth blob.`,
    );
    this.name = "ImplementationNotDeployedError";
  }
}

/** Thrown when code at the canonical implementation address is not the published runtime. */
export class ImplementationCodeHashMismatchError extends Error {
  constructor(actual: Hex) {
    super(`implementation code hash ${actual} does not match the published canonical hash.`);
    this.name = "ImplementationCodeHashMismatchError";
  }
}

/** Thrown when the canonical implementation cannot prove its Glaux compatibility marker. */
export class ImplementationCompatibilityError extends Error {
  constructor() {
    super("canonical implementation did not return the Glaux compatibility marker; refusing to sign or submit a birth blob.");
    this.name = "ImplementationCompatibilityError";
  }
}

/** Thrown when a factor identifies an unsupported verifier, before any blob is crafted. */
export class InvalidBirthVerifierTypeError extends Error {
  readonly slotIndex: number;

  constructor(slotIndex: number) {
    super(`birth factor slot ${slotIndex} has an unsupported verifier type.`);
    this.name = "InvalidBirthVerifierTypeError";
    this.slotIndex = slotIndex;
  }
}

/** Thrown when a factor's key encoding fails the exact on-chain validity predicate. */
export class InvalidBirthSlotError extends Error {
  readonly slotIndex: number;

  constructor(slotIndex: number) {
    super(`birth factor slot ${slotIndex} has key data that Glaux will reject.`);
    this.name = "InvalidBirthSlotError";
    this.slotIndex = slotIndex;
  }
}

/** Thrown when two factor slots encode the same `(verifierType, data)` pair. */
export class DuplicateBirthSlotError extends Error {
  readonly firstSlotIndex: number;
  readonly secondSlotIndex: number;

  constructor(firstSlotIndex: number, secondSlotIndex: number) {
    super(`birth factor slots ${firstSlotIndex} and ${secondSlotIndex} are duplicates and Glaux will reject them.`);
    this.name = "DuplicateBirthSlotError";
    this.firstSlotIndex = firstSlotIndex;
    this.secondSlotIndex = secondSlotIndex;
  }
}

/** Thrown when the public P-256 verifier probe key is supplied as a factor. */
export class ProbeKeyNotInstallableError extends Error {
  readonly slotIndex: number;

  constructor(slotIndex: number) {
    super(`birth factor slot ${slotIndex} is the public P-256 verifier probe key and cannot be installed.`);
    this.name = "ProbeKeyNotInstallableError";
    this.slotIndex = slotIndex;
  }
}

/** Thrown when a signer emitted a possession proof the contract will reject. */
export class BirthPossessionProofError extends Error {
  readonly slotIndex: number;

  constructor(slotIndex: number) {
    super(`birth factor slot ${slotIndex} did not produce a possession proof Glaux will accept.`);
    this.name = "BirthPossessionProofError";
    this.slotIndex = slotIndex;
  }
}

/**
 * Thrown if the crafted authorization does not recover to the account the blob
 * names. Nothing signs a birth, so `"authorization"` is the only part there is
 * to check — the union kept a `"birth signature"` member no caller could pass
 * once births became rootless.
 */
export class BirthBlobSelfCheckError extends Error {
  constructor(part: "authorization") {
    super(`generated ${part} does not recover to the birth account; refusing to emit an unrecoverable blob.`);
    this.name = "BirthBlobSelfCheckError";
  }
}

/** Thrown when an RPC chain id differs from the chain the caller explicitly selected. */
export class ChainIdMismatchError extends Error {
  readonly expected: number;
  readonly actual: number;

  constructor(expected: number, actual: number) {
    super(`RPC reported chain id ${actual}, but the caller selected chain id ${expected}; refusing to sign or submit on an ambiguous chain.`);
    this.name = "ChainIdMismatchError";
    this.expected = expected;
    this.actual = actual;
  }
}

/**
 * Thrown before signing a user operation whose named EntryPoint is not the
 * canonical one Glaux accounts accept. `GlauxAccount.validateUserOp` reverts
 * unless `msg.sender == ENTRYPOINT` (an immutable set at deployment), so exactly
 * one EntryPoint can ever validate an operation; a signature folded — through
 * `getUserOpHash` — over any other EntryPoint's address is one the account can
 * never use. Refusing it keeps a quorum signature from being spent on an
 * operation bound to an EntryPoint that will never call the account, matching the
 * direct path's binding of its own chain id.
 */
export class EntryPointMismatchError extends Error {
  readonly expected: Address;
  readonly actual: Address;

  constructor(expected: Address, actual: Address) {
    super(
      `operation names EntryPoint ${actual}, but Glaux accounts only accept the canonical ` +
        `EntryPoint ${expected}; refusing to sign for another.`,
    );
    this.name = "EntryPointMismatchError";
    this.expected = expected;
    this.actual = actual;
  }
}

/** Thrown when a restore/interchange birth blob changes a canonical binding. */
export class InvalidBirthBlobError extends Error {
  readonly field:
    | "router"
    | "implementation"
    | "authorization target"
    | "authorization chain id"
    | "authorization nonce"
    | "authorization signer"
    | "authorization r"
    | "authorization parity"
    | "authorization rootless proof";

  constructor(field: InvalidBirthBlobError["field"]) {
    super(`birth blob ${field} is not canonical; refusing to broadcast it.`);
    this.name = "InvalidBirthBlobError";
    this.field = field;
  }
}

/** Thrown when a mined birth transaction did not leave the exact expected account state. */
export class BirthPostconditionError extends Error {
  constructor(reason: string) {
    super(`birth transaction succeeded but did not establish the expected Glaux account state: ${reason}`);
    this.name = "BirthPostconditionError";
  }
}

/**
 * Thrown by `preflightFreshAccount` when a candidate birth account is not a
 * pristine EOA — port of `scripts/submit_birth.py:preflight_fresh_account`,
 * hardened per audit finding H-2 (threat-model residual 17).
 *
 * An EIP-7702 re-delegation does not clear storage, and Glaux's namespaced
 * slots are public, so a hostile prior delegate could pre-plant them and
 * present as an attacker-owned Glaux account the instant this blob delegates
 * to the router — or, less catastrophically, brick the birth by poisoning a
 * word the account's own init path never expects to see non-zero. This error
 * is the client-side gate: no on-chain check can catch it, because by the
 * time `initialize` runs the EIP-7702 authorization is already applied
 * regardless of whether the call that follows it reverts.
 */
export class BirthPreflightError extends Error {
  constructor(reason: string) {
    super(`refusing to submit birth blob: ${reason}`);
    this.name = "BirthPreflightError";
  }
}

/**
 * Thrown when the birth preflight cannot obtain a well-formed code or storage
 * value from its RPC client.
 *
 * This is intentionally distinct from `BirthPreflightError`: the latter means
 * the account was read successfully and is unsafe to birth, whereas this
 * error means the account's safety is unknown. An unknown account must never
 * be treated as an empty EOA: the blob is one-shot per chain, and by the time
 * an erroneous preflight is discovered the authorization has been applied.
 */
export class BirthPreflightReadError extends Error {
  readonly account: Address;
  readonly target: "code" | "storage";
  readonly slot: Hex | undefined;

  constructor(account: Address, target: "code" | "storage", slot?: Hex) {
    const location = target === "code" ? "account code" : `storage word at ${slot}`;
    super(
      `refusing to submit birth blob: could not read ${location} for ${account}; ` +
        "the RPC response was absent, malformed, or failed. Account cleanliness is unknown.",
    );
    this.name = "BirthPreflightReadError";
    this.account = account;
    this.target = target;
    this.slot = slot;
  }
}

/**
 * Thrown when an EIP-7702 birth cannot be priced with an authorization-aware,
 * plausible gas estimate. Nothing has been broadcast when this is thrown.
 */
export class BirthGasEstimationError extends Error {
  constructor() {
    super(
      "unable to obtain a plausible gas estimate for the EIP-7702 birth transaction; refusing to broadcast.",
    );
    this.name = "BirthGasEstimationError";
  }
}

/** Thrown when the type-4 transaction was mined but its initialization reverted. */
export class BirthTransactionRevertedError extends Error {
  readonly txHash: Hex;

  constructor(txHash: Hex) {
    super(`birth transaction ${txHash} was mined but initialization reverted; birth did not succeed.`);
    this.name = "BirthTransactionRevertedError";
    this.txHash = txHash;
  }
}

/**
 * Thrown when `signExecution` is given a signer whose key material does not
 * match any of the account's three installed factor slots.
 *
 * `executeWithSigs` identifies a factor by `slotIndex`, not by key material,
 * so a client must know which slot each signer occupies. Rather than accept a
 * caller-supplied index that could silently name the wrong slot (and produce
 * a signature that verifies against a different factor than the one that
 * actually signed), `signExecution` reads the account's three slots live and
 * matches each signer to the one whose `(verifierType, data)` equals the
 * signer's own — the only source of truth for "which slot is this", per the
 * contract's own state rather than an assumption about factor ordering.
 */
export class UnrecognizedSignerError extends Error {
  constructor() {
    super(
      "a provided signer's key material does not match any of the account's three installed factor slots.",
    );
    this.name = "UnrecognizedSignerError";
  }
}

/**
 * Thrown when `signExecution` (direct path) or `buildUserOp`/`signUserOp`
 * (ERC-4337 path, `../execute/userop.js`) cannot obtain a well-formed value
 * needed to bind a quorum, or a submission, to the account's current state.
 * This is deliberately distinct from a recognized but unsuitable state:
 * unknown state must never be signed or submitted. Shared across both
 * execution paths on purpose: reading a nonce, a factor slot, or a fee field
 * fails closed the same way regardless of which transport ultimately carries
 * the operation.
 */
export class ExecutionStateReadError extends Error {
  readonly target:
    | "block number"
    | "chain id"
    | "account code"
    | "execution nonce"
    | "entrypoint nonce"
    | "entrypoint deposit"
    | "factor slot"
    | "relayer transaction nonce"
    | "latest block"
    | "gas price"
    | "priority fee"
    | "transaction receipt"
    | "userOp hash";
  readonly slotIndex: number | undefined;

  constructor(
    target: ExecutionStateReadError["target"],
    slotIndex?: number,
  ) {
    const location = target === "factor slot" ? `factor slot ${slotIndex}` : target;
    super(
      `could not read ${location}; the RPC response was absent, malformed, or failed. ` +
        "Refusing to continue with unknown chain state.",
    );
    this.name = "ExecutionStateReadError";
    this.target = target;
    this.slotIndex = slotIndex;
  }
}

/**
 * Thrown when two views of an execution nonce disagree: the contract getter
 * versus raw storage, the nonce an operation carries versus the live EntryPoint
 * nonce re-read at signing time, or their agreed value versus a caller-supplied
 * trusted expectation. No signature is requested after this error.
 *
 * Getter/raw agreement is only a consistency check against a buggy or
 * partially hostile endpoint. One fully hostile endpoint can forge both
 * replies consistently; callers that need authenticity must supply an
 * `expectedNonce` obtained independently.
 */
export class ExecutionNonceMismatchError extends Error {
  readonly path: "direct" | "erc4337";
  readonly source: "raw storage" | "caller expectation" | "entrypoint";
  readonly expected: bigint;
  readonly actual: bigint;

  constructor(
    path: ExecutionNonceMismatchError["path"],
    source: ExecutionNonceMismatchError["source"],
    expected: bigint,
    actual: bigint,
  ) {
    const label = path === "direct" ? "direct execution" : "ERC-4337";
    super(
      `${label} nonce ${actual} disagrees with ${source} value ${expected}; refusing to request signatures.`,
    );
    this.name = "ExecutionNonceMismatchError";
    this.path = path;
    this.source = source;
    this.expected = expected;
    this.actual = actual;
  }
}

/**
 * Thrown when a direct-execution snapshot proves that the account has no code.
 *
 * This is intentionally not an `ExecutionStateReadError`: the node answered
 * the reads coherently, and that answer establishes a known account state
 * rather than leaving the client with unknown chain state.
 */
export class ExecutionAccountNotBornError extends Error {
  readonly account: Address;
  readonly blockNumber: bigint;

  constructor(account: Address, blockNumber: bigint) {
    super(
      `account ${account} has no code at block ${blockNumber}; direct execution requires a born Glaux account.`,
    );
    this.name = "ExecutionAccountNotBornError";
    this.account = account;
    this.blockNumber = blockNumber;
  }
}

/**
 * Thrown when the direct-execution pre-flight could not be confirmed because
 * simulation failed without a contract revert, or returned no usable result.
 * This differs from `ExecutionRevertedError`: the latter proves the chain
 * evaluated the operation and rejected it; this error means that is unknown.
 */
export class ExecutionSimulationError extends Error {
  constructor() {
    super(
      "could not confirm the direct execution pre-flight simulation; the RPC response was absent, malformed, or failed. Refusing to broadcast.",
    );
    this.name = "ExecutionSimulationError";
  }
}

/**
 * Thrown when both supplied execution signers resolve to the same installed
 * factor slot. `GlauxAccount._checkTwoSigs` requires two distinct slots, so
 * emitting this quorum would be known to fail on-chain.
 */
export class DuplicateExecutionSignerError extends Error {
  readonly slotIndex: number;

  constructor(slotIndex: number) {
    super(
      `both execution signers resolve to factor slot ${slotIndex}; two distinct installed factor slots are required.`,
    );
    this.name = "DuplicateExecutionSignerError";
    this.slotIndex = slotIndex;
  }
}

/**
 * Thrown when `submitExecution`'s pre-flight simulation of `executeWithSigs`
 * reverts with `OperationExpired(uint48 validUntil, uint256 blockTimestamp)`
 * — the CONTRACT's own rejection of an expired operation, decoded from the
 * real revert data rather than inferred. Distinct from `OperationExpiredError`,
 * which fires client-side for `validUntil === 0` before any signing or RPC
 * call; this one only ever fires after the contract itself has evaluated
 * `block.timestamp > validUntil` and found the operation dead on arrival.
 */
export class ExecutionExpiredError extends Error {
  readonly validUntil: number;
  readonly blockTimestamp: bigint;

  constructor(validUntil: number, blockTimestamp: bigint) {
    super(
      `executeWithSigs reverted OperationExpired: validUntil ${validUntil} is not after block timestamp ${blockTimestamp}.`,
    );
    this.name = "ExecutionExpiredError";
    this.validUntil = validUntil;
    this.blockTimestamp = blockTimestamp;
  }
}

/**
 * Thrown when `submitExecution`'s pre-flight simulation of `executeWithSigs`
 * reverts with a decoded reason other than `OperationExpired` (for example
 * `InvalidSignature`, `NotInitialized`, or `CallFailed`), or with a reason
 * that could not be decoded against the account's ABI at all. `reason`
 * carries whatever the simulation could establish — the decoded custom
 * error's name, or the raw message — so a caller can distinguish "no
 * quorum" from "account not initialized" from "one of the calls failed"
 * rather than seeing only "it reverted".
 */
export class ExecutionRevertedError extends Error {
  readonly reason: string;

  constructor(reason: string) {
    super(`executeWithSigs simulation reverted: ${reason}`);
    this.name = "ExecutionRevertedError";
    this.reason = reason;
  }
}

/**
 * Thrown when a plausible gas estimate for `executeWithSigs` cannot be
 * obtained after the pre-flight simulation already succeeded. Nothing has
 * been broadcast when this is thrown.
 */
export class ExecutionGasEstimationError extends Error {
  constructor() {
    super(
      "unable to obtain a gas estimate for the direct execution transaction; refusing to broadcast.",
    );
    this.name = "ExecutionGasEstimationError";
  }
}

/**
 * Thrown when the direct execution transaction was mined but its receipt
 * reports failure — despite a successful pre-flight simulation (for example
 * a state change between simulation and inclusion). Never silently treated
 * as success.
 */
export class ExecutionTransactionRevertedError extends Error {
  readonly txHash: Hex;

  constructor(txHash: Hex) {
    super(`execution transaction ${txHash} was mined but reverted.`);
    this.name = "ExecutionTransactionRevertedError";
    this.txHash = txHash;
  }
}

/**
 * Thrown when a plausible gas estimate for the ERC-4337 path (either
 * `executeFromEntryPoint`'s call gas in `buildUserOp`, or `handleOps`' own
 * transaction gas in `submitUserOpDirect`) cannot be obtained. Nothing has
 * been broadcast when this is thrown.
 */
export class UserOpGasEstimationError extends Error {
  constructor() {
    super(
      "unable to obtain a gas estimate for the ERC-4337 user operation; refusing to broadcast.",
    );
    this.name = "UserOpGasEstimationError";
  }
}

/**
 * Thrown before encoding a UserOperation whose EntryPoint gas field exceeds
 * v0.7's `uint120` ceiling. `PackedUserOperation` physically reserves 128
 * bits, but EntryPoint rejects the top eight with AA94; producing one would
 * therefore create an artifact guaranteed to fail on-chain.
 */
export class UserOpGasValueOutOfRangeError extends Error {
  readonly field: string;
  readonly value: bigint;
  readonly max: bigint;

  constructor(field: string, value: bigint, max: bigint) {
    super(`ERC-4337 ${field} ${value} exceeds the EntryPoint uint120 maximum ${max}.`);
    this.name = "UserOpGasValueOutOfRangeError";
    this.field = field;
    this.value = value;
    this.max = max;
  }
}

/**
 * Thrown when `submitUserOpDirect`'s pre-flight simulation of `handleOps`
 * could not be confirmed because simulation failed without a decodable
 * revert, or returned no usable result. Distinct from `UserOpFailedError`:
 * that error proves the EntryPoint evaluated the operation and rejected it;
 * this one means that is unknown.
 */
export class UserOpSimulationError extends Error {
  constructor() {
    super(
      "could not confirm the handleOps pre-flight simulation; the RPC response was absent, malformed, or failed. Refusing to broadcast.",
    );
    this.name = "UserOpSimulationError";
  }
}

/**
 * Thrown when `submitUserOpDirect`'s pre-flight simulation of `handleOps`
 * reverts with the EntryPoint's own `FailedOp(uint256 opIndex, string reason)`
 * (or `FailedOpWithRevert`) custom error, decoded from the real revert data
 * rather than inferred. `reason` carries the EntryPoint's exact diagnostic
 * string (for example `"AA24 signature error"` or `"AA22 expired or not
 * due"`, both defined in the vendored
 * `lib/account-abstraction/contracts/core/EntryPoint.sol`), so a caller can
 * distinguish a bad quorum from an expired window from an unauthorized
 * caller rather than seeing only "it reverted".
 */
export class UserOpFailedError extends Error {
  readonly opIndex: bigint;
  readonly reason: string;

  constructor(opIndex: bigint, reason: string) {
    super(`handleOps reverted FailedOp(${opIndex}): ${reason}`);
    this.name = "UserOpFailedError";
    this.opIndex = opIndex;
    this.reason = reason;
  }
}

/**
 * Thrown when `submitUserOpDirect`'s pre-flight simulation of `handleOps`
 * reverts for a reason that could not be decoded as `FailedOp`/
 * `FailedOpWithRevert` against the EntryPoint's own ABI.
 */
export class UserOpSubmissionRevertedError extends Error {
  readonly reason: string;

  constructor(reason: string) {
    super(`handleOps simulation reverted: ${reason}`);
    this.name = "UserOpSubmissionRevertedError";
    this.reason = reason;
  }
}

/**
 * Thrown when the `handleOps` transaction was mined but its receipt reports
 * failure — despite a successful pre-flight simulation (for example a state
 * change between simulation and inclusion). Never silently treated as success.
 */
export class UserOpTransactionRevertedError extends Error {
  readonly txHash: Hex;

  constructor(txHash: Hex) {
    super(`handleOps transaction ${txHash} was mined but reverted.`);
    this.name = "UserOpTransactionRevertedError";
    this.txHash = txHash;
  }
}

/**
 * Thrown when `handleOps` itself mined successfully but EntryPoint recorded
 * the submitted UserOperation as reverted. This is distinct from
 * `UserOpTransactionRevertedError`: EntryPoint deliberately catches an
 * account-call failure, consumes the operation, and emits
 * `UserOperationEvent(success=false)` while leaving the outer transaction
 * successful.
 */
export class UserOpExecutionFailedError extends Error {
  readonly txHash: Hex;
  readonly userOpHash: Hex;

  constructor(txHash: Hex, userOpHash: Hex) {
    super(`user operation ${userOpHash} failed during handleOps transaction ${txHash}.`);
    this.name = "UserOpExecutionFailedError";
    this.txHash = txHash;
    this.userOpHash = userOpHash;
  }
}

/**
 * Thrown when a mined `handleOps` transaction's receipt reports success but
 * no `UserOperationEvent` for the expected `userOpHash` can be found in its
 * logs. `submitUserOpDirect` and its callers must read the real cost the
 * EntryPoint reports, never infer it from the transaction receipt's own gas
 * fields (which include EVERY operation in the bundle, not just this one) —
 * an absent event means that real cost is unknown, not zero.
 */
export class UserOpEventNotFoundError extends Error {
  readonly userOpHash: Hex;
  readonly txHash: Hex | undefined;

  constructor(userOpHash: Hex, txHash?: Hex) {
    super(
      txHash === undefined
        ? `no UserOperationEvent found for userOpHash ${userOpHash} in the transaction's logs.`
        : `no UserOperationEvent found for userOpHash ${userOpHash} in transaction ${txHash}'s logs.`,
    );
    this.name = "UserOpEventNotFoundError";
    this.userOpHash = userOpHash;
    this.txHash = txHash;
  }
}

/**
 * Thrown by `../gas/erc7677.js`'s `Erc7677Client` whenever an ERC-7677
 * paymaster-service call cannot be trusted: a transport failure, a non-2xx
 * HTTP status, a JSON-RPC `error` field, or a response that does not
 * validate against the expected shape (a missing/malformed `paymaster`
 * address or `paymasterData`). All four collapse into this one error
 * deliberately: per the design's threat model (`docs/threat-model.md`, the
 * paymaster entry), a paymaster can at worst DENY sponsorship, so an
 * ambiguous or malformed response is treated exactly like an explicit
 * denial — never retried, never coerced into a best-effort guess at what
 * the provider "probably" meant. `../gas/policy.js`'s `GasPolicy` catches
 * this (by name, via `.name`) to drive its sponsored → self-funded
 * fallback, and surfaces the transition as an observable event rather than
 * silently degrading (spec `docs/specs/2026-08-03-glaux-phase4-sdk-design.md`
 * §7).
 */
export class PaymasterUnavailableError extends Error {
  readonly method: "pm_getPaymasterStubData" | "pm_getPaymasterData";

  constructor(method: "pm_getPaymasterStubData" | "pm_getPaymasterData", reason: string) {
    super(`ERC-7677 ${method} failed: ${reason}`);
    this.name = "PaymasterUnavailableError";
    this.method = method;
  }
}

/**
 * Thrown (as the fallback event's `cause`, never actually thrown to a
 * caller — see `../gas/policy.js`'s `GasPolicy.plan`) when no ERC-7677
 * provider is configured at all: `GLAUX_PAYMASTER_URL` is unset, or the
 * caller explicitly passed `paymasterClient: null`.
 *
 * Deliberately distinct from `PaymasterUnavailableError`: that error means a
 * configured provider was asked and failed to answer trustworthily; this one
 * means sponsorship was never attempted in the first place. Collapsing the
 * two into one cause would let an integrator's missing configuration masquerade
 * as "the provider happened to be down today" — exactly the silent-fallback
 * failure mode spec §7 forbids.
 */
export class PaymasterNotConfiguredError extends Error {
  constructor() {
    super("no ERC-7677 paymaster provider is configured (GLAUX_PAYMASTER_URL is unset).");
    this.name = "PaymasterNotConfiguredError";
  }
}

/**
 * Thrown by `../reconcile/reconcile.js` when a raw code/storage read, or
 * issuing a getter call at all, fails for a reason that is not itself an EVM
 * revert.
 *
 * The two failures are kept apart, and `scripts/reconcile.py` keeps them
 * apart the same way (its own `ReconciliationReadError`, exit 3): an
 * implementation that cannot describe its own state IS a reconciliation
 * finding (the `"unreadable"` verdict, Python's exit 2), but a dropped
 * connection or malformed JSON-RPC response is not evidence about the chain's
 * state at all — it is evidence about nothing, and reporting any verdict from
 * it would be silently treating unknown state as reconciled. The Python tool's
 * exit codes are therefore 0/1/2/3, with 3 outside the verdict range
 * altogether.
 */
export class ReconciliationReadError extends Error {
  readonly chain: string;
  readonly target: "account code" | "storage word" | "implementation code" | "getter call";

  constructor(chain: string, target: ReconciliationReadError["target"]) {
    super(
      `reconciliation on chain "${chain}" could not read ${target}: the RPC response was absent, malformed, or the transport failed. Chain state is unknown, not reconciled.`,
    );
    this.name = "ReconciliationReadError";
    this.chain = chain;
    this.target = target;
  }
}

/**
 * Used (as the fallback event's `cause`, never actually thrown — see
 * `../gas/policy.js`'s `GasPolicy.plan`) when neither sponsorship nor
 * self-funded ERC-4337 is viable: the account's own native balance cannot
 * cover the prefund still missing after its EntryPoint deposit is consumed.
 * `GasPolicy` degrades to
 * `selfRelay` at that point — the structural fallback the design (§2) treats
 * as always available, because direct execution (`../execute/direct.js`) is
 * permissionless and needs no prefund from the account at all.
 */
export class SelfFundingUnavailableError extends Error {
  readonly required: bigint;
  readonly available: bigint;

  constructor(required: bigint, available: bigint) {
    super(
      `account balance ${available} is insufficient for the self-funded ERC-4337 path's remaining prefund ${required}.`,
    );
    this.name = "SelfFundingUnavailableError";
    this.required = required;
    this.available = available;
  }
}

/**
 * Thrown when the fee baseline cannot be established from a well-formed
 * `eth_feeHistory` response.
 *
 * The baseline exists to price an operation WITHOUT trusting the fee values
 * the same endpoint proposes, so there is no safe fallback when it cannot be
 * read: guessing one, or silently reverting to the proposed fee, would restore
 * exactly the situation the guard removes. A caller that cannot reach a usable
 * fee history must decide — retry, switch endpoint, or supply its own
 * baseline — rather than have the SDK decide for it.
 */
export class FeeBaselineReadError extends Error {
  readonly field: string;

  constructor(field: string) {
    super(`cannot establish a fee baseline: ${field} is missing or malformed in the fee history.`);
    this.name = "FeeBaselineReadError";
    this.field = field;
  }
}

/**
 * Thrown before signing when an operation's `maxFeePerGas` exceeds a sanity
 * multiple of the independently computed baseline.
 *
 * This is the wallet-grade anomaly check (Rabby's "this costs far more than
 * this kind of call should", MetaMask's habit of computing fees itself rather
 * than accepting what it is handed), applied at the only moment that matters
 * for a 2-of-3 account: before the quorum's signature exists. It bounds the
 * PRICE per gas; the absolute worst-case spend is bounded separately by
 * {@link UserOpCostExceedsCapError}'s cap, which holds even when the baseline
 * itself is a lie.
 */
export class FeeExceedsBaselineError extends Error {
  readonly maxFeePerGas: bigint;
  readonly allowed: bigint;

  constructor(maxFeePerGas: bigint, allowed: bigint) {
    super(
      `maxFeePerGas ${maxFeePerGas} exceeds ${allowed}, the sanity ceiling derived from this chain's own fee history; ` +
        "refusing to sign.",
    );
    this.name = "FeeExceedsBaselineError";
    this.maxFeePerGas = maxFeePerGas;
    this.allowed = allowed;
  }
}

/**
 * Thrown when no salt in the allowed range produces a curve point.
 *
 * Not a caller error and not reachable in practice: each attempt succeeds with
 * probability about one half, so 256 consecutive failures would mean keccak256
 * had stopped behaving like a hash. It exists so a derivation loop can never
 * spin forever on an immutable contract's input.
 */
export class RootlessDerivationError extends Error {
  readonly digest: string;
  readonly attempts: number;

  constructor(digest: string, attempts: number) {
    super(`no rootless authorization found for digest ${digest} in ${attempts} attempts.`);
    this.name = "RootlessDerivationError";
    this.digest = digest;
    this.attempts = attempts;
  }
}

/**
 * Thrown when a packed 32-byte operation word is not 32 bytes.
 *
 * The two readings diverge exactly there: this SDK unpacks with `hexToBigInt`,
 * which reads a short word as a NUMBER (left-padded), while ABI encoding treats
 * `bytes32` as right-padded — so a 31-byte `gasFees` would be judged at one fee
 * here and mean 256 times that on chain. Nothing exploits this today, because
 * viem's encoder rejects the short word before any signer is reached, but that
 * makes the guard's correctness rest on another library's strictness and on the
 * order of two statements. Neither is a thing to rely on silently.
 */
export class MalformedPackedWordError extends Error {
  readonly field: string;
  readonly length: number;

  constructor(field: string, length: number) {
    super(`${field} must be exactly 32 bytes; received ${length}. Refusing to price a malformed word.`);
    this.name = "MalformedPackedWordError";
    this.field = field;
    this.length = length;
  }
}

/**
 * Thrown when the mandatory cost cap is missing or is not a non-negative
 * bigint.
 *
 * TypeScript marks `maxCostWei` required, which constrains nothing once the
 * package is consumed from JavaScript: an omitted argument arrives as
 * `undefined`, and `cost > undefined` evaluates to `false`, so the comparison
 * passes and the operation is signed with no bound whatsoever. The single
 * parameter whose entire purpose is to be mandatory cannot be left to the
 * compiler to enforce.
 */
export class InvalidCostCapError extends Error {
  readonly received: unknown;

  constructor(received: unknown) {
    super(
      `maxCostWei must be a non-negative bigint; received ${typeof received === "bigint" ? received.toString() : String(received)}. ` +
        "Refusing to sign without a cost bound.",
    );
    this.name = "InvalidCostCapError";
    this.received = received;
  }
}

/**
 * Thrown before signing when an operation's worst-case prefund exceeds the
 * caller's absolute cap.
 *
 * The cap is mandatory and deliberately independent of every value an endpoint
 * supplies: a signature over a user operation authorizes the EntryPoint to
 * collect up to `(verificationGas + callGas + preVerificationGas + paymaster
 * limits) * maxFeePerGas`, so that product — not the expected cost — is what a
 * caller is really agreeing to. Whether that prefund is taken from the account
 * or, when a paymaster is set, from the paymaster's deposit, it is the size of
 * the authorization this bounds. A hostile or broken endpoint that inflates
 * any factor of it runs into this before a factor ever signs.
 */
export class UserOpCostExceedsCapError extends Error {
  readonly cost: bigint;
  readonly cap: bigint;

  constructor(cost: bigint, cap: bigint) {
    super(`operation authorizes up to ${cost} wei, above the caller's cap of ${cap} wei; refusing to sign.`);
    this.name = "UserOpCostExceedsCapError";
    this.cost = cost;
    this.cap = cap;
  }
}

/**
 * Thrown when `paymasterAndData` is non-empty but too short to carry the
 * `address ‖ uint128 ‖ uint128` header ERC-4337 v0.7 defines.
 *
 * Fail-closed on purpose: the alternative reading — "no parsable limits, so
 * charge nothing for the paymaster" — would under-price the operation exactly
 * when the field is malformed, which is when scrutiny should be highest.
 */
export class MalformedPaymasterFieldError extends Error {
  readonly length: number;

  constructor(length: number) {
    super(
      `paymasterAndData is ${length} bytes: too short for the 52-byte address+gas-limits header, ` +
        "so its cost cannot be bounded.",
    );
    this.name = "MalformedPaymasterFieldError";
    this.length = length;
  }
}
