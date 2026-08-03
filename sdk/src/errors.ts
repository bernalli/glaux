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
 * match a real `implementation.codehash`, so a blob signed against it would
 * be permanently unusable — and, because a birth blob cannot be revoked or
 * resigned, that failure must happen here, not after the birth key is gone.
 */
export class ImplementationNotDeployedError extends Error {
  constructor(implementation: Address) {
    super(
      `no code at implementation address ${implementation} on the given chain; deploy it before building a birth blob.`,
    );
    this.name = "ImplementationNotDeployedError";
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
 * be treated as an empty EOA, because the one-shot birth key is already gone
 * by the time an erroneous preflight can be discovered.
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
