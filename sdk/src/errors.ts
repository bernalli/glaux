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
