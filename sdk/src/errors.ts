/**
 * Thrown when a caller supplies `validUntil === 0` to a user-operation digest or
 * signature encoder.
 *
 * The ERC-4337 EntryPoint packs `validUntil` into the returned `validationData`
 * and reads a packed value of `0` as "no expiry" rather than as a timestamp.
 * `GlauxAccount.validateUserOp` already refuses to validate a user operation whose
 * signed `validUntil` is `0` (`decoded && validUntil != 0 && ...`), so a client
 * that built such a signature anyway would only discover it is unusable after a
 * round trip through a bundler. Failing at build time is strictly earlier.
 *
 * This is deliberately scoped to the user-operation path: on the direct
 * `executeWithSigs`/`isValidSignature` paths, `validUntil === 0` is an ordinary
 * (already-expired) deadline like any other timestamp in the past, not a
 * forbidden value — see the `@dev` notes on those functions in
 * `src/GlauxAccount.sol`.
 */
export class OperationExpiredError extends Error {
  constructor() {
    super(
      "validUntil must not be 0: the ERC-4337 EntryPoint reads a packed 0 as " +
        '"no expiry", and GlauxAccount refuses to validate a user operation ' +
        "signed with it.",
    );
    this.name = "OperationExpiredError";
  }
}
