import type { Hex } from "viem";
import { registrationDigest } from "../core/digests.js";
import type { VerifierType } from "../core/types.js";

/**
 * Pluggable signing interface every Glaux factor key implements: the local
 * `LocalSecp256k1Signer`/`LocalP256Signer` in this module for tests and
 * development, or a Secure-Enclave-backed (or other hardware) signer outside
 * this repo that speaks the same shape.
 *
 * `sign` returns the already wire-encoded signature `SignatureVerify.sol`
 * expects for the corresponding `verifierType`:
 * - `VERIFIER_SECP256K1` (1): the raw 65-byte `r || s || v`.
 * - `VERIFIER_P256` (2): `abi.encode(uint256 r, uint256 s)`, with `s`
 *   normalized to the low half of the curve order — a high-s value must
 *   never escape the signer.
 */
export interface Signer {
  readonly verifierType: VerifierType;
  keyData(): Hex;
  sign(digest: Hex): Promise<Hex>;
}

/**
 * Signs the possession proof `GlauxAccount._requirePossession` verifies
 * before a candidate key can be installed into factor slot `index`. See
 * `registrationDigest` (`../core/digests.js`) for the exact digest layout:
 * deliberately not parameterized on an account/validator, since the proof
 * must be producible before the account exists.
 */
export async function registrationProof(signer: Signer, index: number): Promise<Hex> {
  const digest = registrationDigest(index, signer.verifierType, signer.keyData());
  return signer.sign(digest);
}
