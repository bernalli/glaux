import { bytesToBigInt, encodeAbiParameters, hexToBytes, size, type Hex } from "viem";
import { p256 } from "@noble/curves/nist.js";
import { VERIFIER_P256 } from "../core/types.js";
import { InvalidDigestLengthError, InvalidP256PrivateKeyError } from "../errors.js";
import type { Signer } from "./signer.js";

/**
 * Raw-digest P-256 signer for factor slots of `VERIFIER_P256` (test/dev
 * only — a Secure-Enclave-backed signer implements the same `Signer`
 * interface outside this repo, and is the intended production counterpart:
 * this factor is RAW-DIGEST, not a WebAuthn/passkey signer, which signs its
 * own envelope rather than the bare digest `SignatureVerify` verifies).
 *
 * `keyData()` is `abi.encode(uint256 qx, uint256 qy)` and `sign()` produces
 * `abi.encode(uint256 r, uint256 s)` with `s` normalized to the low half of
 * the curve order, matching `SignatureVerify._verifyP256`'s wire format.
 */
export class LocalP256Signer implements Signer {
  readonly verifierType = VERIFIER_P256;
  private readonly privateKeyBytes: Uint8Array;

  constructor(privateKey: Hex) {
    if (size(privateKey) !== 32) {
      throw new InvalidP256PrivateKeyError();
    }
    this.privateKeyBytes = hexToBytes(privateKey);
    const scalar = bytesToBigInt(this.privateKeyBytes);
    if (scalar === 0n || scalar >= p256.Point.Fn.ORDER) {
      throw new InvalidP256PrivateKeyError();
    }
  }

  keyData(): Hex {
    const uncompressed = p256.getPublicKey(this.privateKeyBytes, false);
    const qx = uncompressed.slice(1, 33);
    const qy = uncompressed.slice(33, 65);
    return encodeAbiParameters(
      [{ type: "uint256" }, { type: "uint256" }],
      [bytesToBigInt(qx), bytesToBigInt(qy)],
    );
  }

  /**
   * Signs the raw digest directly, with no additional hashing.
   * `SignatureVerify._verifyP256`/the RIP-7212 & EIP-7951 precompile both
   * take the bare 32-byte digest as the message, so `prehash: false` is
   * mandatory: `@noble/curves` defaults to `prehash: true` (SHA-256 the
   * input first), which would sign a different message than the one the
   * contract verifies. `lowS: true` forces the canonical low-s
   * normalization — a high-s value must never escape this method.
   */
  async sign(digest: Hex): Promise<Hex> {
    if (size(digest) !== 32) {
      throw new InvalidDigestLengthError();
    }
    const signature = p256.sign(hexToBytes(digest), this.privateKeyBytes, {
      lowS: true,
      prehash: false,
    });
    const r = bytesToBigInt(signature.slice(0, 32));
    const s = bytesToBigInt(signature.slice(32, 64));
    return encodeAbiParameters([{ type: "uint256" }, { type: "uint256" }], [r, s]);
  }
}
