import { bytesToHex, encodeAbiParameters, hexToBytes, size, type Address, type Hex } from "viem";
import { privateKeyToAddress, sign } from "viem/accounts";
import { VERIFIER_SECP256K1 } from "../core/types.js";
import { InvalidDigestLengthError } from "../errors.js";
import type { Signer } from "./signer.js";

/**
 * Raw secp256k1 signer for factor slots of `VERIFIER_SECP256K1` (test/dev
 * only — a Secure-Enclave or hardware-wallet-backed signer implements the
 * same `Signer` interface outside this repo). `keyData()` is `abi.encode(address)`
 * and `sign()` produces the 65-byte `r || s || v` wire signature
 * `SignatureVerify._verifySecp256k1` expects, matching `viem/accounts`' own
 * low-s, `v ∈ {27, 28}` normalization.
 */
export class LocalSecp256k1Signer implements Signer {
  readonly verifierType = VERIFIER_SECP256K1;
  readonly address: Address;
  private readonly privateKey: Hex;

  constructor(privateKey: Hex) {
    this.privateKey = privateKey;
    this.address = privateKeyToAddress(privateKey);
  }

  keyData(): Hex {
    return encodeAbiParameters([{ type: "address" }], [this.address]);
  }

  async sign(digest: Hex): Promise<Hex> {
    if (size(digest) !== 32) {
      throw new InvalidDigestLengthError();
    }
    return sign({ hash: bytesToHex(hexToBytes(digest)), privateKey: this.privateKey, to: "hex" });
  }
}
