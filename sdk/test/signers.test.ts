import { describe, expect, it } from "vitest";
import {
  bytesToBigInt,
  bytesToHex,
  decodeAbiParameters,
  hexToBytes,
  keccak256,
  numberToHex,
  recoverAddress,
  size,
  stringToBytes,
  type Hex,
} from "viem";
import { p256 } from "@noble/curves/nist.js";
import { registrationDigest } from "../src/core/digests.js";
import { VERIFIER_P256, VERIFIER_SECP256K1 } from "../src/core/types.js";
import {
  InvalidDigestLengthError,
  InvalidP256PrivateKeyError,
  InvalidSlotIndexError,
} from "../src/errors.js";
import { LocalSecp256k1Signer } from "../src/signers/secp256k1.js";
import { LocalP256Signer } from "../src/signers/p256.js";
import { registrationProof } from "../src/signers/signer.js";
import fixtures from "../../test/fixtures/sdk_parity.json" with { type: "json" };

/**
 * Anvil's well-known default account #0. Its private key is published in
 * every Foundry/Anvil installation and is already the implicit funding key
 * for `script/Deploy.s.sol` broadcasts documented in `docs/deployments.md`
 * — never a key that could hold real value.
 */
const ANVIL_PK = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" as const;
const ANVIL_ADDRESS = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266" as const;

/**
 * `P256_PK` from `test/P256Fixture.sol` (`DEVICE_P256_PK` in `GlauxFixture.sol`)
 * — the same private key `test/SdkParity.t.sol` used to produce this repo's
 * `encodedSlotSigP256` fixture vector below.
 */
const P256_PK = "0x7459e13afd9158a379ee75ca9e80a328916dba1473c863f800f51ee5f46eb3ab" as const;

const UINT256_PAIR = [{ type: "uint256" }, { type: "uint256" }] as const;

/** Curve order `n` for P-256/secp256r1. */
const P256_ORDER = p256.Point.Fn.ORDER;

/** Curve order `n` for secp256k1. */
const SECP256K1_ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

/**
 * Reconstructs the uncompressed SEC1 public key (`0x04 || qx || qy`) `@noble/curves`
 * expects, straight from the wire bytes `keyData()` returns — independent of
 * whatever internal representation `LocalP256Signer` used to produce them.
 */
function uncompressedPublicKeyFromKeyData(keyData: Hex): Uint8Array {
  const raw = hexToBytes(keyData);
  const uncompressed = new Uint8Array(65);
  uncompressed[0] = 0x04;
  uncompressed.set(raw, 1);
  return uncompressed;
}

function secp256k1SignatureParts(signature: Hex): { s: bigint; v: number } {
  const bytes = hexToBytes(signature);
  expect(bytes).toHaveLength(65);
  return {
    s: bytesToBigInt(bytes.slice(32, 64)),
    v: bytes[64]!,
  };
}

describe("LocalSecp256k1Signer", () => {
  it("has verifierType 1 and keyData = abi.encode(address)", () => {
    const signer = new LocalSecp256k1Signer(ANVIL_PK);
    expect(signer.verifierType).toBe(VERIFIER_SECP256K1);
    const [decodedAddress] = decodeAbiParameters([{ type: "address" }], signer.keyData());
    expect(decodedAddress).toBe(ANVIL_ADDRESS);
  });

  it("produces a 65-byte r||s||v signature that recovers to the signer's own address", async () => {
    const signer = new LocalSecp256k1Signer(ANVIL_PK);
    const digest = registrationDigest(0, VERIFIER_SECP256K1, signer.keyData());
    const sig = await signer.sign(digest);

    expect(sig.length).toBe(2 + 65 * 2);
    const { s, v } = secp256k1SignatureParts(sig);
    expect([0x1b, 0x1c]).toContain(v);
    expect(s <= SECP256K1_ORDER / 2n).toBe(true);

    const recovered = await recoverAddress({ hash: digest, signature: sig });
    expect(recovered).toBe(ANVIL_ADDRESS);
  });

  it("makes the recovery-compatible v=0 corruption visibly contract-invalid", async () => {
    const signer = new LocalSecp256k1Signer(ANVIL_PK);
    const digest = registrationDigest(0, VERIFIER_SECP256K1, signer.keyData());
    const corrupted = hexToBytes(await signer.sign(digest));
    corrupted[64] = 0;
    const corruptedSignature = bytesToHex(corrupted);

    // viem can recover this alternate v convention, but Solidity accepts only 27 or 28.
    expect(await recoverAddress({ hash: digest, signature: corruptedSignature })).toBe(ANVIL_ADDRESS);
    expect(secp256k1SignatureParts(corruptedSignature).v).toBe(0);
    expect([0x1b, 0x1c]).not.toContain(secp256k1SignatureParts(corruptedSignature).v);
  });

  it("makes the recovery-compatible high-s corruption visibly contract-invalid", async () => {
    const signer = new LocalSecp256k1Signer(ANVIL_PK);
    const digest = registrationDigest(0, VERIFIER_SECP256K1, signer.keyData());
    const signature = await signer.sign(digest);
    const { s, v } = secp256k1SignatureParts(signature);
    const corrupted = hexToBytes(signature);
    corrupted.set(hexToBytes(numberToHex(SECP256K1_ORDER - s, { size: 32 })), 32);
    corrupted[64] = v === 0x1b ? 0x1c : 0x1b;
    const corruptedSignature = bytesToHex(corrupted);

    // Flipping v preserves recovery, while Solidity rejects the high-s representation.
    expect(await recoverAddress({ hash: digest, signature: corruptedSignature })).toBe(ANVIL_ADDRESS);
    expect(secp256k1SignatureParts(corruptedSignature).s > SECP256K1_ORDER / 2n).toBe(true);
  });

  it("rejects digests that cannot be passed to Solidity as bytes32", async () => {
    const signer = new LocalSecp256k1Signer(ANVIL_PK);
    const digest = registrationDigest(0, VERIFIER_SECP256K1, signer.keyData());

    await expect(signer.sign(digest.slice(0, -2) as Hex)).rejects.toThrow(InvalidDigestLengthError);
    await expect(signer.sign(`${digest}00` as Hex)).rejects.toThrow(InvalidDigestLengthError);
  });

  it("accepts an odd-nibble digest that viem decodes to 32 bytes", async () => {
    const signer = new LocalSecp256k1Signer(ANVIL_PK);
    const digest = `0x${"1".repeat(63)}` as Hex;

    expect(size(digest)).toBe(32);
    expect(hexToBytes(digest)).toHaveLength(32);
    await expect(signer.sign(digest)).resolves.toMatch(/^0x[0-9a-f]{130}$/);
  });

  it("registrationProof signs registrationDigest and recovers to the signer's address", async () => {
    const signer = new LocalSecp256k1Signer(ANVIL_PK);
    const proof = await registrationProof(signer, 2);
    const digest = registrationDigest(2, VERIFIER_SECP256K1, signer.keyData());

    const recovered = await recoverAddress({ hash: digest, signature: proof });
    expect(recovered).toBe(ANVIL_ADDRESS);
  });

  it("rejects registration proofs for slots the contract does not have", async () => {
    const signer = new LocalSecp256k1Signer(ANVIL_PK);

    await expect(registrationProof(signer, 3)).rejects.toThrow(InvalidSlotIndexError);
  });
});

describe("LocalP256Signer", () => {
  it("has verifierType 2 and a keyData shaped like the fixture's abi.encode(qx, qy)", () => {
    const signer = new LocalP256Signer(P256_PK);
    expect(signer.verifierType).toBe(VERIFIER_P256);

    const d = fixtures.encodedSlotSigP256;
    const keyData = signer.keyData();
    // Same private key as `test/P256Fixture.sol`/`SdkParity.t.sol`: the
    // derived public key must equal the fixture's, not merely have the right
    // shape.
    expect(keyData.length).toBe(2 + 64 * 2);
    const [qx, qy] = decodeAbiParameters(UINT256_PAIR, keyData);
    expect(qx).toBe(BigInt(d.qx));
    expect(qy).toBe(BigInt(d.qy));
  });

  it("rejects malformed private-key lengths at construction", () => {
    expect(() => new LocalP256Signer(P256_PK.slice(0, -2) as Hex)).toThrow(InvalidP256PrivateKeyError);
  });

  it("accepts an odd-nibble private key that viem decodes to 32 bytes", () => {
    const privateKey = `0x${"1".repeat(63)}` as Hex;

    expect(size(privateKey)).toBe(32);
    expect(hexToBytes(privateKey)).toHaveLength(32);
    expect(() => new LocalP256Signer(privateKey)).not.toThrow();
  });

  it("sign() reproduces the sdk_parity fixture's proven-accepted P-256 signature byte-for-byte", async () => {
    const signer = new LocalP256Signer(P256_PK);
    const d = fixtures.encodedSlotSigP256;

    const sig = await signer.sign(d.digest as Hex);

    expect(sig).toBe(d.encoded);
  });

  it("produces a signature that @noble/curves independently verifies against the signer's own declared public key", async () => {
    const signer = new LocalP256Signer(P256_PK);
    const digest = keccak256(stringToBytes("glaux-sdk-p256-independent-verify"));

    const sig = await signer.sign(digest);
    const [r, s] = decodeAbiParameters(UINT256_PAIR, sig);

    const compactSig = new Uint8Array(64);
    compactSig.set(hexToBytes(numberToHex(r, { size: 32 })), 0);
    compactSig.set(hexToBytes(numberToHex(s, { size: 32 })), 32);
    const publicKey = uncompressedPublicKeyFromKeyData(signer.keyData());

    expect(p256.verify(compactSig, hexToBytes(digest), publicKey, { lowS: true, prehash: false })).toBe(
      true,
    );
  });

  it("always emits s in the low half of the curve order (canonical, non-malleable)", async () => {
    const signer = new LocalP256Signer(P256_PK);
    const digest = keccak256(stringToBytes("glaux-sdk-p256-lows-check"));

    const sig = await signer.sign(digest);
    const [, s] = decodeAbiParameters(UINT256_PAIR, sig);

    expect(s <= P256_ORDER / 2n).toBe(true);
  });

  it("rejects digests that cannot be passed to Solidity as bytes32", async () => {
    const signer = new LocalP256Signer(P256_PK);
    const digest = fixtures.encodedSlotSigP256.digest as Hex;

    await expect(signer.sign(digest.slice(0, -2) as Hex)).rejects.toThrow(InvalidDigestLengthError);
    await expect(signer.sign(`${digest}00` as Hex)).rejects.toThrow(InvalidDigestLengthError);
  });

  it("accepts an odd-nibble digest that viem decodes to 32 bytes", async () => {
    const signer = new LocalP256Signer(P256_PK);
    const digest = `0x${"1".repeat(63)}` as Hex;

    expect(size(digest)).toBe(32);
    expect(hexToBytes(digest)).toHaveLength(32);
    await expect(signer.sign(digest)).resolves.toMatch(/^0x[0-9a-f]{128}$/);
  });

  it("normalizes a signature whose raw (un-normalized) s falls in the high half of the curve order", async () => {
    // Chosen by brute-force search over labelled digests for this specific
    // key: `p256.sign(..., { lowS: false })` on this digest lands in the high
    // half of the curve order, so it actually exercises the normalization
    // branch instead of merely landing low-s by chance.
    const digest = keccak256(stringToBytes("glaux-sdk-p256-highs-probe-0"));
    const digestBytes = hexToBytes(digest);
    const privateKeyBytes = hexToBytes(P256_PK);

    const rawSig = p256.sign(digestBytes, privateKeyBytes, { lowS: false, prehash: false });
    const rawR = bytesToBigInt(rawSig.slice(0, 32));
    const rawS = bytesToBigInt(rawSig.slice(32, 64));
    expect(rawS > P256_ORDER / 2n, "test vector must exercise the high-s branch").toBe(true);

    const signer = new LocalP256Signer(P256_PK);
    const sig = await signer.sign(digest);
    const [r, s] = decodeAbiParameters(UINT256_PAIR, sig);

    // A high-s signature must never escape the signer: it must emit the
    // canonical low-s complement `n - rawS`, over the same `r`, not the raw
    // high-s value.
    expect(r).toBe(rawR);
    expect(s).toBe(P256_ORDER - rawS);
    expect(s <= P256_ORDER / 2n).toBe(true);
  });
});
