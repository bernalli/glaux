import type { Address, Hex } from "viem";

/** `src/GlauxStorage.sol`: `VERIFIER_SECP256K1`. */
export const VERIFIER_SECP256K1 = 1;
/** `src/GlauxStorage.sol`: `VERIFIER_P256`. */
export const VERIFIER_P256 = 2;

export type VerifierType = typeof VERIFIER_SECP256K1 | typeof VERIFIER_P256;

/**
 * Mirrors `struct FactorSlot` in `src/GlauxStorage.sol`: `data` is already the
 * verifier-specific ABI-encoded key material — `abi.encode(address)` for
 * `VERIFIER_SECP256K1`, `abi.encode(uint256 qx, uint256 qy)` for `VERIFIER_P256`.
 */
export interface FactorSlot {
  verifierType: VerifierType;
  data: Hex;
}

/**
 * Mirrors `struct SlotSig` in `src/GlauxStorage.sol`. `signature` accepts
 * whichever shape a verifier produces natively, and `encodeSlotSig` (in
 * `./encoding.ts`) turns it into the wire bytes the contract expects:
 * - `VERIFIER_SECP256K1`: an already-final `Hex` blob — the raw 65-byte
 *   `r || s || v` a secp256k1 signer produces needs no further encoding.
 * - `VERIFIER_P256`: the raw `{ r, s }` pair, which `encodeSlotSig` ABI-encodes
 *   as `abi.encode(uint256 r, uint256 s)` (64 bytes) to match the wire format
 *   `SignatureVerify` expects for a P-256 signature.
 */
export interface SlotSig {
  slotIndex: number;
  signature: Hex | { r: Hex; s: Hex };
}

/** Mirrors `struct Call` in `src/GlauxStorage.sol`. */
export interface Call {
  to: Address;
  value: bigint;
  data: Hex;
}

/**
 * JSON-compatible with the blob `scripts/birth.py:build_birth_blob` prints —
 * same field names, so a blob produced by either side round-trips through the
 * other unchanged.
 */
export interface BirthBlob {
  account: Address;
  router: Address;
  implementation: Address;
  expectedCodeHash: Hex;
  authorization: {
    chainId: number;
    address: Address;
    nonce: number;
    yParity: number;
    r: Hex;
    s: Hex;
  };
  initData: Hex;
  /**
   * The crafting nonce that put `authorization.r` on the curve. There is no
   * birth signature to carry any more: `authorization` IS the proof, and the
   * router rebuilds `r` from this salt and the init digest to check that the
   * tuple recovers to `account`. It travels in the blob only because `r` is
   * not recoverable from the address alone.
   */
  salt: Hex;
}
