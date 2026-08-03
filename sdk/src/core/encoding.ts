import { encodeAbiParameters, hexToBigInt, type Hex } from "viem";
import type { FactorSlot, SlotSig } from "./types.js";
import { OperationExpiredError } from "../errors.js";

const FACTOR_SLOT_TUPLE_COMPONENTS = [
  { name: "verifierType", type: "uint8" },
  { name: "data", type: "bytes" },
] as const;

/**
 * ABI-encodes the `(FactorSlot[3], bytes[3])` blob `GlauxAccount.initializeAccount`
 * decodes as `initData`. Matches `scripts/birth.py:build_init_data`, which
 * `abi.encode`s the same shape as `("(uint8,bytes)[3]", "bytes[3]")`.
 */
export function encodeInitData(
  slots: readonly [FactorSlot, FactorSlot, FactorSlot],
  proofs: readonly [Hex, Hex, Hex],
): Hex {
  return encodeAbiParameters(
    [
      { type: "tuple[3]", components: FACTOR_SLOT_TUPLE_COMPONENTS },
      { type: "bytes[3]" },
    ],
    [slots, proofs],
  );
}

/**
 * Encodes a `SlotSig`'s `signature` field into the wire bytes
 * `src/GlauxStorage.sol`'s `SlotSig.signature` carries:
 * - `Hex` input (secp256k1, type 1): passed through unchanged — a raw
 *   65-byte `r || s || v` signature is already the wire format.
 * - `{ r, s }` input (P-256, type 2): `abi.encode(uint256 r, uint256 s)` (64 bytes).
 */
export function encodeSlotSig(sig: SlotSig): Hex {
  if (typeof sig.signature === "string") {
    return sig.signature;
  }
  return encodeAbiParameters(
    [{ type: "uint256" }, { type: "uint256" }],
    [hexToBigInt(sig.signature.r), hexToBigInt(sig.signature.s)],
  );
}

/**
 * ABI-encodes the `(uint48 validUntil, SlotSig[2] sigs)` blob shared by the
 * ERC-4337 (`GlauxAccount.validateUserOp`/`decodeSlotSigs`) and ERC-1271
 * (`GlauxAccount.isValidSignature`) paths — "their blobs have the same
 * shape" (`GlauxAccount`'s `MAX_SIGNATURE_BLOB_LENGTH` comment).
 *
 * @throws {OperationExpiredError} if `validUntil === 0` — see the error's
 * documentation for why every Glaux operation path rejects zero at build time.
 */
export function encodeUserOpSignature(
  validUntil: number,
  sigs: readonly [SlotSig, SlotSig],
): Hex {
  if (validUntil === 0) {
    throw new OperationExpiredError();
  }
  const [first, second] = sigs;
  return encodeAbiParameters(
    [
      { type: "uint48" },
      {
        type: "tuple[2]",
        components: [
          { name: "slotIndex", type: "uint8" },
          { name: "signature", type: "bytes" },
        ],
      },
    ],
    [
      validUntil,
      [
        { slotIndex: first.slotIndex, signature: encodeSlotSig(first) },
        { slotIndex: second.slotIndex, signature: encodeSlotSig(second) },
      ],
    ],
  );
}
