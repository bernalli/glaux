import { decodeAbiParameters, type Address, type Hex } from "viem";
import { expect, it } from "vitest";
import {
  execDigest,
  initDigest,
  msgDigest,
  registrationDigest,
  userOpDigest,
} from "../src/core/digests.js";
import { encodeInitData, encodeSlotSig, encodeUserOpSignature } from "../src/core/encoding.js";
import type { Call, FactorSlot, SlotSig } from "../src/core/types.js";
import { OperationExpiredError } from "../src/errors.js";
import fixtures from "../../test/fixtures/sdk_parity.json" with { type: "json" };

// The FactorSlot[3]/bytes[3] ABI shape `initData` is encoded with. Declared once so
// the round-trip test (decode the fixture, then re-encode it) uses the exact same
// wire type the contract does, per GlauxAccount.initializeAccount's
// `abi.decode(initData, (FactorSlot[3], bytes[3]))`.
// `noUncheckedIndexedAccess` treats a JSON-imported array's elements as possibly
// `undefined`; the fixture's `sigs` tuple always has exactly two, so this asserts
// that invariant with a message instead of scattering non-null assertions.
function at<T>(arr: readonly T[], index: number): T {
  const value = arr[index];
  if (value === undefined) {
    throw new Error(`fixture array missing index ${index}`);
  }
  return value;
}

const INIT_DATA_ABI = [
  {
    type: "tuple[3]",
    components: [
      { name: "verifierType", type: "uint8" },
      { name: "data", type: "bytes" },
    ],
  },
  { type: "bytes[3]" },
] as const;

it("registrationDigest matches the fixture vector", () => {
  const d = fixtures.registrationDigest;
  expect(registrationDigest(d.index, d.verifierType as 1 | 2, d.data as Hex)).toBe(d.digest);
});

it("initDigest matches the fixture vector", () => {
  const d = fixtures.initDigest;
  expect(
    initDigest(
      d.router as Address,
      d.implementation as Address,
      d.expectedCodeHash as Hex,
      d.initData as Hex,
    ),
  ).toBe(d.digest);
});

it("execDigest matches the fixture vector", () => {
  const d = fixtures.execDigest;
  const calls: Call[] = [
    { to: d.call.to as Address, value: BigInt(d.call.value), data: d.call.data as Hex },
  ];
  expect(
    execDigest(d.account as Address, BigInt(d.chainId), BigInt(d.nonce), calls, d.validUntil),
  ).toBe(d.digest);
});

it("userOpDigest matches the fixture vector", () => {
  const d = fixtures.userOpDigest;
  expect(userOpDigest(d.account as Address, d.userOpHash as Hex, d.validUntil)).toBe(d.digest);
});

it("userOpDigest throws OperationExpiredError when validUntil is 0", () => {
  const d = fixtures.userOpDigest;
  expect(() => userOpDigest(d.account as Address, d.userOpHash as Hex, 0)).toThrow(
    OperationExpiredError,
  );
});

it("msgDigest matches the fixture vector", () => {
  const d = fixtures.msgDigest;
  expect(msgDigest(d.account as Address, BigInt(d.chainId), d.hash as Hex, d.validUntil)).toBe(
    d.digest,
  );
});

it("encodeInitData reproduces the fixture initData byte-for-byte", () => {
  // Decoded via viem's own decoder (the inverse operation, not the encoder under
  // test) so this is a genuine round-trip check against the fixture bytes, not a
  // value recomputed with the same helper the implementation uses.
  const [slots, proofs] = decodeAbiParameters(
    INIT_DATA_ABI,
    fixtures.initDigest.initData as Hex,
  );
  expect(
    encodeInitData(
      slots as unknown as readonly [FactorSlot, FactorSlot, FactorSlot],
      proofs as unknown as readonly [Hex, Hex, Hex],
    ),
  ).toBe(fixtures.initDigest.initData);
});

it("encodeSlotSig reproduces the fixture P-256 signature encoding", () => {
  const d = fixtures.encodedSlotSigP256;
  expect(encodeSlotSig({ slotIndex: d.slotIndex, signature: { r: d.r as Hex, s: d.s as Hex } })).toBe(
    d.encoded,
  );
});

it("encodeUserOpSignature reproduces the fixture user-operation signature blob", () => {
  const d = fixtures.encodedUserOpSignature;
  const p256 = fixtures.encodedSlotSigP256;
  const rawSig0 = at(d.sigs, 0);
  const rawSig1 = at(d.sigs, 1);
  const sigs: [SlotSig, SlotSig] = [
    { slotIndex: rawSig0.slotIndex, signature: rawSig0.signature as Hex },
    { slotIndex: rawSig1.slotIndex, signature: { r: p256.r as Hex, s: p256.s as Hex } },
  ];
  expect(encodeUserOpSignature(d.validUntil, sigs)).toBe(d.encoded);
});

it("encodeUserOpSignature throws OperationExpiredError when validUntil is 0", () => {
  const d = fixtures.encodedUserOpSignature;
  const rawSig0 = at(d.sigs, 0);
  const rawSig1 = at(d.sigs, 1);
  const sigs: [SlotSig, SlotSig] = [
    { slotIndex: rawSig0.slotIndex, signature: rawSig0.signature as Hex },
    { slotIndex: rawSig1.slotIndex, signature: rawSig1.signature as Hex },
  ];
  expect(() => encodeUserOpSignature(0, sigs)).toThrow(OperationExpiredError);
});
