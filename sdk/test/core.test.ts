import { type Address, type Hex } from "viem";
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
import { buildInitDigest } from "../src/birth/blob.js";
import { OperationExpiredError } from "../src/errors.js";
import fixtures from "../../test/fixtures/sdk_parity.json" with { type: "json" };

// `noUncheckedIndexedAccess` treats a JSON-imported array's elements as possibly
// `undefined`; the fixture's `sigs` tuple always has exactly two, so this asserts
// that invariant with a message instead of scattering non-null assertions.
function at<T>(arr: readonly T[], index: number): T {
  const value = arr[index];
  expect(value, `fixture array missing index ${index}`).toBeDefined();
  return value as T;
}

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

it("exports buildInitDigest as the existing initDigest implementation", () => {
  const d = fixtures.initDigest;
  expect(
    buildInitDigest(
      d.router as Address,
      d.implementation as Address,
      d.expectedCodeHash as Hex,
      d.initData as Hex,
    ),
  ).toBe(initDigest(d.router as Address, d.implementation as Address, d.expectedCodeHash as Hex, d.initData as Hex));
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

it("execDigest throws OperationExpiredError when validUntil is 0", () => {
  const d = fixtures.execDigest;
  const calls: Call[] = [
    { to: d.call.to as Address, value: BigInt(d.call.value), data: d.call.data as Hex },
  ];
  expect(() => execDigest(d.account as Address, BigInt(d.chainId), BigInt(d.nonce), calls, 0)).toThrow(
    OperationExpiredError,
  );
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

it("msgDigest throws OperationExpiredError when validUntil is 0", () => {
  const d = fixtures.msgDigest;
  expect(() => msgDigest(d.account as Address, BigInt(d.chainId), d.hash as Hex, 0)).toThrow(
    OperationExpiredError,
  );
});

it("encodeInitData reproduces the fixture initData byte-for-byte", () => {
  // These inputs are pinned independently from the expected fixture output. They
  // are the concrete `_slots()` values and generated possession proofs in
  // `test/GlauxFixture.sol`/`test/SdkParity.t.sol`.
  const slots: [FactorSlot, FactorSlot, FactorSlot] = [
    {
      verifierType: 1,
      data: "0x000000000000000000000000dd8741eebf53b33f28557dcdbc2b702bb4611f50",
    },
    {
      verifierType: 2,
      data: "0xc9b91be23306ebbd29f0f1718a1db88a151200eb10c6aad04aa24f8006704de60accddfa8e09bddc03677b1f83a1d4aced4155d44ca7c1fd5226b8d312b7de6f",
    },
    {
      verifierType: 1,
      data: "0x000000000000000000000000fb510fa45fc47af191c724938527320c3b5f7184",
    },
  ];
  const proofs: [Hex, Hex, Hex] = [
    "0x6da0e0bd66d2f2e57d450f73004ee5f0551e39d41cfcfd9a69db5caccaf8eee24594ea1c77405d24b021a382d542c5cdab782eea39b67a1a1b78b8cb7226c7e91c",
    "0xa5d11ce5586c7dfa540f6c4dd59c2fc67d6e2957a668b01e00b04d595e0f9c55394bdd96b49af6d4c89f3e994bc4d1e2ab7b10027c65e537be9accd4626ce897",
    "0x834187a2ced42127a630bb59474853eddae8d0247b2a6be9979c78b26b2e641946c602431805849f5e8b3c122831069a2a115c4960f0472fdc4512564f340c091b",
  ];
  expect(
    encodeInitData(slots, proofs),
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
