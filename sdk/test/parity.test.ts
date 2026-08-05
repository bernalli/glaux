import { describe, expect, it } from "vitest";
import { getAddress, keccak256, toHex, type Address, type Hex } from "viem";
import { execDigest, eip191v0, initDigest, msgDigest, registrationDigest, userOpDigest } from "../src/core/digests.js";
import { encodeSlotSig, encodeUserOpSignature } from "../src/core/encoding.js";
import { assertRecoversTo, craftRootlessAuthorization } from "../src/birth/blob.js";
import type { Call, SlotSig } from "../src/core/types.js";
import fixtures from "../../test/fixtures/sdk_parity.json" with { type: "json" };

/** Flips the last hex nibble of a `0x`-prefixed hex string, for sabotage checks. */
function flip(hex: string): Hex {
  const body = hex.slice(2);
  const lastIndex = body.length - 1;
  const flippedChar = body[lastIndex] === "0" ? "1" : "0";
  return `0x${body.slice(0, lastIndex)}${flippedChar}` as Hex;
}

it("fixture sabotage is detectable", () => {
  const d = fixtures.eip191Sample;
  expect(eip191v0(d.validator as Address, d.structHash as Hex)).toBe(d.digest);
  const flipped = (d.structHash.slice(0, 65) +
    (d.structHash[65] === "0" ? "1" : "0")) as Hex;
  expect(eip191v0(d.validator as Address, flipped)).not.toBe(d.digest);
});

it("registrationDigest fixture sabotage is detectable", () => {
  const d = fixtures.registrationDigest;
  expect(registrationDigest(d.index, d.verifierType as 1 | 2, d.data as Hex)).toBe(d.digest);
  expect(registrationDigest(d.index, d.verifierType as 1 | 2, flip(d.data))).not.toBe(d.digest);
});

it("initDigest fixture sabotage is detectable", () => {
  const d = fixtures.initDigest;
  const args = [d.router as Address, d.implementation as Address, d.expectedCodeHash as Hex] as const;
  expect(initDigest(...args, d.initData as Hex)).toBe(d.digest);
  expect(initDigest(...args, flip(d.initData))).not.toBe(d.digest);
});

it("execDigest fixture sabotage is detectable", () => {
  const d = fixtures.execDigest;
  const args = [d.account as Address, BigInt(d.chainId), BigInt(d.nonce)] as const;
  const call = { to: d.call.to as Address, value: BigInt(d.call.value), data: d.call.data as Hex };
  expect(execDigest(...args, [call], d.validUntil)).toBe(d.digest);
  const sabotagedCall: Call = { ...call, data: flip(d.call.data) };
  expect(execDigest(...args, [sabotagedCall], d.validUntil)).not.toBe(d.digest);
});

it("userOpDigest fixture sabotage is detectable", () => {
  const d = fixtures.userOpDigest;
  expect(userOpDigest(d.account as Address, d.userOpHash as Hex, d.validUntil)).toBe(d.digest);
  expect(userOpDigest(d.account as Address, flip(d.userOpHash), d.validUntil)).not.toBe(d.digest);
});

it("msgDigest fixture sabotage is detectable", () => {
  const d = fixtures.msgDigest;
  expect(msgDigest(d.account as Address, BigInt(d.chainId), d.hash as Hex, d.validUntil)).toBe(
    d.digest,
  );
  expect(
    msgDigest(d.account as Address, BigInt(d.chainId), flip(d.hash), d.validUntil),
  ).not.toBe(d.digest);
});

it("encodeSlotSig fixture sabotage is detectable", () => {
  const d = fixtures.encodedSlotSigP256;
  expect(encodeSlotSig({ slotIndex: d.slotIndex, signature: { r: d.r as Hex, s: d.s as Hex } })).toBe(
    d.encoded,
  );
  expect(
    encodeSlotSig({ slotIndex: d.slotIndex, signature: { r: d.r as Hex, s: flip(d.s) } }),
  ).not.toBe(d.encoded);
});

it("encodeUserOpSignature fixture sabotage is detectable", () => {
  const d = fixtures.encodedUserOpSignature;
  const first = d.sigs[0];
  const second = d.sigs[1];
  expect(first, "fixture sigs must have exactly two entries").toBeDefined();
  expect(second, "fixture sigs must have exactly two entries").toBeDefined();
  const sigs: [SlotSig, SlotSig] = [
    { slotIndex: first!.slotIndex, signature: first!.signature as Hex },
    { slotIndex: second!.slotIndex, signature: second!.signature as Hex },
  ];
  expect(encodeUserOpSignature(d.validUntil, sigs)).toBe(d.encoded);
  const sabotagedSigs: [SlotSig, SlotSig] = [
    { slotIndex: first!.slotIndex, signature: flip(first!.signature) },
    sigs[1],
  ];
  expect(encodeUserOpSignature(d.validUntil, sabotagedSigs)).not.toBe(d.encoded);
});

describe("rootless birth derivation", () => {
  /**
   * The contract-emitted vector is the referee: `test/SdkParity.t.sol` crafts
   * it with the router's own derivation and then BIRTHS an account with it, so
   * a vector that reached this file is one the router accepted. Reproducing it
   * here byte for byte is what proves the two implementations agree — a client
   * whose derivation drifted would compute an address the chain never confirms,
   * and would discover it only after funding one.
   */
  it("reproduces the contract-emitted account, salt and s", () => {
    const crafted = craftRootlessAuthorization(
      fixtures.initDigest.digest as Hex,
      fixtures.initDigest.authMsgHash as Hex,
    );

    expect(crafted.account).toBe(getAddress(fixtures.initDigest.account as Hex));
    expect(crafted.salt).toBe(fixtures.initDigest.salt);
    expect(crafted.s).toBe(fixtures.initDigest.s);
    expect(crafted.yParity).toBe(0);
  });

  it("re-derives the same authorization the router will accept, and refuses a tampered one", () => {
    const { salt, s, account } = craftRootlessAuthorization(
      fixtures.initDigest.digest as Hex,
      fixtures.initDigest.authMsgHash as Hex,
    );
    const digest = fixtures.initDigest.digest as Hex;
    const authMsgHash = fixtures.initDigest.authMsgHash as Hex;

    expect(assertRecoversTo(digest, salt, s, account, authMsgHash)).toBe(true);
    // A different salt recovers elsewhere; an untagged `s` is refused outright.
    expect(assertRecoversTo(digest, keccak256(salt), s, account, authMsgHash)).toBe(false);
    const untagged = toHex(BigInt(s) & ((1n << 152n) - 1n), { size: 32 });
    expect(assertRecoversTo(digest, salt, untagged, account, authMsgHash)).toBe(false);
  });
});
