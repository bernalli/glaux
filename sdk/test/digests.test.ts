import { describe, it, expect } from "vitest";
import { keccak256, toBytes, concat, pad, stringToBytes } from "viem";
import { DOMAINS, eip191v0 } from "../src/core/digests.js";

it("domains match keccak of the literal tags", () => {
  expect(DOMAINS.EXEC).toBe(keccak256(stringToBytes("GLAUX_EXEC_V1")));
});
it("eip191v0 is keccak(0x19 || 0x00 || validator || structHash)", () => {
  const validator = "0x1111111111111111111111111111111111111111" as const;
  const structHash = keccak256(stringToBytes("x"));
  const expected = keccak256(concat(["0x1900", validator, structHash]));
  expect(eip191v0(validator, structHash)).toBe(expected);
});
