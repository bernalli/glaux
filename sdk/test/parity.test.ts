import { expect, it } from "vitest";
import type { Address, Hex } from "viem";
import { eip191v0 } from "../src/core/digests.js";
import fixtures from "../../test/fixtures/sdk_parity.json" with { type: "json" };

it("fixture sabotage is detectable", () => {
  const d = fixtures.eip191Sample;
  expect(eip191v0(d.validator as Address, d.structHash as Hex)).toBe(d.digest);
  const flipped = (d.structHash.slice(0, 65) +
    (d.structHash[65] === "0" ? "1" : "0")) as Hex;
  expect(eip191v0(d.validator as Address, flipped)).not.toBe(d.digest);
});
