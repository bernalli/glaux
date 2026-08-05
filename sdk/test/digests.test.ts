import { expect, it } from "vitest";
import { DOMAINS, eip191v0 } from "../src/core/digests.js";
import {
  CREATE2_DEPLOYER,
  designator,
  ENTRYPOINT,
  IMPL,
  ROUTER,
  SALT,
} from "../src/core/constants.js";

it("matches every canonical Glaux constant", () => {
  expect(ROUTER).toBe("0x3ccF1cc0F702C084B31e691e057d8742ADF35790");
  expect(IMPL).toBe("0x21b5D576AB4188Ee06DD866b6Fd4a23085A73f5d");
  expect(CREATE2_DEPLOYER).toBe("0x4e59b44847b379578588920cA78FbF26c0B4956C");
  expect(ENTRYPOINT).toBe("0x0000000071727De22E5E9d8BAf0edAc6f37da032");
  expect(SALT).toBe("0x10a07e19543308b619cd2e0055b65a52674e2f3c59a92260dcccdeefd4112428");
  expect(DOMAINS).toEqual({
    INIT: "0x99a75e75b771bda1bbbb84f07491566b57f405a8a8b79954153c1cd21f038e72",
    UPDATE: "0x3a8f5d3c2202d1c7097807df56c4011bff39c7a16cee217612b34f8f5be686a4",
    EXEC: "0xb881fd41b360af9f55f495aa34c77f46bf7f602fd62420fb6bf3348f1f67447f",
    USEROP: "0xe7e9b7e6f40477183ea0956b2db5c3da30e727277a997888859335ceffc0bad3",
    REG: "0xc6ac354f53fed9914072133601f691782a6902c504211f2dad8581066535ba39",
    MSG: "0x81b19556e5c48050cf054cad533961c2de5bc0bfcaa4f7cc36e73e4a9344c469",
  });
  expect(designator()).toBe("0xef01003ccf1cc0f702c084b31e691e057d8742adf35790");
});

it("eip191v0 is keccak(0x19 || 0x00 || validator || structHash)", () => {
  const validator = "0x1111111111111111111111111111111111111111" as const;
  const structHash = "0x1111111111111111111111111111111111111111111111111111111111111111" as const;

  expect(eip191v0(validator, structHash)).toBe(
    "0x0908a97d2e46ab7b394cc9d0a4e067e0066cc515ab49aaa300a44f31e16d1994",
  );
});
