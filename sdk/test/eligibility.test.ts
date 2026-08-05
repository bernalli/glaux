import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { keccak256, stringToBytes, toHex, type Address, type Hex, type PublicClient, type TestClient } from "viem";
import { describe, expect, it } from "vitest";
import { ENTRYPOINT, IMPL, ROUTER, designator } from "../src/core/constants.js";
import { checkChain } from "../src/eligibility/verdict.js";
import fixtures from "../../test/fixtures/sdk_parity.json" with { type: "json" };
import { clientsFor, spawnAnvil } from "./helpers/anvil.js";

// Contract-derived P-256 probe vector, emitted by test/SdkParity.t.sol.
const P256_VERIFIER: Address = "0x0000000000000000000000000000000000000100";
const P256_DIGEST = fixtures.p256Probe.digest as Hex;
const P256_R = fixtures.p256Probe.r as Hex;
const P256_S = fixtures.p256Probe.s as Hex;
const P256_QX = fixtures.p256Probe.qx as Hex;
const P256_QY = fixtures.p256Probe.qy as Hex;

/**
 * Deployed bytecode of the vendored daimo `P256Verifier`, read from the forge
 * build artifact (`forge build` must have run before this suite).
 * This is the SAME contract `test/oracle/P256VerifierOracle.sol` etches for
 * the Solidity suite; the SDK etches the identical bytes at the same address
 * over JSON-RPC instead of a forge cheatcode.
 */
function loadP256OracleBytecode(): Hex {
  const here = dirname(fileURLToPath(import.meta.url));
  const artifactPath = join(here, "../../out/P256VerifierOracle.sol/P256VerifierOracle.json");
  const artifact = JSON.parse(readFileSync(artifactPath, "utf8")) as {
    deployedBytecode: { object: string };
  };
  const object = artifact.deployedBytecode.object;
  expect(object.startsWith("0x"), "forge artifact bytecode must be 0x-prefixed").toBe(true);
  return object as Hex;
}

/**
 * Hand-written bytecode for the verifier this task exists to reject: it
 * ignores its calldata entirely and always returns the 32-byte word `1`, so
 * a one-armed probe (only checking that a valid signature verifies) would
 * wrongly call this chain P-256-capable. `PUSH32 1; PUSH1 0; MSTORE; PUSH1
 * 0x20; PUSH1 0; RETURN`.
 */
const ALWAYS_ACCEPT_P256_STUB: Hex =
  "0x7f000000000000000000000000000000000000000000000000000000000000000160005260206000f3";

/** Any non-empty bytecode, standing in for a real deployment at a fixed address. */
const MARKER_CODE: Hex = "0x00";

// Mirrors `GlauxStorage.SLOT`/`IMPL_SLOT` and `scripts/submit_birth.py`'s
// `STORAGE_SLOT`/`IMPL_SLOT`, computed independently of `src/eligibility/*`
// so a derivation bug in that module cannot also hide in this test.
const STORAGE_SLOT = BigInt(keccak256(stringToBytes("glaux.account.v1.storage")));
const IMPL_SLOT: Hex = keccak256(stringToBytes("glaux.account.v1.implementation"));
const NON_ZERO_WORD: Hex = toHex(1n, { size: 32 });
const LONG_32_BYTES: Hex = toHex(65n, { size: 32 });
const SECP256K1_TYPE: Hex = toHex(1n, { size: 32 });
const VALID_SECP256K1_DATA: readonly Hex[] = [
  toHex(0x1234567890abcdef1234567890abcdef12345678n, { size: 32 }),
  toHex(0x234567890abcdef1234567890abcdef123456789n, { size: 32 }),
  toHex(0x34567890abcdef1234567890abcdef123456789an, { size: 32 }),
];

const CANDIDATE_ACCOUNT: Address = "0xa0Ee7A142d267C1f36714E4a8F75612F20a79720";

function dynamicDataSlot(headSlot: bigint): Hex {
  return keccak256(toHex(headSlot, { size: 32 }));
}

async function setPassingEnvironment(test: TestClient): Promise<void> {
  await test.setCode({ address: P256_VERIFIER, bytecode: loadP256OracleBytecode() });
  await test.setCode({ address: ROUTER, bytecode: MARKER_CODE });
  await test.setCode({ address: IMPL, bytecode: MARKER_CODE });
  await test.setCode({ address: ENTRYPOINT, bytecode: MARKER_CODE });
}

/** Etches a coherent (but fabricated) initialized account state. */
async function fabricateBornAccount(test: TestClient, account: Address): Promise<void> {
  await test.setCode({ address: account, bytecode: designator() });
  await test.setStorageAt({ address: account, index: IMPL_SLOT, value: toHex(BigInt(IMPL), { size: 32 }) });
  await test.setStorageAt({ address: account, index: toHex(STORAGE_SLOT, { size: 32 }), value: NON_ZERO_WORD });
  for (let index = 0; index < 3; index += 1) {
    const typeSlot = STORAGE_SLOT + 1n + BigInt(index * 2);
    const dataHeadSlot = typeSlot + 1n;
    await test.setStorageAt({
      address: account,
      index: toHex(typeSlot, { size: 32 }),
      value: SECP256K1_TYPE,
    });
    await test.setStorageAt({ address: account, index: toHex(dataHeadSlot, { size: 32 }), value: LONG_32_BYTES });
    await test.setStorageAt({
      address: account,
      index: dynamicDataSlot(dataHeadSlot),
      value: VALID_SECP256K1_DATA[index]!,
    });
  }
}

describe("checkChain", () => {
  it(
    "is eligible when every environment probe passes and the account is not born",
    async () => {
      const { url } = await spawnAnvil();
      const { client, test } = clientsFor(url);
      await setPassingEnvironment(test);

      const result = await checkChain(client, CANDIDATE_ACCOUNT);

      expect(result).toEqual({
        verdict: "eligible",
        probes: {
          p256: true,
          eip7702: true,
          create2Deployer: true,
          entryPoint: true,
          routerDeployed: true,
          implDeployed: true,
          accountBorn: false,
        },
        reasons: [],
      });
    },
    20_000,
  );

  it(
    "is born only when the account carries coherent operational state",
    async () => {
      const { url } = await spawnAnvil();
      const { client, test } = clientsFor(url);
      await setPassingEnvironment(test);
      await fabricateBornAccount(test, CANDIDATE_ACCOUNT);

      const result = await checkChain(client, CANDIDATE_ACCOUNT);

      expect(result.verdict).toBe("born");
      expect(result.probes.accountBorn).toBe(true);
      expect(result.reasons).toEqual([]);
    },
    20_000,
  );

  it(
    "is not born when the account points at an implementation this SDK does not speak to",
    async () => {
      // Coherent in every other respect — right designator, initialized header,
      // three well-formed factor slots, real code behind the pointer — but the
      // pointer is not the canonical implementation. This SDK pins IMPL
      // everywhere it signs, so it cannot drive such an account; calling it
      // "born" would invite a caller to treat it as usable.
      const { url } = await spawnAnvil();
      const { client, test } = clientsFor(url);
      await setPassingEnvironment(test);
      await fabricateBornAccount(test, CANDIDATE_ACCOUNT);

      const other: Address = "0x00000000000000000000000000000000DeaDBeef";
      await test.setCode({ address: other, bytecode: MARKER_CODE });
      await test.setStorageAt({
        address: CANDIDATE_ACCOUNT,
        index: IMPL_SLOT,
        value: toHex(BigInt(other), { size: 32 }),
      });

      const result = await checkChain(client, CANDIDATE_ACCOUNT);

      expect(result.probes.accountBorn).toBe(false);
      expect(result.verdict).not.toBe("born");
    },
    20_000,
  );

  it(
    "does not mistake all-ones storage poison for a born or eligible account",
    async () => {
      const { url } = await spawnAnvil();
      const { client, test } = clientsFor(url);
      await setPassingEnvironment(test);
      await test.setCode({ address: CANDIDATE_ACCOUNT, bytecode: designator() });
      await test.setStorageAt({ address: CANDIDATE_ACCOUNT, index: IMPL_SLOT, value: NON_ZERO_WORD });
      for (let offset = 0; offset < 7; offset += 1) {
        await test.setStorageAt({
          address: CANDIDATE_ACCOUNT,
          index: toHex(STORAGE_SLOT + BigInt(offset), { size: 32 }),
          value: NON_ZERO_WORD,
        });
      }

      const result = await checkChain(client, CANDIDATE_ACCOUNT);

      expect(result.probes.accountBorn).toBe(false);
      expect(result.verdict).toBe("ineligible");
      expect(result.reasons.some((reason) => reason.startsWith("account: not birthable"))).toBe(true);
    },
    20_000,
  );

  it("reports a foreign delegation as ineligible rather than safe to receive", async () => {
    const { url } = await spawnAnvil();
    const { client, test } = clientsFor(url);
    await setPassingEnvironment(test);
    await test.setCode({ address: CANDIDATE_ACCOUNT, bytecode: "0xef01000000000000000000000000000000000000000000" });

    const result = await checkChain(client, CANDIDATE_ACCOUNT);

    expect(result.probes.accountBorn).toBe(false);
    expect(result.verdict).toBe("ineligible");
    expect(result.reasons).toContainEqual(expect.stringContaining("not birthable"));
  });

  it(
    "keeps failed environment reasons even when the account is already born",
    async () => {
      const { url } = await spawnAnvil();
      const { client, test } = clientsFor(url);
      await test.setCode({ address: ROUTER, bytecode: MARKER_CODE });
      await test.setCode({ address: IMPL, bytecode: MARKER_CODE });
      await test.setCode({ address: ENTRYPOINT, bytecode: MARKER_CODE });
      await fabricateBornAccount(test, CANDIDATE_ACCOUNT);

      const result = await checkChain(client, CANDIDATE_ACCOUNT);

      expect(result.probes.accountBorn).toBe(true);
      expect(result.verdict).toBe("ineligible");
      expect(result.reasons.some((reason) => reason.startsWith("p256:"))).toBe(true);
    },
    20_000,
  );

  it(
    "is ineligible on a bare chain and names exactly the missing probes",
    async () => {
      const { url } = await spawnAnvil();
      const { client } = clientsFor(url);

      const result = await checkChain(client);

      // Anvil pre-deploys the canonical CREATE2 deployer at genesis, and
      // `--hardfork prague` already prices EIP-7702 authorizations — neither
      // is something this test set up, so both must read true. Nothing sits
      // at 0x100, and none of entryPoint/router/impl were deployed.
      expect(result.probes).toEqual({
        p256: false,
        eip7702: true,
        create2Deployer: true,
        entryPoint: false,
        routerDeployed: false,
        implDeployed: false,
      });
      expect(result.verdict).toBe("ineligible");
      expect(result.reasons).toHaveLength(4);
      expect(result.reasons.some((r) => r.startsWith("p256:"))).toBe(true);
      expect(result.reasons.some((r) => r.startsWith("entryPoint:"))).toBe(true);
      expect(result.reasons.some((r) => r.startsWith("routerDeployed:"))).toBe(true);
      expect(result.reasons.some((r) => r.startsWith("implDeployed:"))).toBe(true);
    },
    20_000,
  );

  it(
    "rejects a P-256 verifier that answers every signature with success (two-armed probe)",
    async () => {
      const { url } = await spawnAnvil();
      const { client, test } = clientsFor(url);
      // Confirm the stub really is permissive before trusting the negative
      // result below: it must accept the valid vector AND its own sabotage.
      await test.setCode({ address: P256_VERIFIER, bytecode: ALWAYS_ACCEPT_P256_STUB });
      const acceptsValid = await client.call({
        to: P256_VERIFIER,
        data: `0x${P256_DIGEST.slice(2)}${P256_R.slice(2)}${P256_S.slice(2)}${P256_QX.slice(2)}${P256_QY.slice(2)}`,
      });
      expect(acceptsValid.data).toBe(NON_ZERO_WORD);
      const flippedDigest = toHex(BigInt(P256_DIGEST) ^ 1n, { size: 32 });
      const acceptsFlipped = await client.call({
        to: P256_VERIFIER,
        data: `0x${flippedDigest.slice(2)}${P256_R.slice(2)}${P256_S.slice(2)}${P256_QX.slice(2)}${P256_QY.slice(2)}`,
      });
      expect(acceptsFlipped.data).toBe(NON_ZERO_WORD);

      // Everything else looks eligible, isolating the failure to p256 alone.
      await test.setCode({ address: ROUTER, bytecode: MARKER_CODE });
      await test.setCode({ address: IMPL, bytecode: MARKER_CODE });
      await test.setCode({ address: ENTRYPOINT, bytecode: MARKER_CODE });

      const result = await checkChain(client);

      expect(result.probes.p256).toBe(false);
      expect(result.verdict).toBe("ineligible");
      expect(result.reasons).toHaveLength(1);
      expect(result.reasons[0]?.startsWith("p256:")).toBe(true);
    },
    20_000,
  );

  it("reports a flipped-arm transport failure instead of treating it as rejection", async () => {
    const positive = `0x${P256_DIGEST.slice(2)}${P256_R.slice(2)}${P256_S.slice(2)}${P256_QX.slice(2)}${P256_QY.slice(2)}` as Hex;
    const flipped = `0x${(fixtures.p256Probe.flippedDigest as Hex).slice(2)}${P256_R.slice(2)}${P256_S.slice(2)}${P256_QX.slice(2)}${P256_QY.slice(2)}` as Hex;
    let positiveExecuted = false;
    let flippedAttempted = false;
    const client = {
      call: async ({ data }: { data?: Hex }) => {
        if (data === positive) {
          positiveExecuted = true;
          return { data: NON_ZERO_WORD };
        }
        if (data === flipped) {
          flippedAttempted = true;
          throw new Error("negative arm RPC unavailable");
        }
        throw new Error("unexpected P-256 calldata");
      },
      estimateGas: async (request: { authorizationList?: unknown }) => (request.authorizationList ? 2n : 1n),
      getCode: async () => MARKER_CODE,
    } as unknown as PublicClient;

    const result = await checkChain(client);

    expect(positiveExecuted).toBe(true);
    expect(flippedAttempted).toBe(true);
    expect(result.probes.p256).toBe(false);
    expect(result.verdict).toBe("ineligible");
    expect(result.reasons).toEqual([
      expect.stringContaining("p256: verifier probe transport failure"),
    ]);
  });
});
