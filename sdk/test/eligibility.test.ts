import { readFileSync } from "node:fs";
import { spawn, type ChildProcessByStdio } from "node:child_process";
import { dirname, join } from "node:path";
import type { Readable } from "node:stream";
import { fileURLToPath } from "node:url";
import {
  createPublicClient,
  createTestClient,
  http,
  keccak256,
  stringToBytes,
  toHex,
  type Address,
  type Hex,
  type PublicClient,
  type TestClient,
} from "viem";
import { afterEach, describe, expect, it } from "vitest";
import { ENTRYPOINT, IMPL, ROUTER, designator } from "../src/core/constants.js";
import { checkChain } from "../src/eligibility/verdict.js";

// Every scenario below spawns its own anvil and MUST tear it down, on pass or
// fail, so failures never leak a listening process or claim a fixed port.
const runningAnvils = new Set<ChildProcessByStdio<null, Readable, Readable>>();

afterEach(() => {
  for (const child of runningAnvils) {
    child.kill();
  }
  runningAnvils.clear();
});

interface AnvilHandle {
  readonly url: string;
}

const LISTENING_RE = /Listening on 127\.0\.0\.1:(\d+)/;

/**
 * Spawns a fresh anvil on an OS-assigned port (`--port 0`, so parallel runs
 * never collide) pinned to `--hardfork prague`. Pinning matters: a bare
 * modern anvil already answers P-256 at `0x100` natively (its own default
 * "latest" hardfork has picked up EIP-7951/RIP-7212), which would make the
 * "ineligible" and "rejects a permissive verifier" cases below untestable —
 * `anvil_setCode` cannot override a host-implemented precompile, so the only
 * way to put a *contract* at `0x100` under test control is a hardfork old
 * enough not to have the precompile baked in. `prague` already has EIP-7702
 * (needed for the eip7702 probe) but predates the P-256 precompile.
 */
async function spawnAnvil(): Promise<AnvilHandle> {
  const child = spawn("anvil", ["--port", "0", "--hardfork", "prague"], {
    stdio: ["ignore", "pipe", "pipe"],
  });
  runningAnvils.add(child);
  child.once("exit", () => runningAnvils.delete(child));

  const url = await new Promise<string>((resolve, reject) => {
    let buffer = "";
    const onData = (chunk: Buffer): void => {
      buffer += chunk.toString("utf8");
      const match = LISTENING_RE.exec(buffer);
      if (match?.[1]) {
        child.stdout.off("data", onData);
        child.off("exit", onExit);
        resolve(`http://127.0.0.1:${match[1]}`);
      }
    };
    const onExit = (code: number | null): void => {
      reject(new Error(`anvil exited before it started listening (code ${code ?? "unknown"})`));
    };
    child.stdout.on("data", onData);
    child.once("error", reject);
    child.once("exit", onExit);
  });

  return { url };
}

function clientsFor(url: string): { client: PublicClient; test: TestClient } {
  const transport = http(url);
  const client = createPublicClient({ transport });
  const test = createTestClient({ mode: "anvil", transport });
  return { client, test };
}

// ---------------------------------------------------------------------------
// P-256 fixtures: the same known-answer vector as `test/P256Fixture.sol`
// (`P256_DIG`/`P256_R`/`P256_S`/`P256_QX`/`P256_QY`) — a valid signature whose
// private key is public, meant only for probing.
// ---------------------------------------------------------------------------
const P256_VERIFIER: Address = "0x0000000000000000000000000000000000000100";
const P256_DIGEST: Hex = "0x547c05d9093cf1004d4426a5d03202cf500c22777a87f05c18ac247e38fc572e";
const P256_R: Hex = "0x56464d0bb7014173461871178e264acd5e981572bc495d8978bb5b16ca4895bb";
const P256_S: Hex = "0x1018fa59ce5f3bdd39e7df090dd93309be390b068a7cd3123a492cccd3524e5d";
const P256_QX: Hex = "0xc9b91be23306ebbd29f0f1718a1db88a151200eb10c6aad04aa24f8006704de6";
const P256_QY: Hex = "0x0accddfa8e09bddc03677b1f83a1d4aced4155d44ca7c1fd5226b8d312b7de6f";

/**
 * Deployed bytecode of the vendored daimo `P256Verifier`, read from the forge
 * build artifact (`forge build` must have run first — see this repo's
 * development.md sandbox notes on why that has to happen outside the sandbox).
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
const STORAGE_HEADER_WORDS = 7;
const NON_ZERO_WORD: Hex = toHex(1n, { size: 32 });

const CANDIDATE_ACCOUNT: Address = "0xa0Ee7A142d267C1f36714E4a8F75612F20a79720";

/** Etches `designator()` plus non-zero namespaced storage at `account` — a fabricated birth. */
async function fabricateBornAccount(test: TestClient, account: Address): Promise<void> {
  await test.setCode({ address: account, bytecode: designator() });
  await test.setStorageAt({ address: account, index: IMPL_SLOT, value: NON_ZERO_WORD });
  for (let offset = 0; offset < STORAGE_HEADER_WORDS; offset += 1) {
    await test.setStorageAt({
      address: account,
      index: toHex(STORAGE_SLOT + BigInt(offset), { size: 32 }),
      value: NON_ZERO_WORD,
    });
  }
}

describe("checkChain", () => {
  it(
    "is eligible when every environment probe passes and the account is not born",
    async () => {
      const { url } = await spawnAnvil();
      const { client, test } = clientsFor(url);
      await test.setCode({ address: P256_VERIFIER, bytecode: loadP256OracleBytecode() });
      await test.setCode({ address: ROUTER, bytecode: MARKER_CODE });
      await test.setCode({ address: IMPL, bytecode: MARKER_CODE });
      await test.setCode({ address: ENTRYPOINT, bytecode: MARKER_CODE });

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
    "is born when the account carries the designator and non-zero namespaced storage",
    async () => {
      const { url } = await spawnAnvil();
      const { client, test } = clientsFor(url);
      await fabricateBornAccount(test, CANDIDATE_ACCOUNT);

      const result = await checkChain(client, CANDIDATE_ACCOUNT);

      expect(result.verdict).toBe("born");
      expect(result.probes.accountBorn).toBe(true);
      expect(result.reasons).toEqual([]);
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
});
