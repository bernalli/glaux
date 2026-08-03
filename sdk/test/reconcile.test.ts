import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { keccak256, stringToBytes, toHex, type Address, type Hex, type PublicClient } from "viem";
import { designator } from "../src/core/constants.js";
import { buildBirthBlob } from "../src/birth/blob.js";
import { submitBirth } from "../src/birth/submit.js";
import { LocalP256Signer } from "../src/signers/p256.js";
import { LocalSecp256k1Signer } from "../src/signers/secp256k1.js";
import { ReconciliationReadError } from "../src/errors.js";
import { reconcile, type ActiveChainState } from "../src/reconcile/reconcile.js";
import { clientsFor, spawnAnvil } from "./helpers/anvil.js";
import { deployCanonical } from "./helpers/deploy.js";

/**
 * Cross-checked TypeScript port of `scripts/reconcile.py`. Every verdict this
 * suite asserts is also asserted against the REAL Python tool, run as a
 * subprocess against the same live anvil endpoints — the point of a port is
 * that both sides agree on the same chain state, not that the TypeScript side
 * merely looks plausible on its own.
 */

const P256_VERIFIER: Address = "0x0000000000000000000000000000000000000100";
const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "../..");
const PYTHON = join(REPO_ROOT, ".venv/bin/python");
const RECONCILE_PY = join(REPO_ROOT, "scripts/reconcile.py");

// Same well-known anvil accounts every other e2e suite in this package uses
// (see `sdk/test/replay.e2e.test.ts`); none of these ever hold real value.
const DEPLOYER_PK: Hex = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const PAPER_PK: Hex = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const CLOUD_PK: Hex = "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a";
const DEVICE_PK: Hex = "0x7459e13afd9158a379ee75ca9e80a328916dba1473c863f800f51ee5f46eb3ab";

/** Same artifact-loading pattern `sdk/test/replay.e2e.test.ts` and `sdk/test/eligibility.test.ts` use. */
function loadP256OracleBytecode(): Hex {
  const artifactPath = join(REPO_ROOT, "out/P256VerifierOracle.sol/P256VerifierOracle.json");
  const artifact = JSON.parse(readFileSync(artifactPath, "utf8")) as { deployedBytecode: { object: string } };
  return artifact.deployedBytecode.object as Hex;
}

/**
 * Same artifact-loading pattern as `loadP256OracleBytecode`/
 * `../helpers/deploy.js`'s private `loadDeployedBytecode`, duplicated rather
 * than exported: a bug in one copy's path resolution must not silently hide
 * behind another suite's working copy.
 */
function loadRouterDeployedBytecode(): Hex {
  const artifactPath = join(REPO_ROOT, "out/GlauxDelegate.sol/GlauxDelegate.json");
  const artifact = JSON.parse(readFileSync(artifactPath, "utf8")) as { deployedBytecode: { object: string } };
  return artifact.deployedBytecode.object as Hex;
}

// Re-derived independently of `../src/reconcile/reconcile.js` — the point of
// fabricating storage directly is to construct a state without depending on
// the very module under test to describe its own layout correctly.
const STORAGE_SLOT = BigInt(keccak256(stringToBytes("glaux.account.v1.storage")));
const IMPL_SLOT: Hex = keccak256(stringToBytes("glaux.account.v1.implementation"));
const SECP256K1_TYPE: Hex = toHex(1n, { size: 32 });
const LONG_32_BYTES: Hex = toHex(65n, { size: 32 });
const ZERO_WORD: Hex = toHex(0n, { size: 32 });

const CANDIDATE_ACCOUNT: Address = "0xa0Ee7A142d267C1f36714E4a8F75612F20a79720";

function dynamicDataSlot(headSlot: bigint): Hex {
  return keccak256(toHex(headSlot, { size: 32 }));
}

function typeSlot(index: number): bigint {
  return STORAGE_SLOT + 1n + 2n * BigInt(index);
}

function dataHeadSlot(index: number): bigint {
  return STORAGE_SLOT + 2n + 2n * BigInt(index);
}

/** Packs `(initialized, updateNonce, execNonce)` the same way `GlauxStorage` does. */
function headerWord(initialized: boolean, updateNonce: bigint, execNonce: bigint): Hex {
  const word = (initialized ? 1n : 0n) | (updateNonce << 8n) | (execNonce << 72n);
  return toHex(word, { size: 32 });
}

interface TestClientLike {
  setCode(args: { address: Address; bytecode: Hex }): Promise<void>;
  setStorageAt(args: { address: Address; index: Hex; value: Hex }): Promise<void>;
}

/**
 * Fabricates a coherent (well-formed, non-trivial) "looks born" state on
 * `account`, then poisons ONLY the implementation pointer to zero — the
 * `docs/deployments.md` phase-2 finding, reproduced directly via
 * `anvil_setStorageAt` rather than by re-running a real birth against a
 * missing P-256 verifier. Every raw word here decodes cleanly (a real,
 * initialized-looking header, three well-formed secp256k1 factor slots);
 * only the implementation pointer is wrong, which is exactly what makes the
 * account's own getters unable to answer at all (`GlauxDelegate`'s fallback
 * reverts `NotInitialized` before ever reaching them) while every raw read
 * still succeeds.
 */
async function fabricateHalfBornAccount(
  test: TestClientLike,
  account: Address,
  factorAddresses: readonly [Hex, Hex, Hex],
): Promise<void> {
  await test.setCode({ address: account, bytecode: designator() });
  // Poisoned word: IMPL_SLOT stays zero even though everything else below
  // looks like a fully configured account.
  await test.setStorageAt({ address: account, index: IMPL_SLOT, value: ZERO_WORD });
  await test.setStorageAt({
    address: account,
    index: toHex(STORAGE_SLOT, { size: 32 }),
    value: headerWord(true, 3n, 7n),
  });
  for (let index = 0; index < 3; index += 1) {
    await test.setStorageAt({ address: account, index: toHex(typeSlot(index), { size: 32 }), value: SECP256K1_TYPE });
    await test.setStorageAt({
      address: account,
      index: toHex(dataHeadSlot(index), { size: 32 }),
      value: LONG_32_BYTES,
    });
    await test.setStorageAt({
      address: account,
      index: dynamicDataSlot(dataHeadSlot(index)),
      value: factorAddresses[index]!,
    });
  }
}

interface PythonReconcileRun {
  readonly exitCode: number | null;
  readonly stdout: string;
  readonly stderr: string;
}

/**
 * Runs the REAL `scripts/reconcile.py` (repo venv, never a fresh install)
 * against the same anvil endpoints the TypeScript side just inspected, and
 * returns its exit code — 0 consistent, 1 divergent, 2 raw-vs-getter
 * mismatch, exactly as `docs/client-guidance.md` documents.
 */
function runPythonReconcile(
  account: Address,
  rpcs: readonly { readonly name: string; readonly url: string }[],
  router?: Address,
): PythonReconcileRun {
  const args = ["reconcile.py", "--account", account, ...rpcs.flatMap((r) => ["--rpc", `${r.name}=${r.url}`])];
  if (router !== undefined) args.push("--router", router);
  const result = spawnSync(PYTHON, args, { cwd: join(REPO_ROOT, "scripts"), encoding: "utf8" });
  return { exitCode: result.status, stdout: result.stdout, stderr: result.stderr };
}

async function birthOnBothChains(chainA: PublicClient, chainB: PublicClient, urlA: string) {
  const paper = new LocalSecp256k1Signer(PAPER_PK);
  const device = new LocalP256Signer(DEVICE_PK);
  const cloud = new LocalSecp256k1Signer(CLOUD_PK);
  const blob = await buildBirthBlob({ factors: [paper, device, cloud], chainRpc: urlA });
  await submitBirth(chainA, DEPLOYER_PK, blob);
  await submitBirth(chainB, DEPLOYER_PK, blob);
  return { blob, paper, device, cloud };
}

describe("reconcile", () => {
  it(
    "reports consistent for one blob born identically on two chains, and the real Python tool agrees",
    async () => {
      const [a, b] = await Promise.all([spawnAnvil({ chainId: 31337 }), spawnAnvil({ chainId: 31338 })]);
      const chainA = clientsFor(a.url);
      const chainB = clientsFor(b.url);

      await Promise.all([
        chainA.test.setCode({ address: P256_VERIFIER, bytecode: loadP256OracleBytecode() }),
        chainB.test.setCode({ address: P256_VERIFIER, bytecode: loadP256OracleBytecode() }),
      ]);
      await Promise.all([
        deployCanonical(chainA.client, DEPLOYER_PK),
        deployCanonical(chainB.client, DEPLOYER_PK),
      ]);

      const { blob } = await birthOnBothChains(chainA.client, chainB.client, a.url);

      const result = await reconcile(
        [
          { name: "a", client: chainA.client },
          { name: "b", client: chainB.client },
        ],
        blob.account,
      );

      expect(result.verdict).toBe("consistent");
      expect(result.perChain).toHaveLength(2);
      for (const state of result.perChain) {
        expect(state.active).toBe(true);
        const active = state as ActiveChainState;
        expect(active.initialized).toBe(true);
        expect(active.updateNonce).toBe(0n);
        expect(active.execNonce).toBe(0n);
        expect(active.implCodehash).not.toBe("no code at pointer");
        expect(active.getterMismatches).toEqual([]);
      }
      const [stateA, stateB] = result.perChain as [ActiveChainState, ActiveChainState];
      expect(stateA.router).toBe(stateB.router);
      expect(stateA.implPointer).toBe(stateB.implPointer);
      expect(stateA.implCodehash).toBe(stateB.implCodehash);
      expect(stateA.slots).toEqual(stateB.slots);

      const pythonRun = runPythonReconcile(blob.account, [
        { name: "a", url: a.url },
        { name: "b", url: b.url },
      ]);
      expect(pythonRun.exitCode, `python stderr: ${pythonRun.stderr}`).toBe(0);
    },
    120_000,
  );

  it(
    "reports divergent when one chain's factor slot data has genuinely drifted, and the real Python tool agrees",
    async () => {
      const [a, b] = await Promise.all([spawnAnvil({ chainId: 31337 }), spawnAnvil({ chainId: 31338 })]);
      const chainA = clientsFor(a.url);
      const chainB = clientsFor(b.url);

      await Promise.all([
        chainA.test.setCode({ address: P256_VERIFIER, bytecode: loadP256OracleBytecode() }),
        chainB.test.setCode({ address: P256_VERIFIER, bytecode: loadP256OracleBytecode() }),
      ]);
      await Promise.all([
        deployCanonical(chainA.client, DEPLOYER_PK),
        deployCanonical(chainB.client, DEPLOYER_PK),
      ]);

      const { blob } = await birthOnBothChains(chainA.client, chainB.client, a.url);

      // Genuine divergence: chain B's slot 0 (the paper factor) now names a
      // different address. Both the raw word AND chain B's own `getSlot(0)`
      // getter read this SAME storage, so chain B is internally coherent
      // (no getter mismatch) — the drift is purely cross-chain.
      const driftedAddress = toHex(0xdead1n, { size: 32 });
      await chainB.test.setStorageAt({
        address: blob.account,
        index: dynamicDataSlot(dataHeadSlot(0)),
        value: driftedAddress,
      });

      const result = await reconcile(
        [
          { name: "a", client: chainA.client },
          { name: "b", client: chainB.client },
        ],
        blob.account,
      );

      expect(result.verdict).toBe("divergent");
      const [stateA, stateB] = result.perChain as [ActiveChainState, ActiveChainState];
      expect(stateA.getterMismatches).toEqual([]);
      expect(stateB.getterMismatches).toEqual([]);
      expect(stateA.slots[0]!.data).not.toBe(stateB.slots[0]!.data);
      expect(stateB.slots[0]!.data.toLowerCase()).toBe(driftedAddress.toLowerCase());
      // Everything else about the two chains still agrees — isolating the
      // divergence to exactly the drifted slot.
      expect(stateA.router).toBe(stateB.router);
      expect(stateA.implPointer).toBe(stateB.implPointer);
      expect(stateA.implCodehash).toBe(stateB.implCodehash);
      expect(stateA.updateNonce).toBe(stateB.updateNonce);
      expect(stateA.slots[1]).toEqual(stateB.slots[1]);
      expect(stateA.slots[2]).toEqual(stateB.slots[2]);

      const pythonRun = runPythonReconcile(blob.account, [
        { name: "a", url: a.url },
        { name: "b", url: b.url },
      ]);
      expect(pythonRun.exitCode, `python stderr: ${pythonRun.stderr}`).toBe(1);
    },
    120_000,
  );

  it(
    "reports unreadable for the phase-2 half-born candidate (designator present, impl pointer poisoned to zero), and the real Python tool agrees",
    async () => {
      const { url } = await spawnAnvil();
      const { client, test } = clientsFor(url);
      await deployCanonical(client, DEPLOYER_PK);

      const factorAddresses: [Hex, Hex, Hex] = [
        toHex(0x1234567890abcdef1234567890abcdef12345678n, { size: 32 }),
        toHex(0x234567890abcdef1234567890abcdef123456789n, { size: 32 }),
        toHex(0x34567890abcdef1234567890abcdef123456789an, { size: 32 }),
      ];
      await fabricateHalfBornAccount(test, CANDIDATE_ACCOUNT, factorAddresses);

      const result = await reconcile([{ name: "only", client }], CANDIDATE_ACCOUNT);

      expect(result.verdict).toBe("unreadable");
      expect(result.perChain).toHaveLength(1);
      const [state] = result.perChain as [ActiveChainState];
      // The raw side reads the truth directly: a coherent, well-formed,
      // "looks born" state — the getters simply cannot confirm any of it.
      expect(state.active).toBe(true);
      expect(state.initialized).toBe(true);
      expect(state.updateNonce).toBe(3n);
      expect(state.execNonce).toBe(7n);
      expect(state.implPointer).toBe("0x0000000000000000000000000000000000000000");
      expect(state.implCodehash).toBe("no code at pointer");
      for (let index = 0; index < 3; index += 1) {
        expect(state.slots[index]!.data.toLowerCase()).toBe(factorAddresses[index]!.toLowerCase());
      }
      expect(state.getterMismatches).toHaveLength(1);
      expect(state.getterMismatches[0]).toContain("getter call failed");

      const pythonRun = runPythonReconcile(CANDIDATE_ACCOUNT, [{ name: "only", url }]);
      expect(pythonRun.exitCode, `python stderr: ${pythonRun.stderr}`).toBe(2);
    },
    60_000,
  );

  it("throws ReconciliationReadError, not a verdict, when a raw read genuinely fails at the transport level", async () => {
    const brokenClient = {
      getCode: async () => {
        throw new Error("ECONNREFUSED");
      },
    } as unknown as PublicClient;

    await expect(reconcile([{ name: "broken", client: brokenClient }], CANDIDATE_ACCOUNT)).rejects.toBeInstanceOf(
      ReconciliationReadError,
    );
  });
});
