import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  concat,
  encodeAbiParameters,
  keccak256,
  stringToBytes,
  toHex,
  type Address,
  type Hex,
  type PublicClient,
} from "viem";
import { designator } from "../src/core/constants.js";
import { buildBirthBlob } from "../src/birth/blob.js";
import { submitBirth } from "../src/birth/submit.js";
import { LocalP256Signer } from "../src/signers/p256.js";
import { LocalSecp256k1Signer } from "../src/signers/secp256k1.js";
import { ReconciliationReadError } from "../src/errors.js";
import { compareChainStates, reconcile, type ActiveChainState } from "../src/reconcile/reconcile.js";
import { clientsFor, spawnAnvil } from "./helpers/anvil.js";
import { deployCanonical } from "./helpers/deploy.js";

/**
 * Cross-checked TypeScript port of `scripts/reconcile.py`. Every verdict this
 * suite asserts OVER A LIVE CHAIN is also asserted against the REAL Python
 * tool, run as a subprocess against the same anvil endpoints — the point of a
 * port is that both sides agree on the same chain state, not that the
 * TypeScript side merely looks plausible on its own.
 *
 * The tests driven by a mock client cannot do that (there is no URL to hand a
 * subprocess), so for those the parity is pinned differently: the planted word
 * and the verbatim finding string are duplicated in the sibling Python test,
 * and each side's test goes red if its own tool drifts. That is convention
 * enforced by two tests, not by one co-execution — weaker, and named here so
 * the difference is not mistaken for the live cross-check above.
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
const VALID_IMPLEMENTATION_WORD: Hex = toHex(1n, { size: 32 });
const CODELESS_ROUTER: Address = "0x000000000000000000000000000000000000dEaD";
const CODELESS_DESIGNATOR = concat(["0xef0100", CODELESS_ROUTER]).toLowerCase() as Hex;
const UPDATE_NONCE_SELECTOR = keccak256(stringToBytes("updateNonce()")).slice(0, 10) as Hex;
const EXEC_NONCE_SELECTOR = keccak256(stringToBytes("execNonce()")).slice(0, 10) as Hex;
const IMPLEMENTATION_SELECTOR = keccak256(stringToBytes("implementation()")).slice(0, 10) as Hex;
const GET_SLOT_SELECTOR = keccak256(stringToBytes("getSlot(uint8)")).slice(0, 10) as Hex;

/**
 * A `getSlot` return that is canonical ABI except for one junk byte in the
 * padding that follows its two-byte `bytes` payload. viem masks that byte away
 * and hands back exactly the raw state; `eth_abi` decodes in strict mode and
 * raises `NonEmptyPaddingBytes` on these identical bytes, which is Python exit
 * 2. The sibling Python test plants this same vector.
 */
const DIRTY_GET_SLOT_RETURN: Hex = concat([
  toHex(1n, { size: 32 }), // uint8 verifierType, matching the raw type slot
  toHex(0x40n, { size: 32 }), // offset of the bytes payload
  toHex(2n, { size: 32 }), // payload length
  `0xaabb${"00".repeat(29)}7f` as Hex, // payload, then junk in its padding
]);

/** The same return with its padding zeroed: what the real account emits. */
const CLEAN_GET_SLOT_RETURN: Hex = encodeAbiParameters(
  [{ type: "uint8" }, { type: "bytes" }],
  [1, "0xaabb"],
);

/** Solidity's short form for the same two bytes: payload, zeroed padding, `2 * len`. */
const SHORT_FORM_TWO_BYTE_WORD: Hex = `0xaabb${"00".repeat(29)}04`;

/**
 * A complete, readable raw state for testing failures after the raw-first
 * phase. The getter is injected so these tests can isolate RPC-wire and
 * transport handling without claiming malformed wire data is a chain verdict.
 */
function clientWithValidRawState(
  call: (args: { readonly data?: Hex }) => Promise<{ readonly data?: unknown }>,
): PublicClient {
  return {
    getCode: async ({ address }: { address: Address }) =>
      address.toLowerCase() === CANDIDATE_ACCOUNT.toLowerCase() ? designator() : "0x00",
    getStorageAt: async () => VALID_IMPLEMENTATION_WORD,
    call,
  } as unknown as PublicClient;
}

/**
 * A chain whose raw state is fully readable and whose getters agree with it
 * value for value, except that `getSlot(0)` answers with `getSlotZeroReturn`.
 * Raw slot 0 carries exactly the two bytes a lenient decoder reads out of the
 * dirty-padding vector, so in these tests nothing but the canonicality of the
 * return encoding can move the verdict.
 */
function clientWithGetSlotReturn(getSlotZeroReturn: Hex): PublicClient {
  const storage = new Map<string, Hex>([
    [IMPL_SLOT.toLowerCase(), VALID_IMPLEMENTATION_WORD],
    [toHex(STORAGE_SLOT, { size: 32 }), headerWord(true, 3n, 7n)],
    [toHex(typeSlot(0), { size: 32 }), SECP256K1_TYPE],
    [toHex(typeSlot(1), { size: 32 }), SECP256K1_TYPE],
    [toHex(typeSlot(2), { size: 32 }), SECP256K1_TYPE],
    [toHex(dataHeadSlot(0), { size: 32 }), SHORT_FORM_TWO_BYTE_WORD],
  ]);
  const emptySlotReturn = encodeAbiParameters([{ type: "uint8" }, { type: "bytes" }], [1, "0x"]);
  return {
    getCode: async ({ address }: { address: Address }) =>
      address.toLowerCase() === CANDIDATE_ACCOUNT.toLowerCase() ? designator() : "0x00",
    getStorageAt: async ({ slot }: { slot: Hex }) => storage.get(slot.toLowerCase()) ?? ZERO_WORD,
    call: async ({ data }: { data: Hex }) => {
      if (data === UPDATE_NONCE_SELECTOR) return { data: toHex(3n, { size: 32 }) };
      if (data === EXEC_NONCE_SELECTOR) return { data: toHex(7n, { size: 32 }) };
      if (data === IMPLEMENTATION_SELECTOR) return { data: VALID_IMPLEMENTATION_WORD };
      if (data.startsWith(GET_SLOT_SELECTOR)) {
        return { data: BigInt(`0x${data.slice(10)}`) === 0n ? getSlotZeroReturn : emptySlotReturn };
      }
      throw new Error(`unexpected getter call ${data}`);
    },
  } as unknown as PublicClient;
}

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
  await submitBirth(chainA, DEPLOYER_PK, blob, 31337);
  await submitBirth(chainB, DEPLOYER_PK, blob, 31338);
  return { blob, paper, device, cloud };
}

describe("reconcile", () => {
  it("refuses to call an empty observation set consistent", async () => {
    expect(() => compareChainStates([])).toThrow(RangeError);
    await expect(reconcile([], CANDIDATE_ACCOUNT)).rejects.toThrow(RangeError);
  });

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

  it(
    "reports unreadable for viem's real empty eth_call normalisation at a codeless designator target, and the Python tool agrees",
    async () => {
      const { url } = await spawnAnvil();
      const { client, test } = clientsFor(url);

      // Anvil follows this EIP-7702 designator to an address with no code.
      // Its successful eth_call reply is wire `0x`, which viem deliberately
      // exposes to callers as `{ data: undefined }`.
      await test.setCode({ address: CANDIDATE_ACCOUNT, bytecode: CODELESS_DESIGNATOR });
      expect(await client.getCode({ address: CODELESS_ROUTER })).toBeUndefined();
      expect((await client.call({ to: CANDIDATE_ACCOUNT, data: UPDATE_NONCE_SELECTOR })).data).toBeUndefined();

      const result = await reconcile([{ name: "empty", client }], CANDIDATE_ACCOUNT);

      expect(result.verdict).toBe("unreadable");
      const [state] = result.perChain as [ActiveChainState];
      expect(state.active).toBe(true);
      expect(state.implPointer).toBe("0x0000000000000000000000000000000000000000");
      expect(state.implCodehash).toBe("no code at pointer");
      expect(state.getterMismatches).toHaveLength(1);
      expect(state.getterMismatches[0]).toContain("implementation()");

      const pythonRun = runPythonReconcile(CANDIDATE_ACCOUNT, [{ name: "empty", url }]);
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

  it("throws ReconciliationReadError when a getter RPC transport call rejects after valid raw reads", async () => {
    const client = clientWithValidRawState(async () => {
      throw new Error("ECONNREFUSED");
    });

    await expect(reconcile([{ name: "broken", client }], CANDIDATE_ACCOUNT)).rejects.toMatchObject({
      name: "ReconciliationReadError",
      target: "getter call",
    } satisfies Partial<ReconciliationReadError>);
  });

  it("throws ReconciliationReadError when a getter returns invalid RPC hex after valid raw reads", async () => {
    const client = clientWithValidRawState(async () => ({ data: "0xzz" }));

    await expect(reconcile([{ name: "broken", client }], CANDIDATE_ACCOUNT)).rejects.toMatchObject({
      name: "ReconciliationReadError",
      target: "getter call",
    } satisfies Partial<ReconciliationReadError>);
  });

  it("reports unreadable when a getter returns valid hex that cannot ABI-decode", async () => {
    const client = clientWithValidRawState(async () => ({ data: "0x" }));

    const result = await reconcile([{ name: "malformed-abi", client }], CANDIDATE_ACCOUNT);

    expect(result.verdict).toBe("unreadable");
    expect(result.perChain).toHaveLength(1);
    const [state] = result.perChain as [ActiveChainState];
    expect(state.active).toBe(true);
    expect(state.getterMismatches).toHaveLength(1);
    expect(state.getterMismatches[0]).toContain("implementation()");
  });

  it("reports unreadable when implementation() returns an address word with dirty high padding", async () => {
    const dirtyImplementationWord = `0x01${"00".repeat(30)}01` as Hex;
    const client = clientWithValidRawState(async ({ data }) => {
      if (data === UPDATE_NONCE_SELECTOR || data === EXEC_NONCE_SELECTOR) {
        return { data: ZERO_WORD };
      }
      if (data === IMPLEMENTATION_SELECTOR) {
        return { data: dirtyImplementationWord };
      }
      return {
        data: encodeAbiParameters([{ type: "uint8" }, { type: "bytes" }], [1, "0x"]),
      };
    });

    const result = await reconcile([{ name: "dirty-implementation-padding", client }], CANDIDATE_ACCOUNT);

    expect(result.verdict).toBe("unreadable");
    const [state] = result.perChain as [ActiveChainState];
    expect(state.getterMismatches).toHaveLength(1);
    expect(state.getterMismatches[0]).toContain("implementation()");
    expect(state.getterMismatches[0]).toContain("non-zero ABI padding");
  });

  it("reports unreadable when getSlot returns non-zero padding after its bytes payload", async () => {
    const client = clientWithGetSlotReturn(DIRTY_GET_SLOT_RETURN);

    const result = await reconcile([{ name: "dirty-get-slot-padding", client }], CANDIDATE_ACCOUNT);

    // Parity invariant: this identical return vector is TypeScript `unreadable`
    // here and Python exit 2 in the sibling reconcile test. Raw slot 0 holds
    // exactly the two bytes this return decodes to once the junk byte is
    // masked away, so a lenient decoder finds getter and raw in perfect
    // agreement and answers `consistent` where the Python tool exits 2.
    expect(result.verdict).toBe("unreadable");
    const [state] = result.perChain as [ActiveChainState];
    expect(state.slots[0]!.data).toBe("0xaabb");
    expect(state.getterMismatches).toHaveLength(1);
    expect(state.getterMismatches[0]).toContain("getSlot(0)");
  });

  it("still reports consistent for that same getSlot return with its padding zeroed", async () => {
    // The twin of the test above. Without it, refusing every `getSlot` return
    // outright would satisfy the parity assertion and leave the rest of this
    // mock-driven suite green -- only the live two-chain tests would catch it.
    const client = clientWithGetSlotReturn(CLEAN_GET_SLOT_RETURN);

    const result = await reconcile([{ name: "clean-get-slot-padding", client }], CANDIDATE_ACCOUNT);

    expect(result.verdict).toBe("consistent");
    const [state] = result.perChain as [ActiveChainState];
    expect(state.slots[0]!.data).toBe("0xaabb");
    expect(state.getterMismatches).toEqual([]);
  });

  it("bounds a poisoned long bytes length and reports unreadable without unbounded storage reads", async () => {
    let storageReads = 0;
    const poisonedHeader = toHex(2n * 160_000n + 1n, { size: 32 });
    const client = {
      getCode: async ({ address }: { address: Address }) =>
        address.toLowerCase() === CANDIDATE_ACCOUNT.toLowerCase() ? designator() : "0x00",
      getStorageAt: async ({ slot }: { slot: Hex }) => {
        storageReads += 1;
        return slot === toHex(dataHeadSlot(0), { size: 32 }) ? poisonedHeader : ZERO_WORD;
      },
      call: async () => ({ data: "0x" }),
    } as unknown as PublicClient;

    const result = await reconcile([{ name: "poisoned-length", client }], CANDIDATE_ACCOUNT);

    expect(result.verdict).toBe("unreadable");
    expect(storageReads).toBeLessThanOrEqual(8);
    const [state] = result.perChain as [ActiveChainState];
    expect(state.getterMismatches).toContainEqual(expect.stringContaining("raw factor data length"));
  });

  it("reports unreadable for a planted short-form length above Solidity's maximum", async () => {
    const impossibleShortHeader = toHex(2n * 32n, { size: 32 });
    const client = {
      getCode: async ({ address }: { address: Address }) =>
        address.toLowerCase() === CANDIDATE_ACCOUNT.toLowerCase() ? designator() : "0x00",
      getStorageAt: async ({ slot }: { slot: Hex }) =>
        slot === toHex(dataHeadSlot(0), { size: 32 }) ? impossibleShortHeader : ZERO_WORD,
      call: async () => ({ data: "0x" }),
    } as unknown as PublicClient;

    const result = await reconcile([{ name: "impossible-short-length", client }], CANDIDATE_ACCOUNT);

    // Parity invariant: planted header 0x40 is TypeScript `unreadable` here
    // and Python exit 2 in the sibling reconcile test.
    expect(result.verdict).toBe("unreadable");
    const [state] = result.perChain as [ActiveChainState];
    expect(state.getterMismatches).toContain(
      "slot 0: raw factor data short-form length 32 exceeds Solidity's 31-byte maximum",
    );
  });

  it("still decodes the largest legal short form, so the refusal is not off by one", async () => {
    // 31 payload bytes followed by Solidity's 2*31 marker: the last word the
    // short form can legally carry. Without this, an off-by-one in THIS port
    // alone (`>=` for `>`) would keep every other test green and diverge from
    // the Python oracle only on a planted 31-byte marker — the sibling Python
    // test pins the same boundary from the other side.
    const legalShortHeader = `0x${"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"}3e` as Hex;
    const client = {
      getCode: async ({ address }: { address: Address }) =>
        address.toLowerCase() === CANDIDATE_ACCOUNT.toLowerCase() ? designator() : "0x00",
      getStorageAt: async ({ slot }: { slot: Hex }) =>
        slot === toHex(dataHeadSlot(0), { size: 32 }) ? legalShortHeader : ZERO_WORD,
      call: async () => ({ data: "0x" }),
    } as unknown as PublicClient;

    const result = await reconcile([{ name: "legal-short-length", client }], CANDIDATE_ACCOUNT);

    const [state] = result.perChain as [ActiveChainState];
    expect(state.getterMismatches).not.toContainEqual(
      expect.stringContaining("short-form length"),
    );
    expect(state.slots[0]?.data).toBe(
      "0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    );
  });

  it.each([
    ["code", { getCode: async (): Promise<string> => "0xzz" }],
    [
      "storage",
      {
        getCode: async (): Promise<Hex> => designator(),
        getStorageAt: async (): Promise<string> => "0xzz",
      },
    ],
  ] as const)("throws ReconciliationReadError when raw %s RPC data is malformed", async (_target, malformedClient) => {
    const client = malformedClient as unknown as PublicClient;

    await expect(reconcile([{ name: "broken", client }], CANDIDATE_ACCOUNT)).rejects.toBeInstanceOf(
      ReconciliationReadError,
    );
  });
});

describe("short-form dirty-padding reconciliation", () => {
  it("reports unreadable for non-zero padding past the declared payload", async () => {
    const dirtyShortHeader: Hex =
      "0xaabb7f0000000000000000000000000000000000000000000000000000000004";
    const client = {
      getCode: async ({ address }: { address: Address }) =>
        address.toLowerCase() === CANDIDATE_ACCOUNT.toLowerCase() ? designator() : "0x00",
      getStorageAt: async ({ slot }: { slot: Hex }) =>
        slot === toHex(dataHeadSlot(0), { size: 32 }) ? dirtyShortHeader : ZERO_WORD,
      call: async () => ({ data: "0x" }),
    } as unknown as PublicClient;

    const result = await reconcile([{ name: "dirty-short-padding", client }], CANDIDATE_ACCOUNT);

    // Parity invariant: this identical planted word is TypeScript `unreadable`
    // here and Python exit 2 in the sibling reconcile test.
    expect(result.verdict).toBe("unreadable");
    const [state] = result.perChain as [ActiveChainState];
    expect(state.getterMismatches).toContain(
      "slot 0: raw factor data short-form padding is non-zero past the declared length 2",
    );
  });

  it("reports unreadable for junk in the last padding byte, the one before the marker", async () => {
    // Byte index 30 is the last padding byte. Without this word, shrinking the
    // check's window to `slice(word, length, 30)` would pass every other test
    // on both sides: every other planted word carries its junk right after the
    // payload, so only junk parked here separates the two windows. The sibling
    // Python test plants the identical word.
    const junkAtLastPaddingByte: Hex =
      "0xaabb000000000000000000000000000000000000000000000000000000007f04";
    const client = {
      getCode: async ({ address }: { address: Address }) =>
        address.toLowerCase() === CANDIDATE_ACCOUNT.toLowerCase() ? designator() : "0x00",
      getStorageAt: async ({ slot }: { slot: Hex }) =>
        slot === toHex(dataHeadSlot(0), { size: 32 }) ? junkAtLastPaddingByte : ZERO_WORD,
      call: async () => ({ data: "0x" }),
    } as unknown as PublicClient;

    const result = await reconcile([{ name: "junk-at-last-padding-byte", client }], CANDIDATE_ACCOUNT);

    expect(result.verdict).toBe("unreadable");
    const [state] = result.perChain as [ActiveChainState];
    expect(state.getterMismatches).toContain(
      "slot 0: raw factor data short-form padding is non-zero past the declared length 2",
    );
  });
});
