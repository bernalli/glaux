import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { keccak256, type Address, type Hex, type PublicClient } from "viem";
import { ROUTER, designator } from "../src/core/constants.js";
import { buildBirthBlob } from "../src/birth/blob.js";
import { preflightFreshAccount } from "../src/birth/preflight.js";
import { submitBirth } from "../src/birth/submit.js";
import type { BirthBlob } from "../src/core/types.js";
import { LocalP256Signer } from "../src/signers/p256.js";
import { LocalSecp256k1Signer } from "../src/signers/secp256k1.js";
import { clientsFor, spawnAnvil } from "./helpers/anvil.js";
import { deployCanonical } from "./helpers/deploy.js";

/**
 * This suite is the SDK-driven counterpart to `scripts/two_chain_proof.sh`
 * (see steps 1-6 there): the same claim — one birth blob, signed once,
 * produces the identical account with identical state on every EVM chain —
 * proven end-to-end through `sdk/src/birth/*` instead of the Python
 * tooling, on two independent local anvil chains with genuinely different
 * chain ids.
 */

const P256_VERIFIER: Address = "0x0000000000000000000000000000000000000100";

// Same well-known anvil accounts `sdk/test/birth.e2e.test.ts` and
// `docs/deployments.md`'s local two-chain proof use as the relayer/deployer
// and the paper/cloud factors — see that file's comment for provenance.
// None of these ever hold real value.
const DEPLOYER_PK: Hex = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const PAPER_PK: Hex = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const CLOUD_PK: Hex = "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a";
// `P256_PK` from `test/P256Fixture.sol` (`DEVICE_P256_PK` in `GlauxFixture.sol`).
const DEVICE_PK: Hex = "0x7459e13afd9158a379ee75ca9e80a328916dba1473c863f800f51ee5f46eb3ab";

/**
 * Deployed bytecode of the vendored daimo `P256Verifier`, read from the
 * forge build artifact — same artifact `sdk/test/birth.e2e.test.ts` and
 * `sdk/test/eligibility.test.ts` already read, duplicated here rather than
 * shared so a bug in one copy's path resolution cannot silently hide behind
 * another suite's working copy.
 */
function loadP256OracleBytecode(): Hex {
  const here = dirname(fileURLToPath(import.meta.url));
  const artifactPath = join(here, "../../out/P256VerifierOracle.sol/P256VerifierOracle.json");
  const artifact = JSON.parse(readFileSync(artifactPath, "utf8")) as {
    deployedBytecode: { object: string };
  };
  return artifact.deployedBytecode.object as Hex;
}

const ACCOUNT_ABI = [
  {
    type: "function",
    name: "updateNonce",
    stateMutability: "view",
    inputs: [],
    outputs: [{ type: "uint64" }],
  },
  {
    type: "function",
    name: "execNonce",
    stateMutability: "view",
    inputs: [],
    outputs: [{ type: "uint64" }],
  },
  {
    type: "function",
    name: "getSlot",
    stateMutability: "view",
    inputs: [{ name: "index", type: "uint8" }],
    outputs: [
      { name: "verifierType", type: "uint8" },
      { name: "data", type: "bytes" },
    ],
  },
] as const;

/** sha256 over the blob's exact JSON wire form — the "one blob, spent twice" evidence. */
function sha256Blob(blob: BirthBlob): string {
  return createHash("sha256").update(JSON.stringify(blob)).digest("hex");
}

interface BornState {
  readonly code: Hex;
  readonly updateNonce: bigint;
  readonly execNonce: bigint;
  readonly slots: readonly { verifierType: number; data: Hex }[];
}

/** Reads the full post-birth surface this test cares about from one chain. */
async function readBornState(client: PublicClient, account: Address): Promise<BornState> {
  const code = await client.getCode({ address: account });
  const updateNonce = await client.readContract({
    address: account,
    abi: ACCOUNT_ABI,
    functionName: "updateNonce",
  });
  const execNonce = await client.readContract({
    address: account,
    abi: ACCOUNT_ABI,
    functionName: "execNonce",
  });
  const slots = [];
  for (let index = 0; index < 3; index += 1) {
    const [verifierType, data] = await client.readContract({
      address: account,
      abi: ACCOUNT_ABI,
      functionName: "getSlot",
      args: [index],
    });
    slots.push({ verifierType, data });
  }
  return { code: code ?? "0x", updateNonce, execNonce, slots };
}

describe("cross-chain replay, driven from the SDK", () => {
  it(
    "births the SAME account from ONE blob on two chains with different chain ids, byte-identically",
    async () => {
      const [a, b] = await Promise.all([spawnAnvil({ chainId: 31337 }), spawnAnvil({ chainId: 31338 })]);
      const chainA = clientsFor(a.url);
      const chainB = clientsFor(b.url);

      expect(await chainA.client.getChainId()).toBe(31337);
      expect(await chainB.client.getChainId()).toBe(31338);

      await Promise.all([
        chainA.test.setCode({ address: P256_VERIFIER, bytecode: loadP256OracleBytecode() }),
        chainB.test.setCode({ address: P256_VERIFIER, bytecode: loadP256OracleBytecode() }),
      ]);

      // Deterministic deploy on both, independently — neither deploy reads
      // anything from the other chain.
      const [deployedA, deployedB] = await Promise.all([
        deployCanonical(chainA.client, DEPLOYER_PK),
        deployCanonical(chainB.client, DEPLOYER_PK),
      ]);
      expect(deployedA.router).toBe(deployedB.router);
      expect(deployedA.impl).toBe(deployedB.impl);
      expect(deployedA.router).toBe(ROUTER);

      // Same addresses is necessary but not sufficient: the runtime bytecode
      // living at those addresses must match too, or "same address" would be
      // proving nothing about the account that lives behind it.
      const [routerCodeA, routerCodeB, implCodeA, implCodeB] = await Promise.all([
        chainA.client.getCode({ address: deployedA.router }),
        chainB.client.getCode({ address: deployedB.router }),
        chainA.client.getCode({ address: deployedA.impl }),
        chainB.client.getCode({ address: deployedB.impl }),
      ]);
      expect(routerCodeA).toBeDefined();
      expect(implCodeA).toBeDefined();
      expect(keccak256(routerCodeA as Hex)).toBe(keccak256(routerCodeB as Hex));
      expect(keccak256(implCodeA as Hex)).toBe(keccak256(implCodeB as Hex));

      const paper = new LocalSecp256k1Signer(PAPER_PK);
      const device = new LocalP256Signer(DEVICE_PK);
      const cloud = new LocalSecp256k1Signer(CLOUD_PK);

      // ONE blob. Built once, against chain A's RPC (immaterial which chain:
      // the implementation code, and therefore its hash, is identical on
      // both, which is exactly what was just asserted above).
      const blob = await buildBirthBlob({ factors: [paper, device, cloud], chainRpc: a.url });

      // The chain-agnostic half of the claim: the authorization this blob
      // carries names no chain at all.
      expect(blob.authorization.chainId).toBe(0);

      const hashBeforeAnySubmission = sha256Blob(blob);

      // Chain B must still be a pristine target for this exact blob before
      // chain A has seen anything — proving chain A's submission below
      // cannot be what makes chain B's submission possible.
      await expect(preflightFreshAccount(chainB.client, blob.account)).resolves.toBeUndefined();

      const resultA = await submitBirth(chainA.client, DEPLOYER_PK, blob, 31337);
      expect(resultA.account).toBe(blob.account);

      const hashBetweenSubmissions = sha256Blob(blob);
      expect(hashBetweenSubmissions).toBe(hashBeforeAnySubmission);

      // The SAME blob object, unmodified, submitted to the OTHER chain.
      const resultB = await submitBirth(chainB.client, DEPLOYER_PK, blob, 31338);
      expect(resultB.account).toBe(blob.account);
      expect(resultB.account).toBe(resultA.account);

      const hashAfterBothSubmissions = sha256Blob(blob);
      expect(hashAfterBothSubmissions).toBe(hashBeforeAnySubmission);

      const expectedDesignator = designator();
      const [stateA, stateB] = await Promise.all([
        readBornState(chainA.client, blob.account),
        readBornState(chainB.client, blob.account),
      ]);

      // Each chain independently matches the expected shape...
      for (const state of [stateA, stateB]) {
        expect(state.code).toBe(expectedDesignator);
        expect(state.updateNonce).toBe(0n);
        expect(state.execNonce).toBe(0n);
      }
      const expectedSlots = [
        { verifierType: paper.verifierType, data: paper.keyData() },
        { verifierType: device.verifierType, data: device.keyData() },
        { verifierType: cloud.verifierType, data: cloud.keyData() },
      ];
      for (const [index, expected] of expectedSlots.entries()) {
        expect(stateA.slots[index]?.verifierType).toBe(expected.verifierType);
        expect(stateA.slots[index]?.data.toLowerCase()).toBe(expected.data.toLowerCase());
      }

      // ...and, field by field, chain A's readback matches chain B's
      // readback directly — the actual cross-chain replay claim, not just
      // two separate matches against a shared hardcoded expectation.
      expect(stateA.code).toBe(stateB.code);
      expect(stateA.updateNonce).toBe(stateB.updateNonce);
      expect(stateA.execNonce).toBe(stateB.execNonce);
      expect(stateA.slots).toHaveLength(stateB.slots.length);
      for (let index = 0; index < stateA.slots.length; index += 1) {
        expect(stateA.slots[index]?.verifierType).toBe(stateB.slots[index]?.verifierType);
        expect(stateA.slots[index]?.data.toLowerCase()).toBe(stateB.slots[index]?.data.toLowerCase());
      }
    },
    120_000,
  );

  it(
    "replays in the reverse order too, proving neither chain's submission depends on the other's state",
    async () => {
      const [a, b] = await Promise.all([spawnAnvil({ chainId: 31337 }), spawnAnvil({ chainId: 31338 })]);
      const chainA = clientsFor(a.url);
      const chainB = clientsFor(b.url);

      await Promise.all([
        chainA.test.setCode({ address: P256_VERIFIER, bytecode: loadP256OracleBytecode() }),
        chainB.test.setCode({ address: P256_VERIFIER, bytecode: loadP256OracleBytecode() }),
      ]);
      await Promise.all([deployCanonical(chainA.client, DEPLOYER_PK), deployCanonical(chainB.client, DEPLOYER_PK)]);

      const paper = new LocalSecp256k1Signer(PAPER_PK);
      const device = new LocalP256Signer(DEVICE_PK);
      const cloud = new LocalSecp256k1Signer(CLOUD_PK);
      const blob = await buildBirthBlob({ factors: [paper, device, cloud], chainRpc: b.url });
      const hashBefore = sha256Blob(blob);

      // Submit to B FIRST this time. Chain A must remain untouched by it:
      // still a bare, no-code EOA for this exact account.
      const resultB = await submitBirth(chainB.client, DEPLOYER_PK, blob, 31338);
      expect(await chainA.client.getCode({ address: blob.account })).toBeUndefined();
      await expect(preflightFreshAccount(chainA.client, blob.account)).resolves.toBeUndefined();

      const hashBetween = sha256Blob(blob);
      expect(hashBetween).toBe(hashBefore);

      const resultA = await submitBirth(chainA.client, DEPLOYER_PK, blob, 31337);
      expect(resultA.account).toBe(resultB.account);

      const hashAfter = sha256Blob(blob);
      expect(hashAfter).toBe(hashBefore);

      const expectedDesignator = designator();
      const [stateA, stateB] = await Promise.all([
        readBornState(chainA.client, blob.account),
        readBornState(chainB.client, blob.account),
      ]);
      for (const state of [stateA, stateB]) {
        expect(state.code).toBe(expectedDesignator);
        expect(state.updateNonce).toBe(0n);
        expect(state.execNonce).toBe(0n);
      }
      expect(stateA.slots).toEqual(stateB.slots);
    },
    120_000,
  );
});
