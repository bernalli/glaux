import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { keccak256, stringToBytes, toHex, type Address, type Hex, type PublicClient } from "viem";
import { ROUTER, designator } from "../src/core/constants.js";
import { buildBirthBlob } from "../src/birth/blob.js";
import { preflightFreshAccount } from "../src/birth/preflight.js";
import { submitBirth } from "../src/birth/submit.js";
import { BirthPreflightError, BirthTransactionRevertedError } from "../src/errors.js";
import { LocalP256Signer } from "../src/signers/p256.js";
import { LocalSecp256k1Signer } from "../src/signers/secp256k1.js";
import { clientsFor, spawnAnvil } from "./helpers/anvil.js";
import { deployCanonical } from "./helpers/deploy.js";

const P256_VERIFIER: Address = "0x0000000000000000000000000000000000000100";
const STORAGE_SLOT = BigInt(keccak256(stringToBytes("glaux.account.v1.storage")));
const IMPL_SLOT = keccak256(stringToBytes("glaux.account.v1.implementation"));
const NON_ZERO_WORD = `0x${"01".padStart(64, "0")}` as Hex;

/**
 * Anvil's well-known default accounts #0/#1/#2 (mnemonic "test test test
 * test test test test test test test test junk", verified live against
 * `viem/accounts`' `mnemonicToAccount`), the same accounts
 * `docs/deployments.md`'s local two-chain proof used as the relayer/deployer
 * and the paper/cloud factors. `#0`'s key is already committed as
 * `sdk/test/signers.test.ts`'s `ANVIL_PK`; none of these ever hold real value.
 */
const DEPLOYER_PK: Hex = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const PAPER_PK: Hex = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const CLOUD_PK: Hex = "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a";

/**
 * `P256_PK` from `test/P256Fixture.sol` (`DEVICE_P256_PK` in
 * `GlauxFixture.sol`), the same key `sdk/test/signers.test.ts` uses as its
 * device factor.
 */
const DEVICE_PK: Hex = "0x7459e13afd9158a379ee75ca9e80a328916dba1473c863f800f51ee5f46eb3ab";

/**
 * Deployed bytecode of the vendored daimo `P256Verifier`, read from the forge
 * build artifact — the same contract `test/oracle/P256VerifierOracle.sol`
 * etches for the Solidity suite and `sdk/test/eligibility.test.ts` etches for
 * the SDK suite. A real (if slow) verifier is required here, not a stub: the
 * device factor's possession proof and `_validateSlot`'s installation probe
 * both get verified against it for real during `submitBirth`.
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

describe("birth e2e", () => {
  it(
    "births an account end-to-end, installing the exact factors, and refuses a second submission",
    async () => {
      const { url } = await spawnAnvil();
      const { client, test } = clientsFor(url);
      await test.setCode({ address: P256_VERIFIER, bytecode: loadP256OracleBytecode() });

      const { router, impl } = await deployCanonical(client, DEPLOYER_PK);
      expect(router).toBe(ROUTER);
      expect(impl).not.toBe("0x0000000000000000000000000000000000000000");

      const paper = new LocalSecp256k1Signer(PAPER_PK);
      const device = new LocalP256Signer(DEVICE_PK);
      const cloud = new LocalSecp256k1Signer(CLOUD_PK);

      const blob = await buildBirthBlob({ factors: [paper, device, cloud], chainRpc: url });
      expect(blob.router).toBe(ROUTER);

      // The account is a fresh, never-delegated EOA before birth: preflight
      // must pass silently.
      await expect(preflightFreshAccount(client, blob.account)).resolves.toBeUndefined();

      const result = await submitBirth(client, DEPLOYER_PK, blob);
      expect(result.account).toBe(blob.account);

      const code = await client.getCode({ address: blob.account });
      expect(code).toBe(designator());

      const updateNonce = await client.readContract({
        address: blob.account,
        abi: ACCOUNT_ABI,
        functionName: "updateNonce",
      });
      expect(updateNonce).toBe(0n);

      const execNonce = await client.readContract({
        address: blob.account,
        abi: ACCOUNT_ABI,
        functionName: "execNonce",
      });
      expect(execNonce).toBe(0n);

      const expectedSlots = [
        { verifierType: paper.verifierType, data: paper.keyData() },
        { verifierType: device.verifierType, data: device.keyData() },
        { verifierType: cloud.verifierType, data: cloud.keyData() },
      ];
      for (const [index, expected] of expectedSlots.entries()) {
        const [verifierType, data] = await client.readContract({
          address: blob.account,
          abi: ACCOUNT_ABI,
          functionName: "getSlot",
          args: [index],
        });
        expect(verifierType).toBe(expected.verifierType);
        expect(data.toLowerCase()).toBe(expected.data.toLowerCase());
      }

      // The account now carries the designator AND non-zero namespaced
      // words: preflight must refuse a second submission attempt, even
      // though the code-only check alone would have looked like a
      // legitimate retry.
      await expect(preflightFreshAccount(client, blob.account)).rejects.toThrow(BirthPreflightError);
      await expect(submitBirth(client, DEPLOYER_PK, blob)).rejects.toThrow(BirthPreflightError);
    },
    90_000,
  );

  it("rejects every independently poisoned Glaux namespaced word", async () => {
    const { url } = await spawnAnvil();
    const { client, test } = clientsFor(url);
    const slots = [
      IMPL_SLOT,
      ...Array.from({ length: 7 }, (_, offset) => toHex(STORAGE_SLOT + BigInt(offset), { size: 32 })),
    ];

    for (const [index, slot] of slots.entries()) {
      // A different no-code address per case keeps every account otherwise
      // fresh, so each assertion proves this exact word is checked.
      const account = `0x${(index + 1).toString(16).padStart(40, "0")}` as Address;
      await test.setStorageAt({ address: account, index: slot, value: NON_ZERO_WORD });
      await expect(preflightFreshAccount(client, account)).rejects.toThrow(BirthPreflightError);
    }
  });

  it(
    "does not report a reverted initialization as a successful birth",
    async () => {
      const { url } = await spawnAnvil();
      const { client } = clientsFor(url);
      await deployCanonical(client, DEPLOYER_PK);

      const paper = new LocalSecp256k1Signer(PAPER_PK);
      const device = new LocalP256Signer(DEVICE_PK);
      const cloud = new LocalSecp256k1Signer(CLOUD_PK);
      const blob = await buildBirthBlob({ factors: [paper, device, cloud], chainRpc: url });

      // An invalid birth signature reverts before factor validation. Force a
      // plausible estimate so the test reaches a mined reverted receipt,
      // rather than stopping at the node's correct simulation failure.
      const clientWithForcedEstimate = Object.create(client) as PublicClient;
      clientWithForcedEstimate.estimateGas = async () => 300_000n;
      const revertedBlob = { ...blob, birthSig: "0x00" as Hex };

      let thrown: unknown;
      try {
        await submitBirth(clientWithForcedEstimate, DEPLOYER_PK, revertedBlob);
      } catch (error) {
        thrown = error;
      }

      expect(thrown).toBeInstanceOf(BirthTransactionRevertedError);
      expect((thrown as BirthTransactionRevertedError).txHash).toMatch(/^0x[0-9a-f]{64}$/u);
      // EIP-7702 applies the authorization even though initialize reverted:
      // the SDK must therefore not return a success result for this state.
      expect(await client.getCode({ address: blob.account })).toBe(designator());
    },
    30_000,
  );
});

describe("birth blob JSON schema", () => {
  it(
    "matches the top-level and authorization key sets scripts/birth.py's build_birth_blob emits",
    async () => {
      const { url } = await spawnAnvil();
      const { client } = clientsFor(url);
      await deployCanonical(client, DEPLOYER_PK);

      const paper = new LocalSecp256k1Signer(PAPER_PK);
      const device = new LocalP256Signer(DEVICE_PK);
      const cloud = new LocalSecp256k1Signer(CLOUD_PK);
      const blob = await buildBirthBlob({ factors: [paper, device, cloud], chainRpc: url });

      // Golden key lists read directly from `scripts/birth.py`'s
      // `build_birth_blob` return dict (the Python source of truth for the
      // wire blob) — not reconstructed from memory. See that function's body
      // for the literal dict this mirrors.
      const pythonTopLevelKeys = [
        "account",
        "router",
        "implementation",
        "expectedCodeHash",
        "authorization",
        "initData",
        "birthSig",
      ].sort();
      const pythonAuthorizationKeys = ["chainId", "address", "nonce", "yParity", "r", "s"].sort();

      expect(Object.keys(blob).sort()).toEqual(pythonTopLevelKeys);
      expect(Object.keys(blob.authorization).sort()).toEqual(pythonAuthorizationKeys);
    },
    30_000,
  );
});
