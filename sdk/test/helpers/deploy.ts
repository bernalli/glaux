import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  concat,
  encodeAbiParameters,
  getContractAddress,
  type Address,
  type Hex,
  type PublicClient,
  type TestClient,
} from "viem";
import { sendRawTransaction } from "viem/actions";
import { privateKeyToAddress, signTransaction } from "viem/accounts";
import { CREATE2_DEPLOYER, ENTRYPOINT, IMPL, ROUTER, SALT } from "../../src/core/constants.js";

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "../../..");

interface ForgeArtifact {
  readonly bytecode: { readonly object: Hex };
  readonly deployedBytecode: { readonly object: Hex };
}

/**
 * Reads a contract's creation bytecode from `out/`, produced by `forge
 * build` (this repo's development.md sandbox notes explain why that build has to
 * happen outside the sandbox). Mirrors the artifact-reading pattern already
 * used by `sdk/test/eligibility.test.ts`'s `loadP256OracleBytecode`.
 */
function loadCreationBytecode(sourceFile: string, contractName: string): Hex {
  const artifactPath = join(REPO_ROOT, "out", `${sourceFile}.sol`, `${contractName}.json`);
  const artifact = JSON.parse(readFileSync(artifactPath, "utf8")) as ForgeArtifact;
  return artifact.bytecode.object;
}

/**
 * Reads a contract's DEPLOYED (runtime) bytecode from `out/` — the shape
 * `anvil_setCode`/`TestClient.setCode` wants, as opposed to
 * `loadCreationBytecode`'s constructor-prefixed initcode. Same artifact-file
 * convention as `loadCreationBytecode` and `sdk/test/eligibility.test.ts`'s
 * `loadP256OracleBytecode`.
 */
function loadDeployedBytecode(sourceFile: string, contractName: string): Hex {
  const artifactPath = join(REPO_ROOT, "out", `${sourceFile}.sol`, `${contractName}.json`);
  const artifact = JSON.parse(readFileSync(artifactPath, "utf8")) as ForgeArtifact;
  return artifact.deployedBytecode.object;
}

/**
 * Etches the vendored `lib/account-abstraction` EntryPoint v0.7's own
 * compiled bytecode at its canonical address (`ENTRYPOINT`,
 * `src/core/constants.ts`) on a local anvil — the same "etch a real,
 * vendored contract's own bytecode at the address the account trusts"
 * pattern `sdk/test/execute.e2e.test.ts` already uses for the P-256 oracle.
 * Unlike `deployCanonical`, this does not go through the CREATE2 deployer:
 * ERC-4337's EntryPoint is not itself CREATE2-deployed by Glaux, so a direct
 * `anvil_setCode` at the already-known canonical address is the correct
 * (and only) way to make a real EntryPoint available under test control.
 */
export async function deployEntryPoint(test: TestClient): Promise<void> {
  const bytecode = loadDeployedBytecode("EntryPoint", "EntryPoint");
  await test.setCode({ address: ENTRYPOINT, bytecode });
}

/**
 * The P-256 precompile address ERC-7951/RIP-7212 reserves. Etched with the
 * vendored daimo `P256VerifierOracle` as a test-only oracle, same address
 * `sdk/test/execute.e2e.test.ts`'s own (pre-existing, duplicated) etch uses —
 * see `spawnAnvil`'s doc comment (`./anvil.js`) for why `--hardfork prague`
 * is required for a *contract* to be etchable here at all.
 */
const P256_VERIFIER: Address = "0x0000000000000000000000000000000000000100";

/**
 * Etches the vendored daimo `P256VerifierOracle` test oracle at the P-256
 * precompile address. Extracted here so new e2e suites (`sdk/test/userop.e2e.test.ts`)
 * reuse the exact same bytecode-loading path as `deployEntryPoint` instead of
 * re-deriving their own artifact read.
 */
export async function deployP256Oracle(test: TestClient): Promise<void> {
  const bytecode = loadDeployedBytecode("P256VerifierOracle", "P256VerifierOracle");
  await test.setCode({ address: P256_VERIFIER, bytecode });
}

/** Sends `initcode` to the canonical CREATE2 deployer and returns the resulting address. */
async function deployInitcode(
  client: PublicClient,
  deployerPrivateKey: Hex,
  deployerAddress: Address,
  initcode: Hex,
): Promise<Address> {
  const expectedAddress = getContractAddress({
    opcode: "CREATE2",
    from: CREATE2_DEPLOYER,
    salt: SALT,
    bytecode: initcode,
  });
  const data = concat([SALT, initcode]);
  const [chainId, nonce, gasPrice, gas] = await Promise.all([
    client.getChainId(),
    client.getTransactionCount({ address: deployerAddress }),
    client.getGasPrice(),
    client.estimateGas({ account: deployerAddress, to: CREATE2_DEPLOYER, data }),
  ]);
  const signedTransaction = await signTransaction({
    privateKey: deployerPrivateKey,
    transaction: { chainId, nonce, to: CREATE2_DEPLOYER, value: 0n, gas, gasPrice, data },
  });
  const hash = await sendRawTransaction(client, { serializedTransaction: signedTransaction });
  const receipt = await client.waitForTransactionReceipt({ hash });
  assert.strictEqual(receipt.status, "success", `CREATE2 deployment to ${expectedAddress} reverted (tx ${hash}).`);
  return expectedAddress;
}

/**
 * Deploys `GlauxAccount` and `GlauxDelegate` deterministically through the
 * canonical CREATE2 deployer — same salt, same deployer, same constructor
 * argument as `script/Deploy.s.sol` — and asserts the resulting addresses
 * equal the canonical `IMPL`/`ROUTER` constants. That equality is the same
 * claim `docs/deployments.md`'s local two-chain proof demonstrates against
 * real chains: a mismatch here means the compiled bytecode in `out/` has
 * drifted from the address those constants were pinned against, which this
 * helper must fail loudly on rather than silently deploy the wrong logic
 * under a birth blob's trusted address.
 */
export async function deployCanonical(
  client: PublicClient,
  deployerPrivateKey: Hex,
): Promise<{ router: Address; impl: Address }> {
  const deployerAddress = privateKeyToAddress(deployerPrivateKey);

  const implInitcode = concat([
    loadCreationBytecode("GlauxAccount", "GlauxAccount"),
    encodeAbiParameters([{ type: "address" }], [ENTRYPOINT]),
  ]);
  const routerInitcode = loadCreationBytecode("GlauxDelegate", "GlauxDelegate");

  const impl = await deployInitcode(client, deployerPrivateKey, deployerAddress, implInitcode);
  const router = await deployInitcode(client, deployerPrivateKey, deployerAddress, routerInitcode);

  assert.strictEqual(impl, IMPL, `deployed GlauxAccount at ${impl}, expected canonical ${IMPL}.`);
  assert.strictEqual(router, ROUTER, `deployed GlauxDelegate at ${router}, expected canonical ${ROUTER}.`);

  return { router, impl };
}
