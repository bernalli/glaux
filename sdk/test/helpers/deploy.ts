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
} from "viem";
import { sendRawTransaction } from "viem/actions";
import { privateKeyToAddress, signTransaction } from "viem/accounts";
import { CREATE2_DEPLOYER, ENTRYPOINT, IMPL, ROUTER, SALT } from "../../src/core/constants.js";

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "../../..");

interface ForgeArtifact {
  readonly bytecode: { readonly object: Hex };
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
