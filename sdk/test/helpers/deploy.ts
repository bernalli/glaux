import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  concat,
  encodeAbiParameters,
  encodeFunctionData,
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
const DEFAULT_OUT_DIR = join(REPO_ROOT, "out");

interface ForgeArtifact {
  readonly bytecode: { readonly object: Hex };
  readonly deployedBytecode: { readonly object: Hex };
}

/**
 * Reads a contract's creation bytecode from a `forge build` output directory
 * (this repo's development.md sandbox notes explain why that build has to happen
 * outside the sandbox). Mirrors the artifact-reading pattern already used by
 * `sdk/test/eligibility.test.ts`'s `loadP256OracleBytecode`. `outDir`
 * defaults to the project's tracked `out/`; `deployVerifyingPaymaster` below
 * passes an out-of-tree one instead (see {@link compileVerifyingPaymaster}).
 */
function loadCreationBytecode(sourceFile: string, contractName: string, outDir: string = DEFAULT_OUT_DIR): Hex {
  const artifactPath = join(outDir, `${sourceFile}.sol`, `${contractName}.json`);
  const artifact = JSON.parse(readFileSync(artifactPath, "utf8")) as ForgeArtifact;
  return artifact.bytecode.object;
}

/**
 * Reads a contract's DEPLOYED (runtime) bytecode from a `forge build` output
 * directory — the shape `anvil_setCode`/`TestClient.setCode` wants, as
 * opposed to `loadCreationBytecode`'s constructor-prefixed initcode. Same
 * artifact-file convention and `outDir` default as `loadCreationBytecode`.
 */
function loadDeployedBytecode(sourceFile: string, contractName: string, outDir: string = DEFAULT_OUT_DIR): Hex {
  const artifactPath = join(outDir, `${sourceFile}.sol`, `${contractName}.json`);
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

/**
 * On-demand, out-of-tree compilation of the vendored `VerifyingPaymaster`
 * sample paymaster
 * (`lib/account-abstraction/contracts/samples/VerifyingPaymaster.sol`).
 * Nothing under `src/`, `test/`, or `script/` imports it, so `forge build`'s
 * normal dependency-graph compilation never produces an
 * `out/VerifyingPaymaster.sol/VerifyingPaymaster.json` artifact for it — and
 * this task must not add an import there to manufacture one (no
 * modifications to the Solidity surface). `forge build <path> --out
 * <tmp> --cache-path <tmp>` still reads this project's `foundry.toml`
 * (remappings, the pinned solc/`bytecode_hash = "none"` settings) exactly as
 * a normal build would; it just writes the result somewhere temporary
 * instead of the tracked `out/`, so nothing in the repo changes.
 */
function compileVerifyingPaymaster(): { readonly outDir: string } {
  const outDir = mkdtempSync(join(tmpdir(), "glaux-verifying-paymaster-out-"));
  const cacheDir = mkdtempSync(join(tmpdir(), "glaux-verifying-paymaster-cache-"));
  const result = spawnSync(
    "forge",
    ["build", "lib/account-abstraction/contracts/samples/VerifyingPaymaster.sol", "--out", outDir, "--cache-path", cacheDir],
    { cwd: REPO_ROOT, stdio: ["ignore", "pipe", "pipe"] },
  );
  if (result.status !== 0) {
    const stderr = result.stderr?.toString("utf8") ?? "";
    throw new Error(`forge build of VerifyingPaymaster.sol failed (exit ${String(result.status)}): ${stderr}`);
  }
  return { outDir };
}

export interface DeployedVerifyingPaymaster {
  readonly address: Address;
}

/**
 * Deploys the vendored `VerifyingPaymaster` via a plain CREATE from
 * `deployerPrivateKey`, whose address becomes both the contract's `Ownable`
 * owner (`BasePaymaster`'s constructor: `Ownable(msg.sender)`) and, when the
 * caller passes the same address as `verifyingSigner`, the key the mock
 * ERC-7677 provider signs `paymasterData` with — the task brief's "owner = a
 * test key" / "the mock server signs paymasterData with the owner key".
 * Not CREATE2: unlike `deployCanonical`, this test paymaster has no
 * cross-chain-identical-address requirement.
 */
export async function deployVerifyingPaymaster(
  client: PublicClient,
  deployerPrivateKey: Hex,
  verifyingSigner: Address,
): Promise<DeployedVerifyingPaymaster> {
  const { outDir } = compileVerifyingPaymaster();
  const bytecode = loadCreationBytecode("VerifyingPaymaster", "VerifyingPaymaster", outDir);
  const deployerAddress = privateKeyToAddress(deployerPrivateKey);
  const initcode = concat([
    bytecode,
    encodeAbiParameters([{ type: "address" }, { type: "address" }], [ENTRYPOINT, verifyingSigner]),
  ]);

  const [chainId, nonce, gasPrice] = await Promise.all([
    client.getChainId(),
    client.getTransactionCount({ address: deployerAddress }),
    client.getGasPrice(),
  ]);
  const gas = await client.estimateGas({ account: deployerAddress, data: initcode });
  const signedTransaction = await signTransaction({
    privateKey: deployerPrivateKey,
    transaction: { chainId, nonce, value: 0n, gas, gasPrice, data: initcode },
  });
  const hash = await sendRawTransaction(client, { serializedTransaction: signedTransaction });
  const receipt = await client.waitForTransactionReceipt({ hash });
  assert.strictEqual(receipt.status, "success", `VerifyingPaymaster deployment reverted (tx ${hash}).`);
  assert.ok(receipt.contractAddress, "VerifyingPaymaster deployment receipt carried no contractAddress");
  return { address: receipt.contractAddress };
}

const VERIFYING_PAYMASTER_ABI = [
  {
    type: "function",
    name: "addStake",
    stateMutability: "payable",
    inputs: [{ name: "unstakeDelaySec", type: "uint32" }],
    outputs: [],
  },
] as const;

const ENTRYPOINT_DEPOSIT_ABI = [
  {
    type: "function",
    name: "depositTo",
    stateMutability: "payable",
    inputs: [{ name: "account", type: "address" }],
    outputs: [],
  },
] as const;

/** Sends one plain legacy value+data call from `privateKey` and requires it to succeed. */
async function sendCall(client: PublicClient, privateKey: Hex, to: Address, value: bigint, data: Hex): Promise<Hex> {
  const from = privateKeyToAddress(privateKey);
  const [chainId, nonce, gasPrice] = await Promise.all([
    client.getChainId(),
    client.getTransactionCount({ address: from }),
    client.getGasPrice(),
  ]);
  const gas = await client.estimateGas({ account: from, to, value, data });
  const signedTransaction = await signTransaction({
    privateKey,
    transaction: { chainId, nonce, to, value, gas, gasPrice, data },
  });
  const hash = await sendRawTransaction(client, { serializedTransaction: signedTransaction });
  const receipt = await client.waitForTransactionReceipt({ hash });
  assert.strictEqual(receipt.status, "success", `call to ${to} reverted (tx ${hash}).`);
  return hash;
}

/**
 * Calls `VerifyingPaymaster.addStake(unstakeDelaySec)` as the paymaster's
 * owner (`onlyOwner`), staking `stakeWei` of the EntryPoint's stake
 * requirement — mirroring `test/EntryPoint4337.t.sol`'s
 * `test_userOp_sponsoredExecutionWithZeroBalanceAccount`, which stakes its
 * own `TestPaymasterAcceptAll` before use.
 */
export async function stakeVerifyingPaymaster(
  client: PublicClient,
  paymaster: Address,
  ownerPrivateKey: Hex,
  stakeWei: bigint,
  unstakeDelaySec = 1,
): Promise<void> {
  const data = encodeFunctionData({ abi: VERIFYING_PAYMASTER_ABI, functionName: "addStake", args: [unstakeDelaySec] });
  await sendCall(client, ownerPrivateKey, paymaster, stakeWei, data);
}

/**
 * Deposits `amountWei` into `paymaster`'s EntryPoint balance via
 * `EntryPoint.depositTo` — permissionless (any funded key may top up any
 * paymaster's deposit), same call `test/EntryPoint4337.t.sol`'s sponsored-
 * execution test uses (`ep.depositTo{value}(address(paymaster))`).
 */
export async function depositForPaymaster(
  client: PublicClient,
  funderPrivateKey: Hex,
  paymaster: Address,
  amountWei: bigint,
): Promise<void> {
  const data = encodeFunctionData({ abi: ENTRYPOINT_DEPOSIT_ABI, functionName: "depositTo", args: [paymaster] });
  await sendCall(client, funderPrivateKey, ENTRYPOINT, amountWei, data);
}
