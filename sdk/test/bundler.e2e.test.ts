import { describe, expect, it } from "vitest";
import { concat, encodeAbiParameters, encodeFunctionData, numberToHex, parseEther, type Address, type Hex } from "viem";
import { generatePrivateKey, privateKeyToAddress } from "viem/accounts";
import { ENTRYPOINT } from "../src/core/constants.js";
import { buildBirthBlob } from "../src/birth/blob.js";
import { submitBirth } from "../src/birth/submit.js";
import { buildUserOp, computeUserOpHash, extractUserOperationEvent, fetchEntryPointDeposit, signUserOp } from "../src/execute/userop.js";
import { GasPolicy, type GasFallbackEvent } from "../src/gas/policy.js";
import { Erc7677Client } from "../src/gas/erc7677.js";
import { LocalP256Signer } from "../src/signers/p256.js";
import { LocalSecp256k1Signer } from "../src/signers/secp256k1.js";
import { clientsFor, spawnAnvil } from "./helpers/anvil.js";
import {
  deployCanonical,
  deployEntryPoint,
  deployP256Oracle,
  deploySponsorshipFixtures,
  deployVerifyingPaymaster,
  depositForPaymaster,
  stakeVerifyingPaymaster,
} from "./helpers/deploy.js";
import { spawnAlto } from "./helpers/alto.js";
import { sendUserOperation, toBundlerRpcUserOp, waitForUserOperationReceipt } from "./helpers/bundlerRpc.js";
import { signVerifyingPaymasterData, startMock7677Server } from "./helpers/mock7677.js";

/**
 * Everything the SDK's ERC-4337 path has proven so far (`sdk/test/userop.e2e.test.ts`,
 * `sdk/test/sponsored.e2e.test.ts`) went straight through `EntryPoint.handleOps`,
 * never through a real bundler. A bundler applies its own ERC-4337
 * validation-phase restrictions (mempool/staking rules, gas-limit ceilings,
 * its own bundling/inclusion logic, its own `eth_getUserOperationReceipt`
 * semantics) on top of what the EntryPoint itself checks at execution time,
 * and can reject or mishandle an operation the EntryPoint would happily
 * accept. This suite is that missing coverage: a real, pinned, independently
 * implemented OSS bundler (Alto, `sdk/package.json`'s
 * `devDependencies["@pimlico/alto"]`), driven purely through its public
 * JSON-RPC surface (`eth_sendUserOperation`, `eth_getUserOperationReceipt`).
 *
 * Run with Alto's pinned DEFAULT `--safe-mode true` (full ERC-7562
 * opcode/storage-access banning), every submission failed identically with
 * Anvil's own `debug_traceCall` rejecting Alto's inline-JS bundler-collector
 * tracer (`"unsupported tracer type"`, code `-32602`) — a Go-Ethereum-only
 * JS-tracer capability Anvil does not implement, confirmed by Alto's own
 * upstream docs and its own local-dev tooling (`scripts/run-local-instance.sh`
 * ships `"safe-mode": false` for exactly this Anvil pairing). `./helpers/alto.js`'s
 * `spawnAlto` therefore runs Alto with `--safe-mode false`: a verified,
 * documented environment necessity, not a weakening of the operations under
 * test — see that helper's doc comment for the exact captured error and the
 * upstream evidence. In Alto 0.0.20, unsafe mode uses `UnsafeValidator` and
 * `NullReputationManager`; ERC-7562 opcode, storage-access, referenced-code,
 * entity-role, reputation, and associated stake enforcement are untested.
 * This suite still proves EntryPoint simulation, fee/gas ceilings, RPC and
 * mempool transport, bundling, inclusion, and receipt handling.
 *
 * Alto 0.0.20 safe mode only recognizes precompiles `0x01` through `0x09`.
 * Glaux's P-256 factor uses `STATICCALL` to `0x0100`, so that Alto version can
 * reject it as an undeployed contract even on an EIP-7951/RIP-7212 chain. This
 * is an Alto-version limitation, not an ERC-7562 violation by Glaux. The
 * P-256 test below covers unsafe-mode transport only; it does not prove
 * safe-mode acceptance. Integrators must verify that their bundler accepts
 * `0x0100` as a precompile on the target chain under its safe validation rules.
 *
 * Skipped unless `GLAUX_ALTO=1`, so the default suite and CI stay exactly as
 * fast and network-free as before — same convention `test/P256ForkProbe.t.sol`
 * uses for its own opt-in, environment-gated chain check. Run it with:
 *
 * ```
 * GLAUX_ALTO=1 npm test -- bundler.e2e
 * ```
 */
const GLAUX_ALTO_REQUIRES_FLAG = "requires GLAUX_ALTO=1, skipped by default";

const DEPLOYER_PK: Hex = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const PAPER_PK: Hex = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const CLOUD_PK: Hex = "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a";
const DEVICE_PK: Hex = "0x7459e13afd9158a379ee75ca9e80a328916dba1473c863f800f51ee5f46eb3ab";
/**
 * Fund Alto's own executor/utility accounts with two freshly generated keys
 * that are neither an account factor, the birth deployer, nor any anvil
 * default account reused by a sibling e2e suite. Generated per test run
 * rather than hardcoded, unlike every other key in this file: these hold no
 * protocol meaning beyond "a funded EOA Alto submits/deploys from", so there
 * is nothing for a fixed value to pin down or make reproducible.
 */
const ALTO_EXECUTOR_PK: Hex = generatePrivateKey();
const ALTO_UTILITY_PK: Hex = generatePrivateKey();

const FRESH_RECIPIENT: Address = "0x000000000000000000000000000000000000f00d";

const PAYMASTER_VERIFICATION_GAS_LIMIT = 100_000n;
const PAYMASTER_POSTOP_GAS_LIMIT = 50_000n;
const PAYMASTER_VALID_AFTER = 0;

const COUNTER_ABI = [
  { type: "function", name: "bump", stateMutability: "payable", inputs: [], outputs: [] },
  { type: "function", name: "n", stateMutability: "view", inputs: [], outputs: [{ type: "uint256" }] },
] as const;

interface BornAccount {
  readonly account: Address;
  readonly paper: LocalSecp256k1Signer;
  readonly device: LocalP256Signer;
  readonly cloud: LocalSecp256k1Signer;
}

/** Same birth pattern `sdk/test/userop.e2e.test.ts`'s `bornAndFundedAccount` uses. */
async function bornAndFundedAccount(
  url: string,
  client: ReturnType<typeof clientsFor>["client"],
  test: ReturnType<typeof clientsFor>["test"],
  fundEth: string,
): Promise<BornAccount> {
  await deployP256Oracle(test);
  await deployEntryPoint(test);
  await deployCanonical(client, DEPLOYER_PK);

  const paper = new LocalSecp256k1Signer(PAPER_PK);
  const device = new LocalP256Signer(DEVICE_PK);
  const cloud = new LocalSecp256k1Signer(CLOUD_PK);

  const blob = await buildBirthBlob({ factors: [paper, device, cloud], chainRpc: url });
  await submitBirth(client, DEPLOYER_PK, blob, 31337);
  if (fundEth !== "0") {
    await test.setBalance({ address: blob.account, value: parseEther(fundEth) });
  }

  return { account: blob.account, paper, device, cloud };
}

describe.skipIf(process.env.GLAUX_ALTO !== "1")(`bundler e2e: a real Alto bundler (${GLAUX_ALTO_REQUIRES_FLAG})`, () => {
  it(
    "a self-funded userOp submitted via eth_sendUserOperation is accepted by a real Alto bundler and lands on-chain",
    async () => {
      const { url } = await spawnAnvil();
      const { client, test } = clientsFor(url);
      const born = await bornAndFundedAccount(url, client, test, "1");

      const altoExecutor = privateKeyToAddress(ALTO_EXECUTOR_PK);
      const altoUtility = privateKeyToAddress(ALTO_UTILITY_PK);
      await test.setBalance({ address: altoExecutor, value: parseEther("100") });
      await test.setBalance({ address: altoUtility, value: parseEther("100") });

      const bundler = await spawnAlto({
        rpcUrl: url,
        entryPoints: [ENTRYPOINT],
        executorPrivateKey: ALTO_EXECUTOR_PK,
        utilityPrivateKey: ALTO_UTILITY_PK,
      });

      const recipientBalanceBefore = await client.getBalance({ address: FRESH_RECIPIENT });
      const transferValue = parseEther("0.1");
      const calls = [{ to: FRESH_RECIPIENT, value: transferValue, data: "0x" as Hex }];
      const validUntil = Math.floor(Date.now() / 1000) + 3600;

      const op = await buildUserOp({ account: born.account, client, calls, validUntil });
      const chainId = BigInt(await client.getChainId());
      const signed = await signUserOp({
        op,
        entryPoint: ENTRYPOINT,
        chainId,
        client,
        signers: [born.paper, born.cloud],
      });
      const userOpHash = computeUserOpHash(signed, ENTRYPOINT, chainId);

      const submittedHash = await sendUserOperation(bundler.url, toBundlerRpcUserOp(signed), ENTRYPOINT);
      expect(submittedHash).toBe(userOpHash);

      const bundlerReceipt = await waitForUserOperationReceipt(bundler.url, userOpHash);
      expect(bundlerReceipt.success).toBe(true);

      const receipt = await client.waitForTransactionReceipt({ hash: bundlerReceipt.receipt.transactionHash });
      expect(receipt.status).toBe("success");

      const event = extractUserOperationEvent(receipt.logs, userOpHash, receipt.transactionHash);
      expect(event.success).toBe(true);

      const recipientBalanceAfter = await client.getBalance({ address: FRESH_RECIPIENT });
      expect(recipientBalanceAfter - recipientBalanceBefore).toBe(transferValue);
    },
    120_000,
  );

  it(
    "a P-256 device-factor userOp is bundled and lands on-chain in Alto unsafe mode",
    async () => {
      const { url } = await spawnAnvil();
      const { client, test } = clientsFor(url);
      const born = await bornAndFundedAccount(url, client, test, "1");

      const altoExecutor = privateKeyToAddress(ALTO_EXECUTOR_PK);
      const altoUtility = privateKeyToAddress(ALTO_UTILITY_PK);
      await test.setBalance({ address: altoExecutor, value: parseEther("100") });
      await test.setBalance({ address: altoUtility, value: parseEther("100") });

      const bundler = await spawnAlto({
        rpcUrl: url,
        entryPoints: [ENTRYPOINT],
        executorPrivateKey: ALTO_EXECUTOR_PK,
        utilityPrivateKey: ALTO_UTILITY_PK,
      });

      const recipientBalanceBefore = await client.getBalance({ address: FRESH_RECIPIENT });
      const transferValue = parseEther("0.1");
      const op = await buildUserOp({
        account: born.account,
        client,
        calls: [{ to: FRESH_RECIPIENT, value: transferValue, data: "0x" as Hex }],
        validUntil: Math.floor(Date.now() / 1000) + 3600,
      });
      const chainId = BigInt(await client.getChainId());
      const signed = await signUserOp({
        op,
        entryPoint: ENTRYPOINT,
        chainId,
        client,
        signers: [born.device, born.paper],
      });
      const userOpHash = computeUserOpHash(signed, ENTRYPOINT, chainId);

      const submittedHash = await sendUserOperation(bundler.url, toBundlerRpcUserOp(signed), ENTRYPOINT);
      expect(submittedHash).toBe(userOpHash);

      const bundlerReceipt = await waitForUserOperationReceipt(bundler.url, userOpHash);
      expect(bundlerReceipt.success).toBe(true);

      const receipt = await client.waitForTransactionReceipt({ hash: bundlerReceipt.receipt.transactionHash });
      expect(receipt.status).toBe("success");

      const event = extractUserOperationEvent(receipt.logs, userOpHash, receipt.transactionHash);
      expect(event.success).toBe(true);

      const recipientBalanceAfter = await client.getBalance({ address: FRESH_RECIPIENT });
      expect(recipientBalanceAfter - recipientBalanceBefore).toBe(transferValue);
    },
    120_000,
  );

  it(
    "a sponsored userOp (ERC-7677 → VerifyingPaymaster) submitted via eth_sendUserOperation is accepted by Alto and lands on-chain, with the zero-balance account paying nothing",
    async () => {
      const { url } = await spawnAnvil();
      const { client, test } = clientsFor(url);

      await deployP256Oracle(test);
      await deployEntryPoint(test);
      await deployCanonical(client, DEPLOYER_PK);

      const paper = new LocalSecp256k1Signer(PAPER_PK);
      const device = new LocalP256Signer(DEVICE_PK);
      const cloud = new LocalSecp256k1Signer(CLOUD_PK);
      const blob = await buildBirthBlob({ factors: [paper, device, cloud], chainRpc: url });
      await submitBirth(client, DEPLOYER_PK, blob, 31337);
      const account = blob.account;
      // Deliberately NOT funded, same as `sdk/test/sponsored.e2e.test.ts`:
      // sponsorship, never the account's own wallet, must cover every wei.
      const { counter } = await deploySponsorshipFixtures(client, DEPLOYER_PK, account);

      const paymasterOwner = DEPLOYER_PK;
      const paymasterOwnerAddress = privateKeyToAddress(paymasterOwner);
      const { address: paymaster } = await deployVerifyingPaymaster(client, paymasterOwner, paymasterOwnerAddress);
      await stakeVerifyingPaymaster(client, paymaster, paymasterOwner, parseEther("1"));
      await depositForPaymaster(client, DEPLOYER_PK, paymaster, parseEther("10"));

      const altoExecutor = privateKeyToAddress(ALTO_EXECUTOR_PK);
      const altoUtility = privateKeyToAddress(ALTO_UTILITY_PK);
      await test.setBalance({ address: altoExecutor, value: parseEther("100") });
      await test.setBalance({ address: altoUtility, value: parseEther("100") });

      const bundler = await spawnAlto({
        rpcUrl: url,
        entryPoints: [ENTRYPOINT],
        executorPrivateKey: ALTO_EXECUTOR_PK,
        utilityPrivateKey: ALTO_UTILITY_PK,
      });

      const chainId = BigInt(await client.getChainId());
      const validUntil = Math.floor(Date.now() / 1000) + 3600;

      const mock = await startMock7677Server({
        getPaymasterStubData: () => ({
          paymaster,
          paymasterData: concat([
            encodeAbiParameters([{ type: "uint48" }, { type: "uint48" }], [validUntil, PAYMASTER_VALID_AFTER]),
            `0x${"00".repeat(65)}` as Hex,
          ]),
          paymasterVerificationGasLimit: numberToHex(PAYMASTER_VERIFICATION_GAS_LIMIT),
          paymasterPostOpGasLimit: numberToHex(PAYMASTER_POSTOP_GAS_LIMIT),
          isFinal: false,
        }),
        getPaymasterData: async ({ userOp }) => {
          const paymasterData = await signVerifyingPaymasterData(userOp, {
            paymaster,
            ownerPrivateKey: paymasterOwner,
            chainId,
            validUntil,
            validAfter: PAYMASTER_VALID_AFTER,
            paymasterVerificationGasLimit: PAYMASTER_VERIFICATION_GAS_LIMIT,
            paymasterPostOpGasLimit: PAYMASTER_POSTOP_GAS_LIMIT,
          });
          return { paymaster, paymasterData };
        },
      });

      try {
        const events: GasFallbackEvent[] = [];
        const policy = new GasPolicy({ paymasterClient: new Erc7677Client(mock.url), onFallback: (event) => events.push(event) });

        const calls = [{ to: counter, value: 0n, data: encodeFunctionData({ abi: COUNTER_ABI, functionName: "bump" }) }];
        const op = await buildUserOp({ account, client, calls, validUntil });

        const plan = await policy.plan(op, { client, entryPoint: ENTRYPOINT, chainId });
        expect(events).toEqual([]);
        if (plan.kind !== "sponsored") {
          throw new Error(`expected a sponsored plan, got ${plan.kind}`);
        }

        const signed = await signUserOp({ op: plan.op, entryPoint: ENTRYPOINT, chainId, client, signers: [paper, cloud] });
        const userOpHash = computeUserOpHash(signed, ENTRYPOINT, chainId);

        const submittedHash = await sendUserOperation(bundler.url, toBundlerRpcUserOp(signed), ENTRYPOINT);
        expect(submittedHash).toBe(userOpHash);

        const bundlerReceipt = await waitForUserOperationReceipt(bundler.url, userOpHash);
        expect(bundlerReceipt.success).toBe(true);

        const receipt = await client.waitForTransactionReceipt({ hash: bundlerReceipt.receipt.transactionHash });
        expect(receipt.status).toBe("success");

        const event = extractUserOperationEvent(receipt.logs, userOpHash, receipt.transactionHash);
        expect(event.success).toBe(true);

        const counterValue = await client.readContract({ address: counter, abi: COUNTER_ABI, functionName: "n" });
        expect(counterValue).toBe(1n);

        const accountBalanceAfter = await client.getBalance({ address: account });
        const accountDepositAfter = await fetchEntryPointDeposit(client, ENTRYPOINT, account);
        expect(accountBalanceAfter).toBe(0n);
        expect(accountDepositAfter).toBe(0n);
      } finally {
        await mock.close();
      }
    },
    120_000,
  );
});
