import { describe, expect, it } from "vitest";
import { concat, encodeAbiParameters, encodeFunctionData, numberToHex, parseEther, type Address, type Hex } from "viem";
import { privateKeyToAddress } from "viem/accounts";
import { ENTRYPOINT } from "../src/core/constants.js";
import { buildBirthBlob } from "../src/birth/blob.js";
import { submitBirth } from "../src/birth/submit.js";
import {
  buildUserOp,
  computeUserOpHash,
  extractUserOperationEvent,
  fetchEntryPointDeposit,
  signUserOp,
  submitUserOpDirect,
} from "../src/execute/userop.js";
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
import { signVerifyingPaymasterData, startMock7677Server } from "./helpers/mock7677.js";
import { Erc7677Client } from "../src/gas/erc7677.js";
import { GasPolicy, type GasFallbackEvent } from "../src/gas/policy.js";

/** Same well-known anvil accounts every other SDK e2e suite uses (see `sdk/test/userop.e2e.test.ts`). */
const DEPLOYER_PK: Hex = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const PAPER_PK: Hex = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const CLOUD_PK: Hex = "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a";
const DEVICE_PK: Hex = "0x7459e13afd9158a379ee75ca9e80a328916dba1473c863f800f51ee5f46eb3ab";
const RELAYER_PK: Hex = "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6";
const BENEFICIARY: Address = "0x000000000000000000000000000000000000beef";

const PAYMASTER_VERIFICATION_GAS_LIMIT = 100_000n;
const PAYMASTER_POSTOP_GAS_LIMIT = 50_000n;
const PAYMASTER_VALID_AFTER = 0;

const OBSERVER_ABI = [
  { type: "function", name: "observe", stateMutability: "nonpayable", inputs: [], outputs: [] },
  { type: "function", name: "accountBalanceDuringExecution", stateMutability: "view", inputs: [], outputs: [{ type: "uint256" }] },
  { type: "function", name: "accountDepositDuringExecution", stateMutability: "view", inputs: [], outputs: [{ type: "uint256" }] },
] as const;

const COUNTER_ABI = [
  { type: "function", name: "bump", stateMutability: "payable", inputs: [], outputs: [] },
  { type: "function", name: "n", stateMutability: "view", inputs: [], outputs: [{ type: "uint256" }] },
] as const;

describe("sponsored e2e: ERC-7677 → VerifyingPaymaster → EntryPoint, mirroring EntryPoint4337.t.sol's zero-balance proof", () => {
  it(
    "a ZERO-balance born account executes through a real, staked+deposited VerifyingPaymaster, " +
      "paid entirely from the paymaster's own EntryPoint deposit, with GasPolicy choosing `sponsored` " +
      "and emitting no fallback event at all",
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
      // Deliberately NOT funded: `setBalance` is never called for `account`.
      // This is the crux of the proof — sponsorship, not the account's own
      // wallet, must cover every wei of gas.
      const { observer, counter } = await deploySponsorshipFixtures(client, DEPLOYER_PK, account);

      // Owner AND verifyingSigner are the SAME test key (the task brief's
      // "owner = a test key" / "the mock server signs paymasterData with the
      // owner key"): `BasePaymaster`'s owner is fixed to the deployer at
      // construction, and `VerifyingPaymaster` takes `verifyingSigner`
      // separately, so reusing one key for both is a deliberate
      // simplification, not an accident of the contract's own design.
      const paymasterOwner = DEPLOYER_PK;
      const paymasterOwnerAddress = privateKeyToAddress(paymasterOwner);
      const { address: paymaster } = await deployVerifyingPaymaster(client, paymasterOwner, paymasterOwnerAddress);
      await stakeVerifyingPaymaster(client, paymaster, paymasterOwner, parseEther("1"));
      await depositForPaymaster(client, DEPLOYER_PK, paymaster, parseEther("10"));

      const chainId = BigInt(await client.getChainId());

      const accountBalanceBefore = await client.getBalance({ address: account });
      const accountDepositBefore = await fetchEntryPointDeposit(client, ENTRYPOINT, account);
      const paymasterDepositBefore = await fetchEntryPointDeposit(client, ENTRYPOINT, paymaster);
      expect(accountBalanceBefore).toBe(0n);
      expect(accountDepositBefore).toBe(0n);

      const validUntil = Math.floor(Date.now() / 1000) + 3600;

      const mock = await startMock7677Server({
        getPaymasterStubData: () => ({
          paymaster,
          // A placeholder, deliberately NOT correctly signed: stub data is
          // only ever used for gas estimation in a real bundler flow, never
          // submitted, so its signature need not verify.
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
          return {
            paymaster,
            paymasterData,
          };
        },
      });

      try {
        const events: GasFallbackEvent[] = [];
        const policy = new GasPolicy({
          paymasterClient: new Erc7677Client(mock.url),
          onFallback: (event) => events.push(event),
        });

        const calls = [
          // This is executed by the Glaux account inside EntryPoint.handleOps,
          // not sampled before or after the transaction. It records the
          // account's native balance and EntryPoint deposit at that execution
          // point; it cannot by itself prove every individual opcode's state.
          { to: observer, value: 0n, data: encodeFunctionData({ abi: OBSERVER_ABI, functionName: "observe" }) },
          // A separate state-changing target proves the intended user call ran
          // after the observer, rather than merely validating a paymaster path.
          { to: counter, value: 0n, data: encodeFunctionData({ abi: COUNTER_ABI, functionName: "bump" }) },
        ];
        const op = await buildUserOp({ account, client, calls, validUntil });

        const plan = await policy.plan(op, { client, entryPoint: ENTRYPOINT, chainId });
        // No degradation at all: sponsorship must succeed cleanly, or this
        // whole test is proving the wrong thing.
        expect(events).toEqual([]);
        if (plan.kind !== "sponsored") {
          throw new Error(`expected a sponsored plan, got ${plan.kind}`);
        }
        expect(plan.events).toEqual([]);
        expect(plan.op.paymasterAndData).not.toBe("0x");

        const signed = await signUserOp({
          op: plan.op,
          entryPoint: ENTRYPOINT,
          chainId,
          client,
          signers: [paper, cloud],
        });

        const userOpHash = computeUserOpHash(signed, ENTRYPOINT, chainId);
        const txHash = await submitUserOpDirect(client, RELAYER_PK, BENEFICIARY, signed);
        const receipt = await client.waitForTransactionReceipt({ hash: txHash });
        expect(receipt.status).toBe("success");

        // Read the EntryPoint's own event; never infer success or cost.
        const event = extractUserOperationEvent(receipt.logs, userOpHash, txHash);
        expect(event.success).toBe(true);
        expect(event.actualGasCost).toBeGreaterThan(0n);

        const [counterValue, accountBalanceDuringExecution, accountDepositDuringExecution] = await Promise.all([
          client.readContract({ address: counter, abi: COUNTER_ABI, functionName: "n" }),
          client.readContract({ address: observer, abi: OBSERVER_ABI, functionName: "accountBalanceDuringExecution" }),
          client.readContract({ address: observer, abi: OBSERVER_ABI, functionName: "accountDepositDuringExecution" }),
        ]);
        expect(counterValue).toBe(1n);
        expect(accountBalanceDuringExecution).toBe(0n);
        expect(accountDepositDuringExecution).toBe(0n);

        const accountBalanceAfter = await client.getBalance({ address: account });
        const accountDepositAfter = await fetchEntryPointDeposit(client, ENTRYPOINT, account);
        const paymasterDepositAfter = await fetchEntryPointDeposit(client, ENTRYPOINT, paymaster);

        // Together with the observer's in-execution reading above, the native
        // balance and EntryPoint deposit are zero before, during the actual
        // account call, and after the sponsored operation.
        expect(accountBalanceAfter).toBe(0n);
        expect(accountDepositAfter).toBe(0n);

        // The paymaster's own EntryPoint deposit was debited by EXACTLY the
        // EntryPoint's own reported `actualGasCost` — read from the event,
        // never inferred from the transaction receipt's aggregate gas.
        expect(paymasterDepositBefore - paymasterDepositAfter).toBe(event.actualGasCost);
      } finally {
        await mock.close();
      }
    },
    60_000,
  );
});
