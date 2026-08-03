import { describe, expect, it } from "vitest";
import { concat, encodeAbiParameters, numberToHex, parseEther, type Address, type Hex } from "viem";
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
import { deployCanonical, deployEntryPoint, deployP256Oracle, deployVerifyingPaymaster, depositForPaymaster, stakeVerifyingPaymaster } from "./helpers/deploy.js";
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
const FRESH_RECIPIENT: Address = "0x000000000000000000000000000000000000f00d";

const PAYMASTER_VERIFICATION_GAS_LIMIT = 100_000n;
const PAYMASTER_POSTOP_GAS_LIMIT = 50_000n;
const PAYMASTER_VALID_AFTER = 0;

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
      await submitBirth(client, DEPLOYER_PK, blob);
      const account = blob.account;
      // Deliberately NOT funded: `setBalance` is never called for `account`.
      // This is the crux of the proof — sponsorship, not the account's own
      // wallet, must cover every wei of gas.

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
            paymasterVerificationGasLimit: numberToHex(PAYMASTER_VERIFICATION_GAS_LIMIT),
            paymasterPostOpGasLimit: numberToHex(PAYMASTER_POSTOP_GAS_LIMIT),
          };
        },
      });

      try {
        const events: GasFallbackEvent[] = [];
        const policy = new GasPolicy({
          paymasterClient: new Erc7677Client(mock.url),
          onFallback: (event) => events.push(event),
        });

        const calls = [{ to: FRESH_RECIPIENT, value: 0n, data: "0x" as Hex }];
        const op = await buildUserOp({ account, client, calls, validUntil });

        const plan = await policy.plan(op, { client, entryPoint: ENTRYPOINT, chainId });
        // No degradation at all: sponsorship must succeed cleanly, or this
        // whole test is proving the wrong thing.
        expect(events).toEqual([]);
        if (plan.kind !== "sponsored") {
          throw new Error(`expected a sponsored plan, got ${plan.kind}`);
        }
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

        const accountBalanceAfter = await client.getBalance({ address: account });
        const accountDepositAfter = await fetchEntryPointDeposit(client, ENTRYPOINT, account);
        const paymasterDepositAfter = await fetchEntryPointDeposit(client, ENTRYPOINT, paymaster);

        // Mirrors `EntryPoint4337.t.sol::test_userOp_sponsoredExecutionWithZeroBalanceAccount`'s
        // before/after assertions: the account's native balance and its
        // EntryPoint deposit are zero both before and after the entire
        // sponsored operation — the account never fronts anything. (The
        // Solidity proof additionally walks every intermediate state-diff
        // step via `vm.recordLogs`/`vm.stopAndReturnStateDiff`, an EVM-
        // internal cheatcode with no JSON-RPC equivalent this external SDK
        // test can reach; before/after zero across the one atomic
        // transaction is the strongest check available from outside the
        // EVM, and is what this test asserts.)
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
