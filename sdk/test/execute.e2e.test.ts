import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { ContractFunctionZeroDataError, parseEther, toHex, type Address, type Hex, type PublicClient } from "viem";
import { buildBirthBlob } from "../src/birth/blob.js";
import { submitBirth } from "../src/birth/submit.js";
import {
  DEFAULT_EXECUTION_VALIDITY_WINDOW_SECONDS,
  signExecution,
  submitExecution,
  withRelayerRefund,
} from "../src/execute/direct.js";
import {
  ChainIdMismatchError,
  DuplicateExecutionSignerError,
  ExecutionAccountNotBornError,
  ExecutionExpiredError,
  ExecutionNonceMismatchError,
  ExecutionSimulationError,
  ExecutionStateReadError,
  ExecutionValidityWindowError,
  OperationExpiredError,
  UnrecognizedSignerError,
} from "../src/errors.js";
import { LocalP256Signer } from "../src/signers/p256.js";
import { LocalSecp256k1Signer } from "../src/signers/secp256k1.js";
import type { Signer } from "../src/signers/signer.js";
import { clientsFor, spawnAnvil } from "./helpers/anvil.js";
import { deployCanonical } from "./helpers/deploy.js";

/**
 * Same well-known anvil accounts the other e2e suites use for the
 * deployer/paper/cloud/device roles (see `sdk/test/birth.e2e.test.ts`'s
 * comment for provenance) plus anvil's account #3 as a RELAYER distinct from
 * every factor and from the deployer — verified live against `anvil`'s own
 * printed "Private Keys" banner and against `viem/accounts`'
 * `privateKeyToAddress`, none of these ever hold real value.
 */
const P256_VERIFIER: Address = "0x0000000000000000000000000000000000000100";
const DEPLOYER_PK: Hex = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const PAPER_PK: Hex = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const CLOUD_PK: Hex = "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a";
const DEVICE_PK: Hex = "0x7459e13afd9158a379ee75ca9e80a328916dba1473c863f800f51ee5f46eb3ab";
const RELAYER_PK: Hex = "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6";
const RELAYER_ADDRESS: Address = "0x90F79bf6EB2c4f870365E785982E1f101E93b906";

const FRESH_RECIPIENT: Address = "0x000000000000000000000000000000000000f00d";
const STUB_ACCOUNT: Address = "0x1111111111111111111111111111111111111111";

function signingStubClient(
  paper: Signer,
  device: Signer,
  cloud: Signer,
  options: {
    readonly unreadNonce?: boolean;
    readonly unreadSlot?: number;
    readonly unborn?: boolean;
    readonly snapshotBlockNumbers?: readonly bigint[];
    readonly noCodeAtSnapshot?: bigint;
    readonly getterNonce?: bigint;
    readonly rawNonce?: bigint;
  } = {},
): {
  client: PublicClient;
  sent: () => number;
  readBlockNumbers: () => readonly bigint[];
  snapshotCacheTimes: () => readonly number[];
} {
  let sends = 0;
  let snapshotReads = 0;
  const blockNumbers: bigint[] = [];
  const snapshotCacheTimes: number[] = [];
  const slots = [paper, device, cloud];
  const client = {
    getBlockNumber: async ({ cacheTime }: { cacheTime?: number } = {}) => {
      snapshotCacheTimes.push(cacheTime!);
      const snapshots = options.snapshotBlockNumbers ?? [123n];
      const snapshot = snapshots[Math.min(snapshotReads, snapshots.length - 1)]!;
      snapshotReads += 1;
      return snapshot;
    },
    getChainId: async () => 31337,
    readContract: async ({
      functionName,
      args,
      blockNumber,
    }: {
      functionName: string;
      args?: readonly number[];
      blockNumber?: bigint;
    }) => {
      blockNumbers.push(blockNumber!);
      if (blockNumber === options.noCodeAtSnapshot) {
        throw new ContractFunctionZeroDataError({ functionName });
      }
      if (functionName === "execNonce") return options.unreadNonce ? undefined : (options.getterNonce ?? 0n);
      const index = args?.[0];
      if (index === undefined || options.unreadSlot === index) return undefined;
      const signer = slots[index];
      return [signer!.verifierType, signer!.keyData()];
    },
    getStorageAt: async ({
      slot,
      blockNumber,
    }: {
      slot: Hex;
      blockNumber?: bigint;
    }) => {
      expect(slot).toBe("0xc645ef19799bcce32b2c21e3256a200e9914fa1c588f704be7391b93be01ae7f");
      blockNumbers.push(blockNumber!);
      return toHex((options.rawNonce ?? options.getterNonce ?? 0n) << 72n, { size: 32 });
    },
    getCode: async ({ blockNumber }: { blockNumber?: bigint } = {}) =>
      options.unborn || blockNumber === options.noCodeAtSnapshot ? undefined : "0x01",
    request: async ({ method }: { method: string }) => {
      if (method === "eth_sendRawTransaction") sends += 1;
      return "0x";
    },
  } as unknown as PublicClient;
  return {
    client,
    sent: () => sends,
    readBlockNumbers: () => blockNumbers,
    snapshotCacheTimes: () => snapshotCacheTimes,
  };
}

function loadP256OracleBytecode(): Hex {
  const here = dirname(fileURLToPath(import.meta.url));
  const artifactPath = join(here, "../../out/P256VerifierOracle.sol/P256VerifierOracle.json");
  const artifact = JSON.parse(readFileSync(artifactPath, "utf8")) as {
    deployedBytecode: { object: string };
  };
  return artifact.deployedBytecode.object as Hex;
}

interface BornAccount {
  readonly client: PublicClient;
  readonly account: Address;
  readonly paper: LocalSecp256k1Signer;
  readonly device: LocalP256Signer;
  readonly cloud: LocalSecp256k1Signer;
}

/** Births a fresh account and funds it with `fundEth` ETH via anvil's `setBalance`. */
async function bornAndFundedAccount(
  url: string,
  client: PublicClient,
  test: ReturnType<typeof clientsFor>["test"],
  fundEth: string,
): Promise<BornAccount> {
  await test.setCode({ address: P256_VERIFIER, bytecode: loadP256OracleBytecode() });
  await deployCanonical(client, DEPLOYER_PK);

  const paper = new LocalSecp256k1Signer(PAPER_PK);
  const device = new LocalP256Signer(DEVICE_PK);
  const cloud = new LocalSecp256k1Signer(CLOUD_PK);

  const blob = await buildBirthBlob({ factors: [paper, device, cloud], chainRpc: url });
  await submitBirth(client, DEPLOYER_PK, blob, 31337);
  await test.setBalance({ address: blob.account, value: parseEther(fundEth) });

  return { client, account: blob.account, paper, device, cloud };
}

describe("execute direct path fail-closed guards", () => {
  it("rejects an endpoint chain-id mismatch before requesting either factor signature", async () => {
    let signaturesRequested = 0;
    const signer: Signer = {
      verifierType: paper.verifierType,
      keyData: () => paper.keyData(),
      sign: async () => {
        signaturesRequested += 1;
        return paper.sign(toHex(1n, { size: 32 }));
      },
    };
    const client = { getChainId: async () => 31338 } as unknown as PublicClient;
    await expect(
      signExecution({
        account: STUB_ACCOUNT,
        client,
        expectedChainId: 31337,
        calls,
        validUntil: 1,
        signers: [signer, signer],
      }),
    ).rejects.toBeInstanceOf(ChainIdMismatchError);
    expect(signaturesRequested).toBe(0);
  });

  const paper = new LocalSecp256k1Signer(PAPER_PK);
  const device = new LocalP256Signer(DEVICE_PK);
  const cloud = new LocalSecp256k1Signer(CLOUD_PK);
  const calls = [{ to: FRESH_RECIPIENT, value: 0n, data: "0x" as Hex }];

  it("rejects a deadline beyond the default local validity ceiling before any RPC or signature", async () => {
    let signaturesRequested = 0;
    const signer: Signer = {
      verifierType: paper.verifierType,
      keyData: () => paper.keyData(),
      sign: async (digest) => {
        signaturesRequested += 1;
        return paper.sign(digest);
      },
    };
    const stub = signingStubClient(signer, device, cloud);

    await expect(
      signExecution({
        account: STUB_ACCOUNT,
        client: stub.client,
        expectedChainId: 31337,
        calls,
        validUntil: Math.floor(Date.now() / 1000) + DEFAULT_EXECUTION_VALIDITY_WINDOW_SECONDS + 60,
        signers: [signer, cloud],
      }),
    ).rejects.toBeInstanceOf(ExecutionValidityWindowError);

    expect(stub.readBlockNumbers()).toEqual([]);
    expect(signaturesRequested).toBe(0);
  });

  it("signs past the one-hour default when the caller explicitly widens the validity window", async () => {
    const stub = signingStubClient(paper, device, cloud);
    const validUntil = Math.floor(Date.now() / 1000) + DEFAULT_EXECUTION_VALIDITY_WINDOW_SECONDS * 2;

    const signed = await signExecution({
      account: STUB_ACCOUNT,
      client: stub.client,
      expectedChainId: 31337,
      calls,
      validUntil,
      maxValidityWindowSeconds: DEFAULT_EXECUTION_VALIDITY_WINDOW_SECONDS * 4,
      signers: [paper, cloud],
    });

    // The widened deadline reaches the signed material unchanged: an override
    // that were ignored (or the ceiling nailed to one hour) would fail here,
    // where every other validity-window test only ever asserts a refusal.
    expect(signed.validUntil).toBe(validUntil);
    expect(signed.sigs.map((sig) => sig.slotIndex)).toEqual([0, 2]);

    // Non-vacuity: the very same deadline is refused without the override, so
    // the acceptance above is the override's doing and not a deadline that
    // happened to sit inside the default ceiling anyway.
    await expect(
      signExecution({
        account: STUB_ACCOUNT,
        client: stub.client,
        expectedChainId: 31337,
        calls,
        validUntil,
        signers: [paper, cloud],
      }),
    ).rejects.toBeInstanceOf(ExecutionValidityWindowError);
  });

  it("rejects a future execNonce lie when the same-block raw header still reports the current nonce", async () => {
    const stub = signingStubClient(paper, device, cloud, { getterNonce: 1n, rawNonce: 0n });

    await expect(
      signExecution({
        account: STUB_ACCOUNT,
        client: stub.client,
        expectedChainId: 31337,
        calls,
        validUntil: 1,
        signers: [paper, cloud],
      }),
    ).rejects.toMatchObject({
      name: "ExecutionNonceMismatchError",
      path: "direct",
      source: "raw storage",
      expected: 0n,
      actual: 1n,
    } satisfies Partial<ExecutionNonceMismatchError>);
  });

  it("rejects a consistently forged nonce when it disagrees with an independent caller expectation", async () => {
    const stub = signingStubClient(paper, device, cloud, { getterNonce: 1n, rawNonce: 1n });

    await expect(
      signExecution({
        account: STUB_ACCOUNT,
        client: stub.client,
        expectedChainId: 31337,
        expectedNonce: 0n,
        calls,
        validUntil: 1,
        signers: [paper, cloud],
      }),
    ).rejects.toMatchObject({
      name: "ExecutionNonceMismatchError",
      path: "direct",
      source: "caller expectation",
      expected: 0n,
      actual: 1n,
    } satisfies Partial<ExecutionNonceMismatchError>);
  });

  it("refuses an absent simulation result before a raw transaction can be sent", async () => {
    let sends = 0;
    const client = {
      simulateContract: async () => undefined,
      request: async ({ method }: { method: string }) => {
        if (method === "eth_sendRawTransaction") sends += 1;
        return "0x";
      },
    } as unknown as PublicClient;
    const signed = {
      account: STUB_ACCOUNT,
      calls,
      validUntil: 1,
      nonce: 0n,
      sigs: [
        { slotIndex: 0, signature: "0x" as Hex },
        { slotIndex: 1, signature: "0x" as Hex },
      ] as const,
    };

    await expect(submitExecution(client, RELAYER_PK, signed)).rejects.toBeInstanceOf(ExecutionSimulationError);
    expect(sends).toBe(0);
  });

  it("distinguishes an unreadable execution nonce from a proven un-born account without broadcasting", async () => {
    const stub = signingStubClient(paper, device, cloud, { unreadNonce: true });

    await expect(
      signExecution({
        account: STUB_ACCOUNT,
        client: stub.client,
        expectedChainId: 31337,
        calls,
        validUntil: 1,
        signers: [paper, cloud],
      }),
    ).rejects.toMatchObject({
      name: "ExecutionStateReadError",
      target: "execution nonce",
    } satisfies Partial<ExecutionStateReadError>);

    expect(stub.sent()).toBe(0);
    const unborn = signingStubClient(paper, device, cloud, { unreadNonce: true, unborn: true });

    await expect(
      signExecution({
        account: STUB_ACCOUNT,
        client: unborn.client,
        expectedChainId: 31337,
        calls,
        validUntil: 1,
        signers: [paper, cloud],
      }),
    ).rejects.toMatchObject({
      name: "ExecutionAccountNotBornError",
      account: STUB_ACCOUNT,
      blockNumber: 123n,
    } satisfies Partial<ExecutionAccountNotBornError>);

    expect(unborn.sent()).toBe(0);
  });

  it("pins nonce and every factor-slot read to one fresh snapshot", async () => {
    const stub = signingStubClient(paper, device, cloud, {
      snapshotBlockNumbers: [122n, 123n],
      noCodeAtSnapshot: 122n,
    });

    await signExecution({
      account: STUB_ACCOUNT,
      client: stub.client,
      expectedChainId: 31337,
      calls,
      validUntil: 1,
      signers: [paper, cloud],
    });

    expect(stub.readBlockNumbers()).toEqual([122n, 123n, 123n, 123n, 123n, 123n]);
    expect(stub.snapshotCacheTimes()).toEqual([0, 0]);
  });

  it("refuses an unreadable factor slot without broadcasting", async () => {
    const stub = signingStubClient(paper, device, cloud, { unreadSlot: 1 });

    await expect(
      signExecution({
        account: STUB_ACCOUNT,
        client: stub.client,
        expectedChainId: 31337,
        calls,
        validUntil: 1,
        signers: [paper, cloud],
      }),
    ).rejects.toMatchObject({
      name: "ExecutionStateReadError",
      target: "factor slot",
      slotIndex: 1,
    } satisfies Partial<ExecutionStateReadError>);

    expect(stub.sent()).toBe(0);
  });

  it("rejects a duplicate resolved slot before requesting either signature", async () => {
    let signaturesRequested = 0;
    const duplicateSigner: Signer = {
      verifierType: paper.verifierType,
      keyData: () => paper.keyData(),
      sign: async (digest) => {
        signaturesRequested += 1;
        return paper.sign(digest);
      },
    };
    const stub = signingStubClient(duplicateSigner, device, cloud);

    await expect(
      signExecution({
        account: STUB_ACCOUNT,
        client: stub.client,
        expectedChainId: 31337,
        calls,
        validUntil: 1,
        signers: [duplicateSigner, duplicateSigner],
      }),
    ).rejects.toMatchObject({
      name: "DuplicateExecutionSignerError",
      slotIndex: 0,
    } satisfies Partial<DuplicateExecutionSignerError>);

    expect(signaturesRequested).toBe(0);
  });

  it("rejects a signer whose key is not installed in any factor slot", async () => {
    const uninstalled = new LocalSecp256k1Signer(DEPLOYER_PK);
    const stub = signingStubClient(paper, device, cloud);

    await expect(
      signExecution({
        account: STUB_ACCOUNT,
        client: stub.client,
        expectedChainId: 31337,
        calls,
        validUntil: 1,
        signers: [paper, uninstalled],
      }),
    ).rejects.toBeInstanceOf(UnrecognizedSignerError);

    expect(stub.sent()).toBe(0);
  });
});

describe("execute e2e: direct executeWithSigs path", () => {
  it(
    "transfers value through a separate relayer, advances execNonce by exactly 1, and the relayer alone pays gas",
    async () => {
      const { url } = await spawnAnvil();
      const { client, test } = clientsFor(url);
      const born = await bornAndFundedAccount(url, client, test, "1");

      const accountBalanceBefore = await client.getBalance({ address: born.account });
      const recipientBalanceBefore = await client.getBalance({ address: FRESH_RECIPIENT });
      const relayerBalanceBefore = await client.getBalance({ address: RELAYER_ADDRESS });
      const execNonceBefore = await client.readContract({
        address: born.account,
        abi: [
          { type: "function", name: "execNonce", stateMutability: "view", inputs: [], outputs: [{ type: "uint64" }] },
        ] as const,
        functionName: "execNonce",
      });
      expect(execNonceBefore).toBe(0n);

      const transferValue = parseEther("0.1");
      const calls = [{ to: FRESH_RECIPIENT, value: transferValue, data: "0x" as Hex }];
      const validUntil = Math.floor(Date.now() / 1000) + 3600;

      const signed = await signExecution({
        account: born.account,
        client,
        expectedChainId: 31337,
        calls,
        validUntil,
        signers: [born.paper, born.cloud],
      });

      const txHash = await submitExecution(client, RELAYER_PK, signed);
      const receipt = await client.waitForTransactionReceipt({ hash: txHash });
      expect(receipt.status).toBe("success");

      const accountBalanceAfter = await client.getBalance({ address: born.account });
      const recipientBalanceAfter = await client.getBalance({ address: FRESH_RECIPIENT });
      const relayerBalanceAfter = await client.getBalance({ address: RELAYER_ADDRESS });
      const execNonceAfter = await client.readContract({
        address: born.account,
        abi: [
          { type: "function", name: "execNonce", stateMutability: "view", inputs: [], outputs: [{ type: "uint64" }] },
        ] as const,
        functionName: "execNonce",
      });

      // The recipient gained exactly the transferred amount.
      expect(recipientBalanceAfter - recipientBalanceBefore).toBe(transferValue);
      // execNonce advanced by exactly 1, not more, not zero.
      expect(execNonceAfter - execNonceBefore).toBe(1n);
      // The ACCOUNT's balance dropped by exactly the transferred value — no gas
      // was drawn from it.
      expect(accountBalanceBefore - accountBalanceAfter).toBe(transferValue);
      // The RELAYER's balance dropped by MORE than zero (it paid gas) but by
      // LESS than the transfer amount plus any gas — i.e. it paid gas only,
      // never the transferred value, which came entirely out of the account.
      const relayerSpent = relayerBalanceBefore - relayerBalanceAfter;
      expect(relayerSpent).toBeGreaterThan(0n);
      expect(relayerSpent).toBeLessThan(transferValue);
      const gasUsed = receipt.gasUsed * receipt.effectiveGasPrice;
      expect(relayerSpent).toBe(gasUsed);
    },
    60_000,
  );

  it(
    "the contract reverts OperationExpired for a past validUntil, and the SDK surfaces the typed error with the real reason",
    async () => {
      const { url } = await spawnAnvil();
      const { client, test } = clientsFor(url);
      const born = await bornAndFundedAccount(url, client, test, "1");

      const pastValidUntil = 1; // 1970-01-01T00:00:01Z: expired on every real chain.
      const calls = [{ to: FRESH_RECIPIENT, value: parseEther("0.01"), data: "0x" as Hex }];

      const signed = await signExecution({
        account: born.account,
        client,
        expectedChainId: 31337,
        calls,
        validUntil: pastValidUntil,
        signers: [born.paper, born.cloud],
      });

      let thrown: unknown;
      try {
        await submitExecution(client, RELAYER_PK, signed);
      } catch (error) {
        thrown = error;
      }

      expect(thrown).toBeInstanceOf(ExecutionExpiredError);
      const error = thrown as ExecutionExpiredError;
      // The genuine revert reason, not merely "something threw": the exact
      // `validUntil` the contract rejected travels back from the decoded
      // `OperationExpired(uint48,uint256)` custom error.
      expect(error.validUntil).toBe(pastValidUntil);
      expect(error.blockTimestamp).toBeGreaterThan(BigInt(pastValidUntil));
    },
    60_000,
  );

  it("rejects validUntil === 0 client-side before any RPC call is made", async () => {
    const calls = [{ to: FRESH_RECIPIENT, value: 0n, data: "0x" as Hex }];
    let requestsIssued = 0;
    const stubClient = {
      getChainId: async () => {
        requestsIssued += 1;
        return 31337;
      },
      readContract: async () => {
        requestsIssued += 1;
        return 0n;
      },
    } as unknown as PublicClient;

    await expect(
      signExecution({
        account: "0x1111111111111111111111111111111111111111",
        client: stubClient,
        expectedChainId: 31337,
        calls,
        validUntil: 0,
        signers: [new LocalSecp256k1Signer(PAPER_PK), new LocalSecp256k1Signer(CLOUD_PK)],
      }),
    ).rejects.toThrow(OperationExpiredError);

    expect(requestsIssued).toBe(0);
  });

  it(
    "replay protection: submitting the same signed execution twice fails the second time",
    async () => {
      const { url } = await spawnAnvil();
      const { client, test } = clientsFor(url);
      const born = await bornAndFundedAccount(url, client, test, "1");

      const calls = [{ to: FRESH_RECIPIENT, value: parseEther("0.01"), data: "0x" as Hex }];
      const validUntil = Math.floor(Date.now() / 1000) + 3600;
      const signed = await signExecution({
        account: born.account,
        client,
        expectedChainId: 31337,
        calls,
        validUntil,
        signers: [born.paper, born.cloud],
      });

      const firstTxHash = await submitExecution(client, RELAYER_PK, signed);
      const firstReceipt = await client.waitForTransactionReceipt({ hash: firstTxHash });
      expect(firstReceipt.status).toBe("success");

      // The exact same signed payload again: the nonce it was signed against
      // has already moved, so this must fail rather than execute twice.
      await expect(submitExecution(client, RELAYER_PK, signed)).rejects.toThrow();
    },
    60_000,
  );

  it("withRelayerRefund produces a batch whose refund call actually reaches the relayer's balance", async () => {
    const { url } = await spawnAnvil();
    const { client, test } = clientsFor(url);
    const born = await bornAndFundedAccount(url, client, test, "1");

    const relayerBalanceBefore = await client.getBalance({ address: RELAYER_ADDRESS });

    const refundAmount = parseEther("0.02");
    const baseCalls = [{ to: FRESH_RECIPIENT, value: parseEther("0.01"), data: "0x" as Hex }];
    const calls = withRelayerRefund(baseCalls, RELAYER_ADDRESS, refundAmount);
    expect(calls).toHaveLength(2);
    expect(calls[0]).toEqual(baseCalls[0]);
    expect(calls[1]).toEqual({ to: RELAYER_ADDRESS, value: refundAmount, data: "0x" });

    const validUntil = Math.floor(Date.now() / 1000) + 3600;
    const signed = await signExecution({
      account: born.account,
      client,
      expectedChainId: 31337,
      calls,
      validUntil,
      signers: [born.paper, born.cloud],
    });

    const txHash = await submitExecution(client, RELAYER_PK, signed);
    const receipt = await client.waitForTransactionReceipt({ hash: txHash });
    expect(receipt.status).toBe("success");

    const relayerBalanceAfter = await client.getBalance({ address: RELAYER_ADDRESS });
    const gasCost = receipt.gasUsed * receipt.effectiveGasPrice;

    // Net change = refund received minus gas fronted, not merely "some
    // change happened" — proves the refund call actually landed on the
    // relayer, not just that the batch had two entries.
    expect(relayerBalanceAfter - relayerBalanceBefore).toBe(refundAmount - gasCost);
  });
});
