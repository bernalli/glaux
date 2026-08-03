import { afterEach, describe, expect, it } from "vitest";
import { encodePacked, parseEther, type Address, type Hex, type PublicClient } from "viem";
import { ENTRYPOINT } from "../src/core/constants.js";
import { buildBirthBlob } from "../src/birth/blob.js";
import { submitBirth } from "../src/birth/submit.js";
import { buildUserOp, signUserOp, submitUserOpDirect, type PackedUserOperation } from "../src/execute/userop.js";
import { PaymasterNotConfiguredError, PaymasterUnavailableError, SelfFundingUnavailableError } from "../src/errors.js";
import { LocalP256Signer } from "../src/signers/p256.js";
import { LocalSecp256k1Signer } from "../src/signers/secp256k1.js";
import { clientsFor, spawnAnvil } from "./helpers/anvil.js";
import { deployCanonical, deployEntryPoint, deployP256Oracle } from "./helpers/deploy.js";
import { MockHttpError, startMock7677Server, type Mock7677ServerHandle } from "./helpers/mock7677.js";
import { Erc7677Client } from "../src/gas/erc7677.js";
import { GasPolicy, type GasFallbackEvent } from "../src/gas/policy.js";

/**
 * Same well-known anvil accounts `sdk/test/userop.e2e.test.ts` uses (see its
 * comment for provenance) for the deployer/paper/cloud/device/relayer roles,
 * plus a synthetic beneficiary that holds no key at all.
 */
const DEPLOYER_PK: Hex = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const PAPER_PK: Hex = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const CLOUD_PK: Hex = "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a";
const DEVICE_PK: Hex = "0x7459e13afd9158a379ee75ca9e80a328916dba1473c863f800f51ee5f46eb3ab";
const RELAYER_PK: Hex = "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6";
const BENEFICIARY: Address = "0x000000000000000000000000000000000000beef";
const FRESH_RECIPIENT: Address = "0x000000000000000000000000000000000000f00d";
const STUB_ACCOUNT: Address = "0x1111111111111111111111111111111111111111";

interface BornAccount {
  readonly account: Address;
  readonly paper: LocalSecp256k1Signer;
  readonly device: LocalP256Signer;
  readonly cloud: LocalSecp256k1Signer;
}

/** Births and funds a fresh account — same flow as `sdk/test/userop.e2e.test.ts`'s own helper. */
async function bornAndFundedAccount(
  url: string,
  client: PublicClient,
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
  await submitBirth(client, DEPLOYER_PK, blob);
  await test.setBalance({ address: blob.account, value: parseEther(fundEth) });

  return { account: blob.account, paper, device, cloud };
}

function packGas(hi: bigint, lo: bigint): Hex {
  return encodePacked(["uint128", "uint128"], [hi, lo]);
}

/** A well-formed, self-contained `PackedUserOperation` for tests that never touch a chain. */
function stubOp(overrides: Partial<PackedUserOperation> = {}): PackedUserOperation {
  return {
    sender: STUB_ACCOUNT,
    nonce: 0n,
    initCode: "0x",
    callData: "0x",
    accountGasLimits: packGas(600_000n, 200_000n),
    preVerificationGas: 100_000n,
    gasFees: packGas(1n, 10n),
    paymasterAndData: "0x",
    signature: "0x",
    validUntil: 1,
    ...overrides,
  };
}

const openMocks: Mock7677ServerHandle[] = [];

afterEach(async () => {
  await Promise.all(openMocks.splice(0).map((mock) => mock.close()));
});

async function mockServer(handlers: Parameters<typeof startMock7677Server>[0]): Promise<Mock7677ServerHandle> {
  const server = await startMock7677Server(handlers);
  openMocks.push(server);
  return server;
}

describe("Erc7677Client: ERC-7677 wire round trip against an in-process mock", () => {
  it("decodes stub and final paymaster data, and passes entryPoint/chainId/context through verbatim", async () => {
    const paymaster: Address = "0x9999999999999999999999999999999999999999" as Address; // 42 chars incl. 0x
    const seenStub: unknown[] = [];
    const seenFinal: unknown[] = [];

    const server = await mockServer({
      getPaymasterStubData: (params) => {
        seenStub.push(params);
        return { paymaster, paymasterData: "0x1234", paymasterVerificationGasLimit: "0xea60", isFinal: false };
      },
      getPaymasterData: (params) => {
        seenFinal.push(params);
        return { paymaster, paymasterData: "0x5678", paymasterPostOpGasLimit: "0x2710" };
      },
    });

    const client = new Erc7677Client(server.url);
    const op = stubOp();
    const context = { policyId: "test-policy" };

    const stub = await client.getPaymasterStubData({ op, entryPoint: ENTRYPOINT, chainId: 31337n, context });
    expect(stub).toEqual({
      paymaster,
      paymasterData: "0x1234",
      paymasterVerificationGasLimit: 60_000n,
      paymasterPostOpGasLimit: undefined,
      isFinal: false,
    });

    const final = await client.getPaymasterData({ op, entryPoint: ENTRYPOINT, chainId: 31337n, context });
    expect(final).toEqual({
      paymaster,
      paymasterData: "0x5678",
      paymasterVerificationGasLimit: undefined,
      paymasterPostOpGasLimit: 10_000n,
    });

    expect(seenStub).toHaveLength(1);
    expect(seenFinal).toHaveLength(1);
    const [stubParams] = seenStub as [{ entryPoint: Address; chainId: Hex; context: Record<string, unknown> }];
    expect(stubParams.entryPoint).toBe(ENTRYPOINT);
    expect(stubParams.chainId).toBe("0x7a69"); // 31337
    expect(stubParams.context).toEqual(context);
  });

  it("fails closed with PaymasterUnavailableError on a malformed provider response (missing paymaster address)", async () => {
    const server = await mockServer({
      getPaymasterStubData: () => ({ paymasterData: "0x1234" }),
    });
    const client = new Erc7677Client(server.url);

    await expect(
      client.getPaymasterStubData({ op: stubOp(), entryPoint: ENTRYPOINT, chainId: 31337n }),
    ).rejects.toBeInstanceOf(PaymasterUnavailableError);
  });

  it("fails closed with PaymasterUnavailableError on an HTTP-level failure", async () => {
    const server = await mockServer({
      getPaymasterStubData: () => {
        throw new MockHttpError(500, "provider outage");
      },
    });
    const client = new Erc7677Client(server.url);

    let thrown: unknown;
    try {
      await client.getPaymasterStubData({ op: stubOp(), entryPoint: ENTRYPOINT, chainId: 31337n });
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toBeInstanceOf(PaymasterUnavailableError);
    expect((thrown as PaymasterUnavailableError).message).toContain("HTTP 500");
  });

  it("fails closed with PaymasterUnavailableError on a JSON-RPC-level error field", async () => {
    // No handler registered for either method: the mock server's router
    // default responds with a well-formed 200 JSON-RPC envelope carrying an
    // `error` field (`"method not found"`) rather than a `result` — exactly
    // the shape a real provider sends for, e.g., an unsupported chain.
    const server = await mockServer({});
    const client = new Erc7677Client(server.url);

    await expect(
      client.getPaymasterStubData({ op: stubOp(), entryPoint: ENTRYPOINT, chainId: 31337n }),
    ).rejects.toBeInstanceOf(PaymasterUnavailableError);
  });
});

describe("GasPolicy: no silent fallbacks", () => {
  it("emits a distinct PaymasterNotConfiguredError event (never PaymasterUnavailableError) when no provider is configured, then completes self-funded", async () => {
    const events: GasFallbackEvent[] = [];
    const policy = new GasPolicy({ paymasterClient: null, onFallback: (event) => events.push(event) });
    const op = stubOp();
    const stubClient = { getBalance: async () => parseEther("1") } as unknown as PublicClient;

    const plan = await policy.plan(op, { client: stubClient, entryPoint: ENTRYPOINT, chainId: 31337n });

    expect(plan).toEqual({ kind: "selfFunded", op });
    expect(events).toEqual([{ from: "sponsored", to: "selfFunded", cause: PaymasterNotConfiguredError.name }]);
  });

  it("degrades further to selfRelay, with its own emitted event, when the account cannot cover the self-funded prefund", async () => {
    const events: GasFallbackEvent[] = [];
    const policy = new GasPolicy({ paymasterClient: null, onFallback: (event) => events.push(event) });
    const op = stubOp();
    const stubClient = { getBalance: async () => 0n } as unknown as PublicClient;

    const plan = await policy.plan(op, { client: stubClient, entryPoint: ENTRYPOINT, chainId: 31337n });

    expect(plan).toEqual({ kind: "selfRelay" });
    expect(events).toEqual([
      { from: "sponsored", to: "selfFunded", cause: PaymasterNotConfiguredError.name },
      { from: "selfFunded", to: "selfRelay", cause: SelfFundingUnavailableError.name },
    ]);
  });

  it(
    "an HTTP 500 from a CONFIGURED provider emits {from: sponsored, to: selfFunded, cause: PaymasterUnavailableError} " +
      "and the operation still completes via the self-funded ERC-4337 path (Task 9 harness)",
    async () => {
      const { url } = await spawnAnvil();
      const { client, test } = clientsFor(url);
      const born = await bornAndFundedAccount(url, client, test, "1");

      const server = await mockServer({
        getPaymasterStubData: () => {
          throw new MockHttpError(500, "provider outage");
        },
      });

      const events: GasFallbackEvent[] = [];
      const policy = new GasPolicy({
        paymasterClient: new Erc7677Client(server.url),
        onFallback: (event) => events.push(event),
      });

      const calls = [{ to: FRESH_RECIPIENT, value: parseEther("0.01"), data: "0x" as Hex }];
      const validUntil = Math.floor(Date.now() / 1000) + 3600;
      const op = await buildUserOp({ account: born.account, client, calls, validUntil });
      const chainId = BigInt(await client.getChainId());

      const plan = await policy.plan(op, { client, entryPoint: ENTRYPOINT, chainId });
      expect(events).toEqual([{ from: "sponsored", to: "selfFunded", cause: PaymasterUnavailableError.name }]);
      if (plan.kind !== "selfFunded") {
        throw new Error(`expected a selfFunded plan, got ${plan.kind}`);
      }
      // No silent decoration: the provider failure must leave the op exactly
      // as buildUserOp produced it, still unpaid by any paymaster.
      expect(plan.op.paymasterAndData).toBe("0x");

      const signed = await signUserOp({
        op: plan.op,
        entryPoint: ENTRYPOINT,
        chainId,
        client,
        signers: [born.paper, born.cloud],
      });
      const txHash = await submitUserOpDirect(client, RELAYER_PK, BENEFICIARY, signed);
      const receipt = await client.waitForTransactionReceipt({ hash: txHash });
      expect(receipt.status).toBe("success");
    },
    60_000,
  );
});
