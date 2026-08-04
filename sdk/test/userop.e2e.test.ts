import { describe, expect, it } from "vitest";
import { decodeAbiParameters, parseEther, type Address, type Hex, type PublicClient } from "viem";
import { ENTRYPOINT } from "../src/core/constants.js";
import { buildBirthBlob } from "../src/birth/blob.js";
import { submitBirth } from "../src/birth/submit.js";
import { encodeUserOpSignature } from "../src/core/encoding.js";
import type { SlotSig } from "../src/core/types.js";
import {
  DEFAULT_EXECUTION_VALIDITY_WINDOW_SECONDS,
} from "../src/execute/direct.js";
import {
  buildUserOp,
  computeUserOpHash,
  extractUserOperationEvent,
  fetchEntryPointDeposit,
  fetchUserOpHash,
  signUserOp,
  submitUserOpDirect,
  type PackedUserOperation,
} from "../src/execute/userop.js";
import {
  ExecutionNonceMismatchError,
  ExecutionValidityWindowError,
  OperationExpiredError,
  UserOpEventNotFoundError,
  UserOpExecutionFailedError,
  UserOpFailedError,
  UserOpGasValueOutOfRangeError,
} from "../src/errors.js";
import { LocalP256Signer } from "../src/signers/p256.js";
import { LocalSecp256k1Signer } from "../src/signers/secp256k1.js";
import { clientsFor, spawnAnvil } from "./helpers/anvil.js";
import { deployCanonical, deployEntryPoint, deployP256Oracle } from "./helpers/deploy.js";

/**
 * Same well-known anvil accounts `sdk/test/execute.e2e.test.ts` uses (see its
 * comment for provenance) for the deployer/paper/cloud/device roles, plus
 * anvil's account #3 as a RELAYER distinct from every factor and from the
 * deployer, and a synthetic BENEFICIARY address that holds no key at all —
 * `handleOps`' beneficiary only ever RECEIVES value, it never signs anything.
 */
const DEPLOYER_PK: Hex = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const PAPER_PK: Hex = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const CLOUD_PK: Hex = "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a";
const DEVICE_PK: Hex = "0x7459e13afd9158a379ee75ca9e80a328916dba1473c863f800f51ee5f46eb3ab";
const RELAYER_PK: Hex = "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6";
const BENEFICIARY: Address = "0x000000000000000000000000000000000000beef";

const FRESH_RECIPIENT: Address = "0x000000000000000000000000000000000000f00d";
const REVERTING_TARGET: Address = "0x000000000000000000000000000000000000c0de";
const STUB_ACCOUNT: Address = "0x1111111111111111111111111111111111111111";
const STUB_TX_HASH: Hex = "0x1111111111111111111111111111111111111111111111111111111111111111";
const STUB_ENTRYPOINT_NONCE_SLOT: Hex = "0x53576231d24dd226f8944f9473fe29cd80ca059775ce9d983d1726c8fe5174a6";

interface BornAccount {
  readonly account: Address;
  readonly paper: LocalSecp256k1Signer;
  readonly device: LocalP256Signer;
  readonly cloud: LocalSecp256k1Signer;
}

/**
 * Births a fresh account and funds it with `fundEth` ETH via anvil's
 * `setBalance`, with BOTH the P-256 oracle (needed to verify the device
 * factor's possession proof during birth) and a real, vendored EntryPoint
 * v0.7 etched at its canonical address — see `deployP256Oracle`/
 * `deployEntryPoint` (`./helpers/deploy.js`) for why each is etched rather
 * than deployed.
 */
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
  await submitBirth(client, DEPLOYER_PK, blob, 31337);
  await test.setBalance({ address: blob.account, value: parseEther(fundEth) });

  return { account: blob.account, paper, device, cloud };
}

/** Decodes an already-encoded `abi.encode(uint48, SlotSig[2])` blob back into its parts. */
function decodeUserOpSignature(signature: Hex): { validUntil: number; sigs: [SlotSig, SlotSig] } {
  const [validUntil, sigs] = decodeAbiParameters(
    [
      { type: "uint48" },
      {
        type: "tuple[2]",
        components: [
          { name: "slotIndex", type: "uint8" },
          { name: "signature", type: "bytes" },
        ],
      },
    ],
    signature,
  ) as [number, readonly [{ slotIndex: number; signature: Hex }, { slotIndex: number; signature: Hex }]];
  return { validUntil, sigs: [sigs[0], sigs[1]] };
}

function stubUserOp(nonce: bigint, validUntil: number): PackedUserOperation {
  return {
    sender: STUB_ACCOUNT,
    nonce,
    initCode: "0x",
    callData: "0x",
    accountGasLimits: `0x${"00".repeat(32)}`,
    preVerificationGas: 0n,
    gasFees: `0x${"00".repeat(32)}`,
    paymasterAndData: "0x",
    signature: "0x",
    validUntil,
  };
}

describe("userop build/sign fail-closed guards", () => {
  it("rejects validUntil === 0 client-side before any RPC call is made", async () => {
    let requestsIssued = 0;
    const stubClient = {
      readContract: async () => {
        requestsIssued += 1;
        return 0n;
      },
      getBlock: async () => {
        requestsIssued += 1;
        return { baseFeePerGas: 1n };
      },
      getGasPrice: async () => {
        requestsIssued += 1;
        return 1n;
      },
      estimateMaxPriorityFeePerGas: async () => {
        requestsIssued += 1;
        return 1n;
      },
      estimateGas: async () => {
        requestsIssued += 1;
        return 1n;
      },
    } as unknown as PublicClient;

    await expect(
      buildUserOp({
        account: STUB_ACCOUNT,
        client: stubClient,
        calls: [{ to: FRESH_RECIPIENT, value: 0n, data: "0x" }],
        validUntil: 0,
      }),
    ).rejects.toThrow(OperationExpiredError);

    expect(requestsIssued).toBe(0);
  });

  it("rejects a deadline beyond the default local validity ceiling before any RPC call", async () => {
    let requestsIssued = 0;
    const stubClient = {
      getBlockNumber: async () => {
        requestsIssued += 1;
        return 123n;
      },
    } as unknown as PublicClient;

    await expect(
      buildUserOp({
        account: STUB_ACCOUNT,
        client: stubClient,
        calls: [{ to: FRESH_RECIPIENT, value: 0n, data: "0x" }],
        validUntil: Math.floor(Date.now() / 1000) + DEFAULT_EXECUTION_VALIDITY_WINDOW_SECONDS + 60,
      }),
    ).rejects.toBeInstanceOf(ExecutionValidityWindowError);

    expect(requestsIssued).toBe(0);
  });

  it("builds past the one-hour default when the caller explicitly widens the validity window", async () => {
    const stubClient = {
      readContract: async () => 0n,
      getBlockNumber: async () => 123n,
      getStorageAt: async () => `0x${"00".repeat(32)}` as Hex,
      getBlock: async () => ({ baseFeePerGas: 1n }),
      getGasPrice: async () => 1n,
      estimateMaxPriorityFeePerGas: async () => 1n,
      estimateGas: async () => 21_000n,
    } as unknown as PublicClient;
    const calls = [{ to: FRESH_RECIPIENT, value: 0n, data: "0x" as Hex }];
    const validUntil = Math.floor(Date.now() / 1000) + DEFAULT_EXECUTION_VALIDITY_WINDOW_SECONDS * 2;

    const op = await buildUserOp({
      account: STUB_ACCOUNT,
      client: stubClient,
      calls,
      validUntil,
      maxValidityWindowSeconds: DEFAULT_EXECUTION_VALIDITY_WINDOW_SECONDS * 4,
    });

    // The widened deadline survives into the built operation: an ignored
    // override, or a ceiling nailed to one hour, would break every legitimate
    // long-deadline integration while the refusal-only tests stayed green.
    expect(op.validUntil).toBe(validUntil);

    // Non-vacuity: the identical deadline is refused without the override.
    await expect(
      buildUserOp({ account: STUB_ACCOUNT, client: stubClient, calls, validUntil }),
    ).rejects.toBeInstanceOf(ExecutionValidityWindowError);
  });

  it("signs past the one-hour default when the caller explicitly widens the validity window", async () => {
    const paper = new LocalSecp256k1Signer(PAPER_PK);
    const device = new LocalP256Signer(DEVICE_PK);
    const cloud = new LocalSecp256k1Signer(CLOUD_PK);
    const slots = [paper, device, cloud];
    const client = {
      getBlockNumber: async () => 123n,
      readContract: async ({ args }: { args?: readonly number[] }) => {
        const signer = slots[args![0]!]!;
        return [signer.verifierType, signer.keyData()];
      },
    } as unknown as PublicClient;
    const validUntil = Math.floor(Date.now() / 1000) + DEFAULT_EXECUTION_VALIDITY_WINDOW_SECONDS * 2;

    const signed = await signUserOp({
      op: stubUserOp(0n, validUntil),
      entryPoint: ENTRYPOINT,
      chainId: 31337n,
      client,
      maxValidityWindowSeconds: DEFAULT_EXECUTION_VALIDITY_WINDOW_SECONDS * 4,
      signers: [paper, cloud],
    });

    // The widened deadline is what the factors actually committed to: it is
    // read back out of the encoded `abi.encode(uint48, SlotSig[2])` blob the
    // account will decode, not merely off the returned operation.
    const decoded = decodeUserOpSignature(signed.signature);
    expect(decoded.validUntil).toBe(validUntil);
    expect([decoded.sigs[0].slotIndex, decoded.sigs[1].slotIndex]).toEqual([0, 2]);

    // Non-vacuity: the identical deadline is refused without the override.
    await expect(
      signUserOp({
        op: stubUserOp(0n, validUntil),
        entryPoint: ENTRYPOINT,
        chainId: 31337n,
        client,
        signers: [paper, cloud],
      }),
    ).rejects.toBeInstanceOf(ExecutionValidityWindowError);
  });

  it("rechecks the local validity ceiling when signing an externally supplied UserOperation", async () => {
    let requestsIssued = 0;
    const client = {
      getBlockNumber: async () => {
        requestsIssued += 1;
        return 123n;
      },
    } as unknown as PublicClient;

    await expect(
      signUserOp({
        op: stubUserOp(
          0n,
          Math.floor(Date.now() / 1000) + DEFAULT_EXECUTION_VALIDITY_WINDOW_SECONDS + 60,
        ),
        entryPoint: ENTRYPOINT,
        chainId: 31337n,
        client,
        signers: [new LocalSecp256k1Signer(PAPER_PK), new LocalSecp256k1Signer(CLOUD_PK)],
      }),
    ).rejects.toBeInstanceOf(ExecutionValidityWindowError);
    expect(requestsIssued).toBe(0);
  });

  it("checks an independent expectedNonce again at UserOperation signing time", async () => {
    let requestsIssued = 0;
    const client = {
      getBlockNumber: async () => {
        requestsIssued += 1;
        return 123n;
      },
    } as unknown as PublicClient;

    await expect(
      signUserOp({
        op: stubUserOp(1n, 1),
        entryPoint: ENTRYPOINT,
        chainId: 31337n,
        client,
        expectedNonce: 0n,
        signers: [new LocalSecp256k1Signer(PAPER_PK), new LocalSecp256k1Signer(CLOUD_PK)],
      }),
    ).rejects.toMatchObject({
      name: "ExecutionNonceMismatchError",
      path: "erc4337",
      source: "caller expectation",
      expected: 0n,
      actual: 1n,
    } satisfies Partial<ExecutionNonceMismatchError>);
    expect(requestsIssued).toBe(0);
  });

  it("rejects an EntryPoint future-nonce getter lie that disagrees with the same-block raw mapping", async () => {
    const stubClient = {
      getBlockNumber: async () => 123n,
      // Both nonce views must be read at the SAME pinned block, so the getter
      // read asserts its own `blockNumber` exactly as `getStorageAt` does
      // below: a getter read that silently drifted to "latest" would compare
      // two different blocks and turn this cross-check into noise.
      readContract: async ({
        address,
        functionName,
        blockNumber,
      }: {
        address: Address;
        functionName: string;
        blockNumber?: bigint;
      }) => {
        expect(address).toBe(ENTRYPOINT);
        expect(functionName).toBe("getNonce");
        expect(blockNumber).toBe(123n);
        return 1n;
      },
      getStorageAt: async ({ address, slot, blockNumber }: { address: Address; slot: Hex; blockNumber?: bigint }) => {
        expect(address).toBe(ENTRYPOINT);
        expect(slot).toBe(STUB_ENTRYPOINT_NONCE_SLOT);
        expect(blockNumber).toBe(123n);
        return `0x${"00".repeat(32)}` as Hex;
      },
      getBlock: async () => ({ baseFeePerGas: 1n }),
      getGasPrice: async () => 1n,
      estimateMaxPriorityFeePerGas: async () => 1n,
      estimateGas: async () => 1n,
    } as unknown as PublicClient;

    await expect(
      buildUserOp({
        account: STUB_ACCOUNT,
        client: stubClient,
        calls: [{ to: FRESH_RECIPIENT, value: 0n, data: "0x" }],
        validUntil: 1,
      }),
    ).rejects.toMatchObject({
      name: "ExecutionNonceMismatchError",
      path: "erc4337",
      source: "raw storage",
      expected: 0n,
      actual: 1n,
    } satisfies Partial<ExecutionNonceMismatchError>);
  });

  it("rejects consistently forged EntryPoint nonce views against an independent expectedNonce", async () => {
    const stubClient = {
      getBlockNumber: async () => 123n,
      readContract: async () => 1n,
      getStorageAt: async () => `0x${"00".repeat(31)}01` as Hex,
      getBlock: async () => ({ baseFeePerGas: 1n }),
      getGasPrice: async () => 1n,
      estimateMaxPriorityFeePerGas: async () => 1n,
      estimateGas: async () => 1n,
    } as unknown as PublicClient;

    await expect(
      buildUserOp({
        account: STUB_ACCOUNT,
        client: stubClient,
        expectedNonce: 0n,
        calls: [{ to: FRESH_RECIPIENT, value: 0n, data: "0x" }],
        validUntil: 1,
      }),
    ).rejects.toMatchObject({
      name: "ExecutionNonceMismatchError",
      path: "erc4337",
      source: "caller expectation",
      expected: 0n,
      actual: 1n,
    } satisfies Partial<ExecutionNonceMismatchError>);
  });

  it("pins all ERC-4337 factor-slot reads to one uncached snapshot block", async () => {
    const paper = new LocalSecp256k1Signer(PAPER_PK);
    const device = new LocalP256Signer(DEVICE_PK);
    const cloud = new LocalSecp256k1Signer(CLOUD_PK);
    const slots = [paper, device, cloud];
    const slotReadBlocks: bigint[] = [];
    const snapshotCacheTimes: number[] = [];
    const stubClient = {
      getBlockNumber: async ({ cacheTime }: { cacheTime?: number } = {}) => {
        snapshotCacheTimes.push(cacheTime!);
        return 123n;
      },
      readContract: async ({
        functionName,
        args,
        blockNumber,
      }: {
        functionName: string;
        args?: readonly number[];
        blockNumber?: bigint;
      }) => {
        if (functionName === "getNonce") return 0n;
        const index = args?.[0];
        slotReadBlocks.push(blockNumber!);
        const signer = slots[index!];
        return [signer!.verifierType, signer!.keyData()];
      },
      getStorageAt: async () => `0x${"00".repeat(32)}` as Hex,
      getBlock: async () => ({ baseFeePerGas: 1n }),
      getGasPrice: async () => 1n,
      estimateMaxPriorityFeePerGas: async () => 1n,
      estimateGas: async () => 1n,
    } as unknown as PublicClient;
    const op = await buildUserOp({
      account: STUB_ACCOUNT,
      client: stubClient,
      calls: [{ to: FRESH_RECIPIENT, value: 0n, data: "0x" }],
      validUntil: 1,
    });

    await signUserOp({
      op,
      entryPoint: ENTRYPOINT,
      chainId: 31337n,
      client: stubClient,
      signers: [paper, cloud],
    });

    expect(slotReadBlocks).toEqual([123n, 123n, 123n]);
    expect(snapshotCacheTimes).toEqual([0, 0]);
  });

  it("refuses a buffered EntryPoint gas field above uint120 before ABI encoding", async () => {
    const stubClient = {
      readContract: async () => 0n,
      getBlockNumber: async () => 123n,
      getStorageAt: async () => `0x${"00".repeat(32)}` as Hex,
      getBlock: async () => ({ baseFeePerGas: 1n }),
      getGasPrice: async () => 1n,
      estimateMaxPriorityFeePerGas: async () => 1n,
      estimateGas: async () => 1n << 120n,
    } as unknown as PublicClient;

    await expect(
      buildUserOp({
        account: STUB_ACCOUNT,
        client: stubClient,
        calls: [{ to: FRESH_RECIPIENT, value: 0n, data: "0x" }],
        validUntil: 1,
      }),
    ).rejects.toBeInstanceOf(UserOpGasValueOutOfRangeError);
  });

  it("keeps a missing submitted-operation event typed and correlated to its transaction", () => {
    const userOpHash = "0x2222222222222222222222222222222222222222222222222222222222222222" as Hex;

    expect(() => extractUserOperationEvent([], userOpHash, STUB_TX_HASH)).toThrow(UserOpEventNotFoundError);
    try {
      extractUserOperationEvent([], userOpHash, STUB_TX_HASH);
    } catch (error) {
      expect(error).toMatchObject({ userOpHash, txHash: STUB_TX_HASH });
    }
  });
});

describe("userop e2e: self-funded ERC-4337 path against a real EntryPoint v0.7", () => {
  it(
    "a self-funded userOp transfers value through handleOps, the account bears the real cost, " +
      "and the locally computed userOpHash matches the EntryPoint's own",
    async () => {
      const { url } = await spawnAnvil();
      const { client, test } = clientsFor(url);
      const born = await bornAndFundedAccount(url, client, test, "1");

      const accountNativeBefore = await client.getBalance({ address: born.account });
      const accountDepositBefore = await fetchEntryPointDeposit(client, ENTRYPOINT, born.account);
      const recipientBalanceBefore = await client.getBalance({ address: FRESH_RECIPIENT });
      const beneficiaryBalanceBefore = await client.getBalance({ address: BENEFICIARY });
      expect(accountDepositBefore).toBe(0n);

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

      // Cross-check: the locally computed userOpHash must equal the real,
      // etched EntryPoint's own `getUserOpHash` for the identical op.
      const localHash = computeUserOpHash(signed, ENTRYPOINT, chainId);
      const onChainHash = await fetchUserOpHash(client, ENTRYPOINT, signed);
      expect(localHash).toBe(onChainHash);

      const txHash = await submitUserOpDirect(client, RELAYER_PK, BENEFICIARY, signed);
      const receipt = await client.waitForTransactionReceipt({ hash: txHash });
      expect(receipt.status).toBe("success");

      const event = extractUserOperationEvent(receipt.logs, onChainHash);
      expect(event.success).toBe(true);
      expect(event.actualGasCost).toBeGreaterThan(0n);

      const accountNativeAfter = await client.getBalance({ address: born.account });
      const accountDepositAfter = await fetchEntryPointDeposit(client, ENTRYPOINT, born.account);
      const recipientBalanceAfter = await client.getBalance({ address: FRESH_RECIPIENT });
      const beneficiaryBalanceAfter = await client.getBalance({ address: BENEFICIARY });

      // The recipient gained exactly the transferred amount.
      expect(recipientBalanceAfter - recipientBalanceBefore).toBe(transferValue);

      // The BENEFICIARY (the relayer's chosen payee, not the relayer itself)
      // received exactly the actualGasCost the EntryPoint's own event reports
      // — read from the event, never inferred from the receipt's aggregate gas.
      expect(beneficiaryBalanceAfter - beneficiaryBalanceBefore).toBe(event.actualGasCost);

      // The account's native balance dropped by the transfer PLUS the full
      // self-funded prefund (`missingAccountFunds`, GlauxAccount.validateUserOp
      // src/GlauxAccount.sol:294-311) — not merely the actual gas cost, because
      // EntryPoint v0.7 credits any unused prefund BACK to the account as an
      // EntryPoint-internal deposit (`_postExecution`,
      // lib/account-abstraction/contracts/core/EntryPoint.sol:730-748) rather
      // than returning it to native balance. That deposit is still the
      // account's own asset (withdrawable later), so the account's true
      // economic cost is (native balance decrease) MINUS (deposit increase),
      // which must equal exactly transferValue + actualGasCost regardless of
      // how generously buildUserOp's gas limits were estimated.
      const nativeDecrease = accountNativeBefore - accountNativeAfter;
      const depositIncrease = accountDepositAfter - accountDepositBefore;
      expect(nativeDecrease - depositIncrease).toBe(transferValue + event.actualGasCost);

      // Non-vacuity: the deposit increase must be strictly positive, proving
      // the assertion above is doing real work (reconciling a genuine,
      // non-zero refund-to-deposit) rather than coincidentally degenerating
      // to "native balance dropped by exactly transferValue + actualGasCost"
      // on its own, which would also pass a naive (and generally wrong) check.
      expect(depositIncrease).toBeGreaterThan(0n);
      expect(nativeDecrease).toBeGreaterThan(transferValue + event.actualGasCost);
    },
    60_000,
  );

  it(
    "a validUntil edited AFTER signing fails validation with the EntryPoint's AA24 signature error",
    async () => {
      const { url } = await spawnAnvil();
      const { client, test } = clientsFor(url);
      const born = await bornAndFundedAccount(url, client, test, "1");

      const calls = [{ to: FRESH_RECIPIENT, value: parseEther("0.01"), data: "0x" as Hex }];
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

      // Tamper with validUntil AFTER signing, using the SAME (unchanged)
      // signatures: the factors signed over `(userOpHash, validUntil)`
      // (`../core/digests.js`'s `userOpDigest`), so re-encoding the identical
      // sigs under a different validUntil produces a blob whose digest no
      // longer matches what was actually signed.
      const { sigs } = decodeUserOpSignature(signed.signature);
      const tamperedValidUntil = validUntil + 1;
      const tamperedOp: PackedUserOperation = {
        ...signed,
        signature: encodeUserOpSignature(tamperedValidUntil, sigs),
      };

      let thrown: unknown;
      try {
        await submitUserOpDirect(client, RELAYER_PK, BENEFICIARY, tamperedOp);
      } catch (error) {
        thrown = error;
      }

      expect(thrown).toBeInstanceOf(UserOpFailedError);
      const error = thrown as UserOpFailedError;
      expect(error.reason).toBe("AA24 signature error");
    },
    60_000,
  );

  it(
    "throws a typed error when EntryPoint records the submitted operation as reverted",
    async () => {
      const { url } = await spawnAnvil();
      const { client, test } = clientsFor(url);
      const born = await bornAndFundedAccount(url, client, test, "1");
      // Start as STOP so buildUserOp's deliberately fail-closed estimate can
      // succeed, then switch to REVERT after the operation is signed. This
      // models an inclusion-time target change without weakening that guard.
      await test.setCode({ address: REVERTING_TARGET, bytecode: "0x00" });

      const op = await buildUserOp({
        account: born.account,
        client,
        calls: [{ to: REVERTING_TARGET, value: 0n, data: "0x" }],
        validUntil: Math.floor(Date.now() / 1000) + 3600,
      });
      const chainId = BigInt(await client.getChainId());
      const signed = await signUserOp({
        op,
        entryPoint: ENTRYPOINT,
        chainId,
        client,
        signers: [born.paper, born.cloud],
      });
      const userOpHash = computeUserOpHash(signed, ENTRYPOINT, chainId);
      // PUSH1 0x00, PUSH1 0x00, REVERT: execution reaches the account, but
      // EntryPoint deliberately catches the account-call failure and emits a
      // successful outer receipt with UserOperationEvent(success=false).
      await test.setCode({ address: REVERTING_TARGET, bytecode: "0x60006000fd" });

      let thrown: unknown;
      try {
        await submitUserOpDirect(client, RELAYER_PK, BENEFICIARY, signed);
      } catch (error) {
        thrown = error;
      }

      expect(thrown).toBeInstanceOf(UserOpExecutionFailedError);
      const error = thrown as UserOpExecutionFailedError;
      expect(error.userOpHash).toBe(userOpHash);
      const receipt = await client.waitForTransactionReceipt({ hash: error.txHash });
      expect(receipt.status).toBe("success");
      expect(extractUserOperationEvent(receipt.logs, userOpHash).success).toBe(false);
    },
    60_000,
  );

  it(
    "an expired validUntil is genuinely signed and submitted, and the EntryPoint's own AA22 rejects it",
    async () => {
      const { url } = await spawnAnvil();
      const { client, test } = clientsFor(url);
      const born = await bornAndFundedAccount(url, client, test, "1");

      const pastValidUntil = 1; // 1970-01-01T00:00:01Z: expired on every real chain.
      const calls = [{ to: FRESH_RECIPIENT, value: parseEther("0.01"), data: "0x" as Hex }];

      const op = await buildUserOp({ account: born.account, client, calls, validUntil: pastValidUntil });
      const chainId = BigInt(await client.getChainId());
      const signed = await signUserOp({
        op,
        entryPoint: ENTRYPOINT,
        chainId,
        client,
        signers: [born.paper, born.cloud],
      });

      let thrown: unknown;
      try {
        await submitUserOpDirect(client, RELAYER_PK, BENEFICIARY, signed);
      } catch (error) {
        thrown = error;
      }

      expect(thrown).toBeInstanceOf(UserOpFailedError);
      const error = thrown as UserOpFailedError;
      // The genuine EntryPoint diagnostic, not merely "something threw": a
      // validly-signed but time-expired operation is rejected with the
      // EntryPoint's own "AA22 expired or not due", distinct from "AA24
      // signature error" (a bad/tampered quorum) asserted in the sibling test.
      expect(error.reason).toBe("AA22 expired or not due");
    },
    60_000,
  );
});
