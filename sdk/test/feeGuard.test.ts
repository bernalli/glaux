import { decodeAbiParameters, encodePacked, type Hex, type PublicClient } from "viem";
import { describe, expect, it } from "vitest";
import { ENTRYPOINT } from "../src/core/constants.js";
import {
  allowedMaxFeePerGas,
  assertFeeWithinBaseline,
  assertUserOpCost,
  computeUserOpMaxCost,
  fetchFeeBaseline,
  userOpMaxFeePerGas,
} from "../src/gas/feeGuard.js";
import {
  FeeBaselineReadError,
  FeeExceedsBaselineError,
  InvalidCostCapError,
  MalformedPackedWordError,
  MalformedPaymasterFieldError,
  UserOpCostExceedsCapError,
} from "../src/errors.js";
import { signUserOp, type PackedUserOperation } from "../src/execute/userop.js";
import { LocalP256Signer } from "../src/signers/p256.js";
import { LocalSecp256k1Signer } from "../src/signers/secp256k1.js";

// The same well-known anvil keys the other suites use for the three factors.
const PAPER_PK: Hex = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const CLOUD_PK: Hex = "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a";
const DEVICE_PK: Hex = "0x7459e13afd9158a379ee75ca9e80a328916dba1473c863f800f51ee5f46eb3ab";

/** Decodes an already-encoded `abi.encode(uint48, SlotSig[2])` blob back into its parts. */
function decodeUserOpSignature(signature: Hex): {
  validUntil: number;
  slotIndices: readonly [number, number];
} {
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
  ) as readonly [number, readonly [{ slotIndex: number }, { slotIndex: number }]];
  return { validUntil, slotIndices: [sigs[0].slotIndex, sigs[1].slotIndex] };
}

/**
 * A client that answers only `eth_feeHistory`. The baseline is deliberately
 * the ONLY thing this module reads from a chain, so a stub this narrow is the
 * whole surface — the same shape `eligibility.test.ts` uses for its
 * transport-failure case.
 */
function feeHistoryClient(baseFeePerGas: unknown, reward: unknown): PublicClient {
  return {
    getFeeHistory: async () => ({ baseFeePerGas, gasUsedRatio: [], oldestBlock: 0n, reward }),
  } as unknown as PublicClient;
}

const GWEI = 1_000_000_000n;

function opWith(fields: Partial<PackedUserOperation> = {}): PackedUserOperation {
  return {
    sender: "0x0000000000000000000000000000000000000001",
    nonce: 0n,
    initCode: "0x",
    callData: "0x",
    accountGasLimits: encodePacked(["uint128", "uint128"], [600_000n, 200_000n]),
    preVerificationGas: 100_000n,
    gasFees: encodePacked(["uint128", "uint128"], [1n * GWEI, 30n * GWEI]),
    paymasterAndData: "0x",
    signature: "0x",
    validUntil: 1,
    ...fields,
  };
}

function paymasterField(verificationGas: bigint, postOpGas: bigint, data: Hex = "0x"): Hex {
  return `${encodePacked(
    ["address", "uint128", "uint128"],
    ["0x00000000000000000000000000000000000000aa", verificationGas, postOpGas],
  )}${data.slice(2)}` as Hex;
}

describe("fetchFeeBaseline", () => {
  it("takes the next block's base fee and the median of the per-block median tips", async () => {
    // A real `eth_feeHistory` over N blocks returns N reward rows and N+1 base
    // fees: the extra trailing one is the pending block's, which is what this
    // operation will actually pay. Three blocks, therefore four base fees.
    const baseline = await fetchFeeBaseline(feeHistoryClient([9n, 10n, 12n, 14n], [[2n], [6n], [4n]]));

    expect(baseline).toEqual({ baseFeePerGas: 14n, medianPriorityFeePerGas: 4n });
  });

  it("accepts a short window, which a young or pruning node may legitimately return", async () => {
    const baseline = await fetchFeeBaseline(feeHistoryClient([10n, 11n], [[3n]]));

    expect(baseline).toEqual({ baseFeePerGas: 11n, medianPriorityFeePerGas: 3n });
  });

  it("refuses a response whose base-fee and reward lengths do not correspond", async () => {
    // The relation is the only thing that identifies the trailing entry as the
    // NEXT block's fee. Without it, a response one entry short would have this
    // code read a mined block's base fee as the pending one — understating the
    // lane, which is the direction a lying endpoint wants.
    await expect(fetchFeeBaseline(feeHistoryClient([10n], [[1n]]))).rejects.toBeInstanceOf(FeeBaselineReadError);
    await expect(
      fetchFeeBaseline(feeHistoryClient([10n, 11n, 12n], [[1n]])),
    ).rejects.toBeInstanceOf(FeeBaselineReadError);
    await expect(
      fetchFeeBaseline(feeHistoryClient([9n, 10n, 11n], [[1n], [2n]])),
    ).resolves.toEqual({ baseFeePerGas: 11n, medianPriorityFeePerGas: 1n });
  });

  it("refuses a reward row that does not carry exactly the one requested percentile", async () => {
    await expect(fetchFeeBaseline(feeHistoryClient([10n, 11n], [[]]))).rejects.toBeInstanceOf(FeeBaselineReadError);
    await expect(
      fetchFeeBaseline(feeHistoryClient([10n, 11n], [[1n, 2n]])),
    ).rejects.toBeInstanceOf(FeeBaselineReadError);
  });

  it("refuses an empty, malformed or unavailable fee history rather than guessing a baseline", async () => {
    // A guessed baseline is worse than none: it would silently authorize
    // whatever the endpoint proposes, which is the hole this guard closes.
    await expect(fetchFeeBaseline(feeHistoryClient([], [[1n]]))).rejects.toBeInstanceOf(FeeBaselineReadError);
    await expect(fetchFeeBaseline(feeHistoryClient([10n], []))).rejects.toBeInstanceOf(FeeBaselineReadError);
    await expect(fetchFeeBaseline(feeHistoryClient(["0x0a", "0x0b"], [[1n]]))).rejects.toBeInstanceOf(
      FeeBaselineReadError,
    );
    await expect(fetchFeeBaseline(feeHistoryClient([10n, 11n], [["0x01"]]))).rejects.toBeInstanceOf(
      FeeBaselineReadError,
    );
    await expect(fetchFeeBaseline(feeHistoryClient([-1n, 11n], [[1n]]))).rejects.toBeInstanceOf(FeeBaselineReadError);
    await expect(
      fetchFeeBaseline({
        getFeeHistory: async () => {
          throw new Error("rpc down");
        },
      } as unknown as PublicClient),
    ).rejects.toBeInstanceOf(FeeBaselineReadError);
  });

  it("asks for the window and percentile it claims to average", async () => {
    // A stub that ignores these arguments would let the implementation request
    // anything at all — one block, the 99th percentile — while the tests kept
    // asserting on values the stub invented.
    let request: { blockCount?: number; rewardPercentiles?: number[] } = {};
    await fetchFeeBaseline({
      getFeeHistory: async (args: { blockCount: number; rewardPercentiles: number[] }) => {
        request = args;
        return { baseFeePerGas: [1n, 2n], gasUsedRatio: [], oldestBlock: 0n, reward: [[1n]] };
      },
    } as unknown as PublicClient);

    expect(request.blockCount).toBe(5);
    expect(request.rewardPercentiles).toEqual([50]);
  });
});

describe("assertFeeWithinBaseline", () => {
  const baseline = { baseFeePerGas: 10n * GWEI, medianPriorityFeePerGas: 1n * GWEI };

  it("allows the sanity multiple exactly and refuses one wei past it", () => {
    // (10 * 2 + 1) * 3 = 63 gwei: the same lane `buildUserOp` computes,
    // scaled by the sanity multiple.
    const allowed = allowedMaxFeePerGas(baseline);
    expect(allowed).toBe(63n * GWEI);

    expect(() => assertFeeWithinBaseline(allowed, baseline)).not.toThrow();
    expect(() => assertFeeWithinBaseline(allowed + 1n, baseline)).toThrow(FeeExceedsBaselineError);
  });

  it("refuses the anomaly this guard exists for: a 100x fee against a healthy baseline", () => {
    expect(() => assertFeeWithinBaseline(2_100n * GWEI, baseline)).toThrow(FeeExceedsBaselineError);
  });

  it("honours a caller-tightened multiple", () => {
    expect(() => assertFeeWithinBaseline(22n * GWEI, baseline, 1n)).toThrow(FeeExceedsBaselineError);
    expect(() => assertFeeWithinBaseline(21n * GWEI, baseline, 1n)).not.toThrow();
  });
});

describe("computeUserOpMaxCost", () => {
  it("prices every gas dimension at maxFeePerGas", () => {
    expect(userOpMaxFeePerGas(opWith())).toBe(30n * GWEI);
    expect(computeUserOpMaxCost(opWith())).toBe(900_000n * 30n * GWEI);
  });

  it("includes the paymaster's own two gas limits, which the account still underwrites", () => {
    // The EntryPoint's required prefund covers the paymaster's verification
    // and postOp gas too. Omitting them would let a sponsored op slip past a
    // cap it actually exceeds.
    const sponsored = opWith({ paymasterAndData: paymasterField(40_000n, 10_000n) });

    expect(computeUserOpMaxCost(sponsored)).toBe(950_000n * 30n * GWEI);
  });

  it("reads the paymaster limits past a trailing opaque payload", () => {
    const sponsored = opWith({ paymasterAndData: paymasterField(40_000n, 10_000n, "0xdeadbeef") });

    expect(computeUserOpMaxCost(sponsored)).toBe(950_000n * 30n * GWEI);
  });

  it("refuses a paymaster field too short to carry its gas limits instead of pricing it as free", () => {
    const malformed = opWith({ paymasterAndData: "0x00000000000000000000000000000000000000aa" });

    expect(() => computeUserOpMaxCost(malformed)).toThrow(MalformedPaymasterFieldError);
  });

  it("refuses a short packed word rather than reading it as a small number", () => {
    // `hexToBigInt` reads a 31-byte word left-padded; ABI encoding reads
    // `bytes32` right-padded. The same bytes would mean one fee here and 256
    // times that on chain, so the ambiguity is refused instead of resolved.
    const shortFees = opWith({ gasFees: `0x${"11".repeat(31)}` });
    const shortLimits = opWith({ accountGasLimits: `0x${"22".repeat(31)}` });

    expect(() => computeUserOpMaxCost(shortFees)).toThrow(MalformedPackedWordError);
    expect(() => userOpMaxFeePerGas(shortFees)).toThrow(MalformedPackedWordError);
    expect(() => computeUserOpMaxCost(shortLimits)).toThrow(MalformedPackedWordError);
  });
});

describe("assertUserOpCost", () => {
  it("allows a cap equal to the worst case and refuses one wei below it", () => {
    const op = opWith();
    const cost = computeUserOpMaxCost(op);

    expect(() => assertUserOpCost(op, cost)).not.toThrow();
    expect(() => assertUserOpCost(op, cost - 1n)).toThrow(UserOpCostExceedsCapError);
  });
});

/**
 * The guard's only job is to stand between an operation and the quorum's
 * signature, so every test here asserts on what `signUserOp` does BEFORE any
 * factor signs — a refusal that arrives after the signature exists would be no
 * protection at all.
 */
describe("signUserOp enforcement", () => {
  const paper = new LocalSecp256k1Signer(PAPER_PK);
  const device = new LocalP256Signer(DEVICE_PK);
  const cloud = new LocalSecp256k1Signer(CLOUD_PK);
  const installedSlots = [paper, device, cloud];
  const HEALTHY_BASELINE = { baseFeePerGas: 10n * GWEI, medianPriorityFeePerGas: 1n * GWEI };

  /**
   * A factor that records whether it was ever asked to sign. Asserting on the
   * rejection alone would stay green if the guards moved AFTER the signatures
   * were produced — the one arrangement that would defeat their whole purpose,
   * since a signature that exists has already left the process.
   */
  function watchedSigner(inner: LocalSecp256k1Signer): { signer: LocalSecp256k1Signer; signed: () => boolean } {
    let signed = false;
    const signer = Object.create(inner) as LocalSecp256k1Signer;
    signer.sign = async (digest: Hex) => {
      signed = true;
      return inner.sign(digest);
    };
    return { signer, signed: () => signed };
  }

  /** Answers the slot reads `signUserOp` performs, and counts every RPC touch. */
  function accountClient(feeHistory?: { baseFeePerGas: bigint[]; reward: bigint[][] }): {
    client: PublicClient;
    calls: () => number;
    feeHistoryCalls: () => number;
  } {
    let calls = 0;
    let feeHistoryCalls = 0;
    const client = {
      getBlockNumber: async () => {
        calls += 1;
        return 123n;
      },
      readContract: async ({ args }: { args?: readonly number[] }) => {
        calls += 1;
        const signer = installedSlots[args![0]!]!;
        return [signer.verifierType, signer.keyData()];
      },
      getFeeHistory: async () => {
        calls += 1;
        feeHistoryCalls += 1;
        if (feeHistory === undefined) throw new Error("fee history not stubbed");
        return { ...feeHistory, gasUsedRatio: [], oldestBlock: 0n };
      },
    } as unknown as PublicClient;
    return { client, calls: () => calls, feeHistoryCalls: () => feeHistoryCalls };
  }

  function signable(): PackedUserOperation {
    return opWith({ validUntil: Math.floor(Date.now() / 1000) + 600 });
  }

  it("refuses a cost above the caller's cap without touching the network or a signer", async () => {
    const { client, calls } = accountClient();
    const op = signable();
    const watchedPaper = watchedSigner(paper);
    const watchedCloud = watchedSigner(cloud);

    await expect(
      signUserOp({
        op,
        entryPoint: ENTRYPOINT,
        chainId: 31337n,
        client,
        maxCostWei: computeUserOpMaxCost(op) - 1n,
        feeBaseline: HEALTHY_BASELINE,
        signers: [watchedPaper.signer, watchedCloud.signer],
      }),
    ).rejects.toBeInstanceOf(UserOpCostExceedsCapError);

    // The cap needs no chain state, so a doomed operation costs nothing to
    // refuse — and, decisively, no factor was ever asked to sign.
    expect(calls()).toBe(0);
    expect(watchedPaper.signed()).toBe(false);
    expect(watchedCloud.signed()).toBe(false);
  });

  it("refuses a cap that is absent or not a bigint, which the type system cannot enforce at runtime", async () => {
    // A JavaScript consumer of the published package omits the argument and
    // gets `undefined`; `cost > undefined` is `false`, so without an explicit
    // check the operation would be signed with no bound at all.
    const { client } = accountClient();
    const op = signable();
    const watched = watchedSigner(paper);
    const invalidCaps = [undefined, null, 0, 1e18, Number.NaN, Infinity, "1000", {}];

    for (const cap of invalidCaps) {
      await expect(
        signUserOp({
          op,
          entryPoint: ENTRYPOINT,
          chainId: 31337n,
          client,
          maxCostWei: cap as unknown as bigint,
          feeBaseline: HEALTHY_BASELINE,
          signers: [watched.signer, cloud],
        }),
      ).rejects.toBeInstanceOf(InvalidCostCapError);
    }
    expect(watched.signed()).toBe(false);

    // A cap of zero wei IS valid — it refuses every non-free operation, which
    // is a coherent thing for a caller to ask for.
    await expect(
      signUserOp({
        op,
        entryPoint: ENTRYPOINT,
        chainId: 31337n,
        client,
        maxCostWei: 0n,
        feeBaseline: HEALTHY_BASELINE,
        signers: [paper, cloud],
      }),
    ).rejects.toBeInstanceOf(UserOpCostExceedsCapError);
  });

  /**
   * The checks and the hashing are separated by two awaits, and the caller
   * keeps a reference to the object throughout. Validating a cost on an object
   * someone else can still edit, then signing that same object, bounds nothing.
   */
  it("signs the operation it checked, not the caller's object as it stands later", async () => {
    // A healthy baseline, so the only thing that could refuse this operation is
    // the cap — and the fee history read is the await the mutation slips into.
    const { client } = accountClient({ baseFeePerGas: [100n * GWEI, 100n * GWEI], reward: [[10n * GWEI]] });
    const op = { ...signable() };
    const cheapFees = op.gasFees;
    const cap = computeUserOpMaxCost(op);

    const signing = signUserOp({
      op,
      entryPoint: ENTRYPOINT,
      chainId: 31337n,
      client,
      maxCostWei: cap,
      // No baseline supplied, so the guard awaits `getFeeHistory` — the window
      // in which the caller's object can change under it.
      signers: [paper, cloud],
    });
    // Mutate while that await is outstanding: a hundredfold fee increase.
    (op as { gasFees: Hex }).gasFees = encodePacked(["uint128", "uint128"], [1n * GWEI, 3_000n * GWEI]);

    const signed = await signing;

    expect(signed.gasFees).toBe(cheapFees);
    expect(computeUserOpMaxCost(signed)).toBeLessThanOrEqual(cap);
  });

  it("refuses a fee beyond the sanity multiple of the baseline it was given", async () => {
    const { client } = accountClient();
    const op = signable();

    await expect(
      signUserOp({
        op,
        entryPoint: ENTRYPOINT,
        chainId: 31337n,
        client,
        maxCostWei: computeUserOpMaxCost(op),
        // Baseline says ~1 gwei is the going rate; the operation asks 30.
        feeBaseline: { baseFeePerGas: 1n * GWEI, medianPriorityFeePerGas: 0n },
        signers: [paper, cloud],
      }),
    ).rejects.toBeInstanceOf(FeeExceedsBaselineError);
  });

  it("reads the baseline from the chain when the caller supplies none", async () => {
    const { client, feeHistoryCalls } = accountClient({ baseFeePerGas: [1n * GWEI, 1n * GWEI], reward: [[0n]] });
    const op = signable();

    await expect(
      signUserOp({
        op,
        entryPoint: ENTRYPOINT,
        chainId: 31337n,
        client,
        maxCostWei: computeUserOpMaxCost(op),
        signers: [paper, cloud],
      }),
    ).rejects.toBeInstanceOf(FeeExceedsBaselineError);
    expect(feeHistoryCalls()).toBe(1);
  });

  it("propagates an unreadable fee history instead of signing at the proposed fee", async () => {
    const { client } = accountClient();
    const op = signable();

    await expect(
      signUserOp({
        op,
        entryPoint: ENTRYPOINT,
        chainId: 31337n,
        client,
        maxCostWei: computeUserOpMaxCost(op),
        signers: [paper, cloud],
      }),
    ).rejects.toBeInstanceOf(FeeBaselineReadError);
  });

  it("signs once the cap and the baseline both allow the operation", async () => {
    const { client } = accountClient();
    const op = signable();

    const signed = await signUserOp({
      op,
      entryPoint: ENTRYPOINT,
      chainId: 31337n,
      client,
      maxCostWei: computeUserOpMaxCost(op),
      feeBaseline: HEALTHY_BASELINE,
      signers: [paper, cloud],
    });

    const decoded = decodeUserOpSignature(signed.signature);
    expect(decoded.slotIndices).toEqual([0, 2]);
    expect(decoded.validUntil).toBe(op.validUntil);
  });
});
