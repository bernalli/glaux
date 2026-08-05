import { encodePacked, type Hex, type PublicClient } from "viem";
import { describe, expect, it } from "vitest";
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
  MalformedPaymasterFieldError,
  UserOpCostExceedsCapError,
} from "../src/errors.js";
import type { PackedUserOperation } from "../src/execute/userop.js";

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
    // `eth_feeHistory` appends the pending block's base fee, so the LAST entry
    // is what the next block will charge — not the average of the window.
    const baseline = await fetchFeeBaseline(feeHistoryClient([10n, 12n, 14n], [[2n], [6n], [4n]]));

    expect(baseline).toEqual({ baseFeePerGas: 14n, medianPriorityFeePerGas: 4n });
  });

  it("refuses an empty, malformed or unavailable fee history rather than guessing a baseline", async () => {
    // A guessed baseline is worse than none: it would silently authorize
    // whatever the endpoint proposes, which is the hole this guard closes.
    await expect(fetchFeeBaseline(feeHistoryClient([], [[1n]]))).rejects.toBeInstanceOf(FeeBaselineReadError);
    await expect(fetchFeeBaseline(feeHistoryClient([10n], []))).rejects.toBeInstanceOf(FeeBaselineReadError);
    await expect(fetchFeeBaseline(feeHistoryClient(["0x0a"], [[1n]]))).rejects.toBeInstanceOf(FeeBaselineReadError);
    await expect(fetchFeeBaseline(feeHistoryClient([10n], [["0x01"]]))).rejects.toBeInstanceOf(FeeBaselineReadError);
    await expect(fetchFeeBaseline(feeHistoryClient([-1n], [[1n]]))).rejects.toBeInstanceOf(FeeBaselineReadError);
    await expect(
      fetchFeeBaseline({
        getFeeHistory: async () => {
          throw new Error("rpc down");
        },
      } as unknown as PublicClient),
    ).rejects.toBeInstanceOf(FeeBaselineReadError);
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
});

describe("assertUserOpCost", () => {
  it("allows a cap equal to the worst case and refuses one wei below it", () => {
    const op = opWith();
    const cost = computeUserOpMaxCost(op);

    expect(() => assertUserOpCost(op, cost)).not.toThrow();
    expect(() => assertUserOpCost(op, cost - 1n)).toThrow(UserOpCostExceedsCapError);
  });
});
