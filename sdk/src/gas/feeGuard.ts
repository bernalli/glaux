import { hexToBigInt, size, slice, type Hex, type PublicClient } from "viem";
import type { PackedUserOperation } from "../execute/userop.js";
import {
  FeeBaselineReadError,
  FeeExceedsBaselineError,
  MalformedPaymasterFieldError,
  UserOpCostExceedsCapError,
} from "../errors.js";
import { unpackAccountGasLimits, unpackGasFees } from "./erc7677.js";

/**
 * Blocks of fee history the baseline reads. Long enough that one anomalous
 * block cannot move the median tip, short enough to still describe current
 * conditions rather than an hour-old average.
 */
const BASELINE_BLOCK_COUNT = 5;
/** Tip percentile requested per block; the median of a block's own transactions. */
const BASELINE_REWARD_PERCENTILE = 50;

/**
 * How far above the baseline lane an operation's `maxFeePerGas` may sit before
 * it is treated as an anomaly rather than as headroom. Three times the fee a
 * client would compute itself covers a genuine spike between reading the
 * history and landing the operation; it does not cover the order-of-magnitude
 * overpricing that marks a hostile quote.
 */
export const DEFAULT_FEE_SANITY_MULTIPLE = 3n;

/** ERC-4337 v0.7 `paymasterAndData` header: `address(20) ‖ uint128 ‖ uint128`. */
const PAYMASTER_HEADER_LENGTH = 52;

export interface FeeBaseline {
  /** What the NEXT block will charge, not an average of the window. */
  readonly baseFeePerGas: bigint;
  /** Median across the sampled blocks of each block's own median tip. */
  readonly medianPriorityFeePerGas: bigint;
}

function isNonNegativeBigInt(value: unknown): value is bigint {
  return typeof value === "bigint" && value >= 0n;
}

function medianOf(values: readonly bigint[]): bigint {
  const sorted = [...values].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  return sorted[Math.floor((sorted.length - 1) / 2)]!;
}

/**
 * Computes a fee baseline from `eth_feeHistory` — the chain's own record of
 * what recent blocks charged — rather than from the `maxFeePerGas` a bundler,
 * paymaster or RPC proposes for this operation.
 *
 * That independence is the whole point: the proposed value is exactly what a
 * hostile counterparty controls, so it cannot also be the yardstick it is
 * measured against. Fee history is not immune to a lying endpoint either,
 * which is why the caller should source it from a second, independent endpoint
 * (`docs/client-guidance.md`) and why the absolute cost cap
 * ({@link assertUserOpCost}) is enforced regardless of any baseline.
 *
 * @throws {FeeBaselineReadError} if the response is unavailable or does not
 * carry a well-formed base fee and reward series — never falls back to a
 * guessed or endpoint-proposed value.
 */
export async function fetchFeeBaseline(client: PublicClient): Promise<FeeBaseline> {
  let history: unknown;
  try {
    history = await client.getFeeHistory({
      blockCount: BASELINE_BLOCK_COUNT,
      rewardPercentiles: [BASELINE_REWARD_PERCENTILE],
    });
  } catch {
    throw new FeeBaselineReadError("eth_feeHistory");
  }

  const { baseFeePerGas, reward } = (history ?? {}) as { baseFeePerGas?: unknown; reward?: unknown };
  if (!Array.isArray(baseFeePerGas) || baseFeePerGas.length === 0 || !baseFeePerGas.every(isNonNegativeBigInt)) {
    throw new FeeBaselineReadError("baseFeePerGas");
  }
  if (!Array.isArray(reward) || reward.length === 0) {
    throw new FeeBaselineReadError("reward");
  }

  const perBlockTips: bigint[] = [];
  for (const blockRewards of reward) {
    if (!Array.isArray(blockRewards) || !isNonNegativeBigInt(blockRewards[0])) {
      throw new FeeBaselineReadError("reward");
    }
    perBlockTips.push(blockRewards[0]);
  }

  return {
    // `eth_feeHistory` returns `blockCount + 1` base fees: the extra trailing
    // entry is the pending block's, which is what this operation will pay.
    baseFeePerGas: baseFeePerGas[baseFeePerGas.length - 1]!,
    medianPriorityFeePerGas: medianOf(perBlockTips),
  };
}

/**
 * The highest `maxFeePerGas` this baseline justifies: the same lane
 * `buildUserOp` computes for itself (`baseFee * 2 + tip`, the conventional
 * two-block headroom), scaled by the sanity multiple.
 */
export function allowedMaxFeePerGas(
  baseline: FeeBaseline,
  multiple: bigint = DEFAULT_FEE_SANITY_MULTIPLE,
): bigint {
  return (baseline.baseFeePerGas * 2n + baseline.medianPriorityFeePerGas) * multiple;
}

/**
 * @throws {FeeExceedsBaselineError} if `maxFeePerGas` sits above what the
 * baseline justifies.
 */
export function assertFeeWithinBaseline(
  maxFeePerGas: bigint,
  baseline: FeeBaseline,
  multiple: bigint = DEFAULT_FEE_SANITY_MULTIPLE,
): void {
  const allowed = allowedMaxFeePerGas(baseline, multiple);
  if (maxFeePerGas > allowed) throw new FeeExceedsBaselineError(maxFeePerGas, allowed);
}

/** The `maxFeePerGas` packed into an operation's `gasFees` word. */
export function userOpMaxFeePerGas(op: PackedUserOperation): bigint {
  return unpackGasFees(op.gasFees).maxFeePerGas;
}

/**
 * The paymaster's own two gas limits, which the account still underwrites in
 * the EntryPoint's required prefund.
 *
 * @throws {MalformedPaymasterFieldError} if the field is non-empty but cannot
 * carry the v0.7 header — pricing an unparsable paymaster field as free would
 * under-state the cost precisely when the field is suspect.
 */
function paymasterGas(paymasterAndData: Hex): bigint {
  if (paymasterAndData === "0x") return 0n;
  const length = size(paymasterAndData);
  if (length < PAYMASTER_HEADER_LENGTH) throw new MalformedPaymasterFieldError(length);
  return hexToBigInt(slice(paymasterAndData, 20, 36)) + hexToBigInt(slice(paymasterAndData, 36, 52));
}

/**
 * The most an operation's signature can cost its account: ERC-4337 v0.7's own
 * required-prefund formula (`EntryPoint._getRequiredPrefund`), every gas
 * dimension priced at `maxFeePerGas`.
 *
 * This is deliberately the worst case and not the expected cost. A signature
 * does not authorize what the operation will probably use — it authorizes what
 * the EntryPoint may charge, and unspent gas comes back only after the fact.
 * The cap has to bound the authorization, not the estimate.
 */
export function computeUserOpMaxCost(op: PackedUserOperation): bigint {
  const { verificationGasLimit, callGasLimit } = unpackAccountGasLimits(op.accountGasLimits);
  const totalGas = verificationGasLimit + callGasLimit + op.preVerificationGas + paymasterGas(op.paymasterAndData);
  return totalGas * userOpMaxFeePerGas(op);
}

/**
 * @throws {UserOpCostExceedsCapError} if the operation could charge the
 * account more than `maxCostWei`.
 */
export function assertUserOpCost(op: PackedUserOperation, maxCostWei: bigint): void {
  const cost = computeUserOpMaxCost(op);
  if (cost > maxCostWei) throw new UserOpCostExceedsCapError(cost, maxCostWei);
}
