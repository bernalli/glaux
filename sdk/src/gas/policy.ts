import type { Address, PublicClient } from "viem";
import type { PackedUserOperation } from "../execute/userop.js";
import { fetchEntryPointDeposit } from "../execute/userop.js";
import { PaymasterNotConfiguredError, PaymasterUnavailableError, SelfFundingUnavailableError } from "../errors.js";
import {
  applyPaymasterData,
  paymasterClientFromEnv,
  unpackAccountGasLimits,
  unpackGasFees,
  Erc7677Client,
  type PaymasterStubData,
  type Erc7677Context,
} from "./erc7677.js";

export interface GasPlanChainContext {
  readonly client: PublicClient;
  readonly entryPoint: Address;
  readonly chainId: bigint;
  /** Passed through verbatim to the ERC-7677 provider, if one is configured. */
  readonly context?: Erc7677Context;
}

/**
 * The outcome of {@link GasPolicy.plan}: exactly one of the three tiers the
 * design's gas module declares (spec §2/§5), each carrying what a caller
 * needs to act on it. `selfRelay` carries no `op` at all — it is not a
 * decoration of the ERC-4337 op, but a signal to abandon the 4337 path
 * entirely and use the always-available, permissionless direct-execution
 * path (`../execute/direct.js`'s `signExecution`/`submitExecution`), which
 * needs no prefund from the account.
 */
export type GasPlan =
  | { readonly kind: "sponsored"; readonly op: PackedUserOperation; readonly events: readonly GasFallbackEvent[] }
  | { readonly kind: "selfFunded"; readonly op: PackedUserOperation; readonly events: readonly GasFallbackEvent[] }
  | { readonly kind: "selfRelay"; readonly events: readonly GasFallbackEvent[] };

export type GasFallbackFrom = "sponsored" | "selfFunded";
export type GasFallbackTo = "selfFunded" | "selfRelay";

/**
 * One degradation, per spec §7: "every degradation is an observable event,
 * never a silent retry". `cause` is the failing tier's typed error's
 * `.name` — a string rather than an `Error` instance, so it survives
 * serialization across a process boundary (logging, telemetry) unchanged.
 */
export interface GasFallbackEvent {
  readonly from: GasFallbackFrom;
  readonly to: GasFallbackTo;
  readonly cause: string;
}

export interface GasPolicyParams {
  /**
   * `undefined` (the default): read `GLAUX_PAYMASTER_URL` from the
   * environment via {@link paymasterClientFromEnv}. `null`: explicitly no
   * provider, regardless of environment — the state a test forces to
   * exercise the "no provider configured" fallback deterministically,
   * without depending on the environment's absence of the variable.
   */
  readonly paymasterClient?: Erc7677Client | null;
  readonly onFallback?: (event: GasFallbackEvent) => void;
}

function causeNameOf(error: unknown): string {
  return error instanceof Error ? error.name : "UnknownPaymasterError";
}

/**
 * `requiredPrefund` mirrors ERC-4337 v0.7's own prefund formula
 * (`EntryPoint._getRequiredPrefund`,
 * `lib/account-abstraction/contracts/core/EntryPoint.sol`) for the
 * NO-paymaster case: `(verificationGasLimit + callGasLimit +
 * preVerificationGas) * maxFeePerGas`. It is a policy-time feasibility
 * estimate, not a contract-exact bound — the real, final check is always the
 * EntryPoint's own `validateUserOp` at submission time
 * (`../execute/userop.js`); this only decides whether attempting the
 * self-funded path is plausible at all before spending an RPC round trip on
 * it.
 */
function requiredPrefund(op: PackedUserOperation): bigint {
  const { verificationGasLimit, callGasLimit } = unpackAccountGasLimits(op.accountGasLimits);
  const { maxFeePerGas } = unpackGasFees(op.gasFees);
  return (verificationGasLimit + callGasLimit + op.preVerificationGas) * maxFeePerGas;
}

/**
 * The gas module's fallback policy (spec §5/§7): sponsored (ERC-7677) →
 * self-funded ERC-4337 → self-relay guidance, with NO silent degradation —
 * every transition between tiers records a `{from, to, cause}` event in the
 * returned plan and calls `onFallback` when supplied, whether the cause is a
 * failed provider call, an unconfigured provider, or an account balance too
 * low to self-fund.
 */
export class GasPolicy {
  private readonly paymasterClient: Erc7677Client | null;
  private readonly onFallback?: (event: GasFallbackEvent) => void;

  constructor(params: GasPolicyParams = {}) {
    this.paymasterClient = params.paymasterClient === undefined ? paymasterClientFromEnv() : params.paymasterClient;
    this.onFallback = params.onFallback;
  }

  /**
   * Decides how `op` (as returned by `buildUserOp`, paymaster fields still
   * the placeholder `"0x"`) should be funded on `chain`. Never mutates `op`;
   * a `sponsored`/`selfFunded` result carries the (possibly decorated) op to
   * sign and submit next (`signUserOp`/`submitUserOpDirect`,
   * `../execute/userop.js`).
   */
  async plan(op: PackedUserOperation, chain: GasPlanChainContext): Promise<GasPlan> {
    const events: GasFallbackEvent[] = [];
    const sponsoredOp = await this.trySponsor(op, chain, events);
    if (sponsoredOp !== null) {
      return { kind: "sponsored", op: sponsoredOp, events };
    }

    const [balance, deposit] = await Promise.all([
      chain.client.getBalance({ address: op.sender }),
      fetchEntryPointDeposit(chain.client, chain.entryPoint, op.sender),
    ]);
    const required = requiredPrefund(op);
    const missingAccountFunds = required > deposit ? required - deposit : 0n;
    if (balance >= missingAccountFunds) {
      return { kind: "selfFunded", op, events };
    }

    this.recordFallback(events, {
      from: "selfFunded",
      to: "selfRelay",
      cause: new SelfFundingUnavailableError(missingAccountFunds, balance).name,
    });
    return { kind: "selfRelay", events };
  }

  private recordFallback(events: GasFallbackEvent[], event: GasFallbackEvent): void {
    events.push(event);
    this.onFallback?.(event);
  }

  private async trySponsor(
    op: PackedUserOperation,
    chain: GasPlanChainContext,
    events: GasFallbackEvent[],
  ): Promise<PackedUserOperation | null> {
    if (this.paymasterClient === null) {
      this.recordFallback(events, { from: "sponsored", to: "selfFunded", cause: new PaymasterNotConfiguredError().name });
      return null;
    }

    const request = { op, entryPoint: chain.entryPoint, chainId: chain.chainId, context: chain.context };
    try {
      // Mirrors a real bundler/integrator's own flow: probe with the stub
      // call first (as gas estimation would), then request the final,
      // submission-safe data. A provider that fails at either stage
      // degrades the same way — one fallback event, not two.
      const stub = await this.paymasterClient.getPaymasterStubData(request);
      if (stub.isFinal) {
        return applyPaymasterData(op, finalDataFromStub(stub), stub);
      }
      const final = await this.paymasterClient.getPaymasterData(request);
      return applyPaymasterData(op, final, stub);
    } catch (error) {
      this.recordFallback(events, { from: "sponsored", to: "selfFunded", cause: causeNameOf(error) });
      return null;
    }
  }
}

function finalDataFromStub(stub: PaymasterStubData): { readonly paymaster: Address; readonly paymasterData: `0x${string}` } {
  if (stub.paymaster === undefined || stub.paymasterData === undefined) {
    throw new PaymasterUnavailableError("pm_getPaymasterStubData", "final stub omitted paymaster data");
  }
  return { paymaster: stub.paymaster, paymasterData: stub.paymasterData };
}
