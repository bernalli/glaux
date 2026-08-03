import type { Address, PublicClient } from "viem";
import { freshAccountFailureReason } from "../birth/preflight.js";
import { CREATE2_DEPLOYER, ENTRYPOINT, IMPL, ROUTER } from "../core/constants.js";
import { BirthPreflightReadError } from "../errors.js";
import {
  P256_VERIFIER,
  probeAccountBorn,
  probeDeployedCode,
  probeEip7702,
  probeP256Result,
} from "./probes.js";

/**
 * One boolean per live check `checkChain` runs. `accountBorn` is present only
 * when `checkChain` was given an `account` to check.
 */
export interface ChainEligibilityProbes {
  p256: boolean;
  eip7702: boolean;
  create2Deployer: boolean;
  entryPoint: boolean;
  routerDeployed: boolean;
  implDeployed: boolean;
  accountBorn?: boolean;
}

/**
 * The result of `checkChain`.
 *
 * Gate rule (spec §5): callers MUST consult this before ever displaying a
 * Glaux address as a receive address. Glaux's address is an EOA whose birth
 * key is destroyed once it is born; on a chain where it has NOT been born,
 * funds sent there arrive but are FROZEN until a birth happens on that same
 * chain — and birth is impossible on a chain that lacks EIP-7702 or the
 * P-256 precompile until that chain upgrades. `"ineligible"` names exactly
 * that hazard. `"born"` is safe to receive; `"eligible"` is safe only when
 * the supplied account has also passed the same freshness predicate birth uses.
 */
export interface ChainEligibility {
  verdict: "born" | "eligible" | "ineligible";
  probes: ChainEligibilityProbes;
  reasons: string[];
}

type EnvironmentProbeKey = keyof Omit<ChainEligibilityProbes, "accountBorn">;

const REASONS: Record<EnvironmentProbeKey, string> = {
  p256: `p256: no conforming P-256 verifier at ${P256_VERIFIER} (RIP-7212/EIP-7951) — a P-256 factor would be inert, and an account holding two of them could never reach its own 2-of-3 threshold.`,
  eip7702: "eip7702: this chain's eth_estimateGas does not price an EIP-7702 authorization list distinctly from a bare call — an EOA cannot be delegated here yet.",
  create2Deployer: `create2Deployer: the canonical CREATE2 deployer is not deployed at ${CREATE2_DEPLOYER}.`,
  entryPoint: `entryPoint: ERC-4337 EntryPoint v0.7 is not deployed at ${ENTRYPOINT}.`,
  routerDeployed: `routerDeployed: GlauxDelegate (the router) is not deployed at ${ROUTER}.`,
  implDeployed: `implDeployed: GlauxAccount (the implementation) is not deployed at ${IMPL}.`,
};

const ENVIRONMENT_PROBE_KEYS = Object.keys(REASONS) as EnvironmentProbeKey[];

/**
 * Runs every live probe against `client` and, if `account` is given, checks
 * whether that specific address has already been born. Read-only throughout:
 * two `eth_call`s to `0x100`, two `eth_estimateGas`s, four `eth_getCode`s,
 * and — only with `account` — its code, implementation code, and the storage
 * words needed to validate the initialized factor layout.
 */
export async function checkChain(client: PublicClient, account?: Address): Promise<ChainEligibility> {
  const [p256Result, eip7702, create2Deployer, entryPoint, routerDeployed, implDeployed, accountBorn] =
    await Promise.all([
      probeP256Result(client),
      probeEip7702(client),
      probeDeployedCode(client, CREATE2_DEPLOYER),
      probeDeployedCode(client, ENTRYPOINT),
      probeDeployedCode(client, ROUTER),
      probeDeployedCode(client, IMPL),
      account !== undefined ? probeAccountBorn(client, account) : Promise.resolve(undefined),
    ]);

  const probes: ChainEligibilityProbes = {
    p256: p256Result.available,
    eip7702,
    create2Deployer,
    entryPoint,
    routerDeployed,
    implDeployed,
    ...(account !== undefined ? { accountBorn: accountBorn as boolean } : {}),
  };

  const failed = ENVIRONMENT_PROBE_KEYS.filter((key) => !probes[key]);
  const reasons = failed.map((key) =>
    key === "p256" && p256Result.transportFailure
      ? `p256: verifier probe transport failure at ${P256_VERIFIER}; eligibility cannot be established.`
      : REASONS[key],
  );
  if (account !== undefined && accountBorn === false) {
    try {
      const reason = await freshAccountFailureReason(client, account);
      if (reason !== undefined) reasons.push(`account: not birthable — ${reason}`);
    } catch (error) {
      if (error instanceof BirthPreflightReadError) {
        reasons.push(`account: birthability could not be established — ${error.message}`);
      } else {
        throw error;
      }
    }
  }
  if (reasons.length === 0) {
    return { verdict: accountBorn === true ? "born" : "eligible", probes, reasons: [] };
  }
  return {
    verdict: "ineligible",
    probes,
    reasons,
  };
}
