import { concat, encodePacked, hexToBigInt, numberToHex, slice, type Address, type Hex } from "viem";
import type { PackedUserOperation } from "../execute/userop.js";
import { PaymasterUnavailableError } from "../errors.js";

const UINT128_MASK = (1n << 128n) - 1n;

/**
 * Unpacks `PackedUserOperation.accountGasLimits` back into its two `uint128`
 * halves. `../execute/userop.js`'s `buildUserOp` packs
 * `(verificationGasLimit, callGasLimit)` high-then-low
 * (`encodePacked(["uint128", "uint128"], ...)`), matching
 * `UserOperationLib.unpackUints` — this is the inverse, needed because the
 * ERC-7677 wire format (and the ERC-4337 bundler RPC schema it borrows) sends
 * these as two separate hex fields, never as one packed word.
 */
export function unpackAccountGasLimits(accountGasLimits: Hex): {
  readonly verificationGasLimit: bigint;
  readonly callGasLimit: bigint;
} {
  const raw = hexToBigInt(accountGasLimits);
  return { verificationGasLimit: raw >> 128n, callGasLimit: raw & UINT128_MASK };
}

/** Same packing convention as {@link unpackAccountGasLimits}, for `gasFees`. */
export function unpackGasFees(gasFees: Hex): {
  readonly maxPriorityFeePerGas: bigint;
  readonly maxFeePerGas: bigint;
} {
  const raw = hexToBigInt(gasFees);
  return { maxPriorityFeePerGas: raw >> 128n, maxFeePerGas: raw & UINT128_MASK };
}

/**
 * The ERC-4337 v0.7 bundler-RPC "unpacked" UserOperation shape ERC-7677's
 * `pm_getPaymasterStubData`/`pm_getPaymasterData` methods take as their first
 * param — every gas/fee field as its own hex string, never as the on-chain
 * struct's packed `bytes32` words. Paymaster fields are always absent here:
 * this is the "unsigned user operation" the spec's ERC-7677 client asks a
 * provider to DECORATE, so it can never itself carry paymaster data.
 */
export interface RpcUserOperationV07 {
  readonly sender: Address;
  readonly nonce: Hex;
  readonly factory?: Address;
  readonly factoryData?: Hex;
  readonly callData: Hex;
  readonly callGasLimit: Hex;
  readonly verificationGasLimit: Hex;
  readonly preVerificationGas: Hex;
  readonly maxFeePerGas: Hex;
  readonly maxPriorityFeePerGas: Hex;
  readonly signature: Hex;
}

/**
 * Converts a Glaux `PackedUserOperation` (`../execute/userop.js`) into the
 * wire shape ERC-7677 providers expect. Glaux never uses ERC-4337's
 * counterfactual-deploy `initCode` (birth is a separate one-shot EIP-7702
 * flow — `../birth/*.js`), so the `factory`/`factoryData` split below only
 * ever fires for a caller-supplied non-empty `initCode`, kept correct rather
 * than assumed unreachable.
 */
export function toRpcUserOp(op: PackedUserOperation): RpcUserOperationV07 {
  const { verificationGasLimit, callGasLimit } = unpackAccountGasLimits(op.accountGasLimits);
  const { maxPriorityFeePerGas, maxFeePerGas } = unpackGasFees(op.gasFees);

  const base = {
    sender: op.sender,
    nonce: numberToHex(op.nonce),
    callData: op.callData,
    callGasLimit: numberToHex(callGasLimit),
    verificationGasLimit: numberToHex(verificationGasLimit),
    preVerificationGas: numberToHex(op.preVerificationGas),
    maxFeePerGas: numberToHex(maxFeePerGas),
    maxPriorityFeePerGas: numberToHex(maxPriorityFeePerGas),
    signature: op.signature,
  };

  if (op.initCode === "0x") {
    return base;
  }
  return {
    ...base,
    factory: slice(op.initCode, 0, 20) as Address,
    factoryData: slice(op.initCode, 20),
  };
}

/** Arbitrary, provider-defined capability context — passed through verbatim, per ERC-7677. */
export type Erc7677Context = Readonly<Record<string, unknown>>;

export interface Erc7677RequestParams {
  /** As returned by `buildUserOp` — paymaster fields must still be the placeholder `"0x"`. */
  readonly op: PackedUserOperation;
  readonly entryPoint: Address;
  readonly chainId: bigint;
  readonly context?: Erc7677Context;
}

/**
 * The subset of ERC-7677's `pm_getPaymasterStubData` result this SDK reads:
 * enough to decorate a UserOperation for gas *estimation*, not yet a value
 * safe to submit (a provider is free to return placeholder/unsigned data
 * here — `isFinal` says whether it happened to already be final).
 */
export interface PaymasterStubData {
  readonly paymaster: Address;
  readonly paymasterData: Hex;
  readonly paymasterVerificationGasLimit?: bigint;
  readonly paymasterPostOpGasLimit?: bigint;
  readonly isFinal?: boolean;
}

/**
 * The subset of ERC-7677's `pm_getPaymasterData` result this SDK reads: the
 * value that is safe to embed into a UserOperation's `paymasterAndData` and
 * submit. Structurally identical to {@link PaymasterStubData} minus
 * `isFinal` (a final response has no ambiguity left to flag).
 */
export interface PaymasterFinalData {
  readonly paymaster: Address;
  readonly paymasterData: Hex;
  readonly paymasterVerificationGasLimit?: bigint;
  readonly paymasterPostOpGasLimit?: bigint;
}

const ERC7677_METHODS = ["pm_getPaymasterStubData", "pm_getPaymasterData"] as const;
type Erc7677Method = (typeof ERC7677_METHODS)[number];

function isAddressLike(value: unknown): value is Address {
  return typeof value === "string" && /^0x[0-9a-fA-F]{40}$/u.test(value);
}

function isHexLike(value: unknown): value is Hex {
  return typeof value === "string" && /^0x(?:[0-9a-fA-F]{2})*$/u.test(value);
}

/**
 * `paymasterVerificationGasLimit`/`paymasterPostOpGasLimit` are JSON-RPC
 * QUANTITY-style hex (a hex number, no byte-padding — `eth_gasPrice`'s own
 * encoding, e.g. `"0x186a0"`), unlike `paymasterData`'s DATA-style
 * byte-aligned hex `isHexLike` validates. Using the byte-aligned check here
 * would reject every odd-hex-digit-count value a compliant provider sends.
 */
function isOptionalHexQuantity(value: unknown): value is Hex | undefined {
  return value === undefined || (typeof value === "string" && /^0x[0-9a-fA-F]+$/u.test(value));
}

/**
 * Validates and narrows a provider's raw JSON-RPC `result` into
 * {@link PaymasterStubData}/{@link PaymasterFinalData}. Fails closed: any
 * missing or malformed field is a {@link PaymasterUnavailableError}, never a
 * best-effort default — an unreadable paymaster decoration must never be
 * silently treated as "no sponsorship", which is a DIFFERENT, honest state
 * (`PaymasterNotConfiguredError`, `../gas/policy.js`), nor smuggled into an
 * artifact the EntryPoint might reject in a way that looks like the
 * account's own fault.
 */
function parsePaymasterResult(method: Erc7677Method, result: unknown, allowIsFinal: boolean): PaymasterFinalData & { isFinal?: boolean } {
  if (typeof result !== "object" || result === null) {
    throw new PaymasterUnavailableError(method, "response result was not an object");
  }
  const candidate = result as Record<string, unknown>;
  const { paymaster, paymasterData, paymasterVerificationGasLimit, paymasterPostOpGasLimit, isFinal } = candidate;

  if (!isAddressLike(paymaster)) {
    throw new PaymasterUnavailableError(method, "response's `paymaster` was missing or not an address");
  }
  if (!isHexLike(paymasterData)) {
    throw new PaymasterUnavailableError(method, "response's `paymasterData` was missing or not hex bytes");
  }
  if (!isOptionalHexQuantity(paymasterVerificationGasLimit) || !isOptionalHexQuantity(paymasterPostOpGasLimit)) {
    throw new PaymasterUnavailableError(method, "response's paymaster gas limit fields were not hex");
  }
  if (allowIsFinal && isFinal !== undefined && typeof isFinal !== "boolean") {
    throw new PaymasterUnavailableError(method, "response's `isFinal` was not a boolean");
  }

  return {
    paymaster,
    paymasterData,
    paymasterVerificationGasLimit:
      paymasterVerificationGasLimit === undefined ? undefined : hexToBigInt(paymasterVerificationGasLimit),
    paymasterPostOpGasLimit:
      paymasterPostOpGasLimit === undefined ? undefined : hexToBigInt(paymasterPostOpGasLimit),
    ...(allowIsFinal ? { isFinal: isFinal as boolean | undefined } : {}),
  };
}

async function callErc7677(url: string, method: Erc7677Method, params: Erc7677RequestParams): Promise<unknown> {
  const body = JSON.stringify({
    jsonrpc: "2.0",
    id: 1,
    method,
    params: [toRpcUserOp(params.op), params.entryPoint, numberToHex(params.chainId), params.context ?? {}],
  });

  let response: Response;
  try {
    response = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body,
    });
  } catch {
    throw new PaymasterUnavailableError(method, "request failed: the provider was unreachable");
  }

  if (!response.ok) {
    throw new PaymasterUnavailableError(method, `provider responded with HTTP ${response.status}`);
  }

  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    throw new PaymasterUnavailableError(method, "provider response was not valid JSON");
  }

  if (typeof payload !== "object" || payload === null) {
    throw new PaymasterUnavailableError(method, "provider response was not a JSON object");
  }
  const envelope = payload as Record<string, unknown>;
  if (envelope.error !== undefined && envelope.error !== null) {
    const error = envelope.error as Record<string, unknown>;
    const message = typeof error.message === "string" ? error.message : "provider returned a JSON-RPC error";
    throw new PaymasterUnavailableError(method, message);
  }
  if (!("result" in envelope)) {
    throw new PaymasterUnavailableError(method, "provider response carried neither a result nor an error");
  }
  return envelope.result;
}

/**
 * ERC-7677 paymaster-web-service client: `pm_getPaymasterStubData` and
 * `pm_getPaymasterData`, both taking the unsigned UserOperation, the
 * EntryPoint address, the chain id, and a provider-defined context object
 * (spec `docs/specs/2026-08-03-glaux-phase4-sdk-design.md` §5 "gas"). `url`
 * is the only configuration this class takes — callers obtain it from
 * `GLAUX_PAYMASTER_URL` via {@link paymasterClientFromEnv}, never from a
 * default endpoint or committed code.
 *
 * Every failure mode (network error, non-2xx HTTP, JSON-RPC `error`,
 * malformed result) is a single typed {@link PaymasterUnavailableError}: per
 * the design's threat model, a paymaster can at worst deny sponsorship, so
 * "unreadable" and "denied" are treated identically — never retried, never
 * guessed at.
 */
export class Erc7677Client {
  constructor(private readonly url: string) {}

  async getPaymasterStubData(params: Erc7677RequestParams): Promise<PaymasterStubData> {
    const result = await callErc7677(this.url, "pm_getPaymasterStubData", params);
    return parsePaymasterResult("pm_getPaymasterStubData", result, true);
  }

  async getPaymasterData(params: Erc7677RequestParams): Promise<PaymasterFinalData> {
    const result = await callErc7677(this.url, "pm_getPaymasterData", params);
    const parsed = parsePaymasterResult("pm_getPaymasterData", result, false);
    return {
      paymaster: parsed.paymaster,
      paymasterData: parsed.paymasterData,
      paymasterVerificationGasLimit: parsed.paymasterVerificationGasLimit,
      paymasterPostOpGasLimit: parsed.paymasterPostOpGasLimit,
    };
  }
}

/**
 * Reads `GLAUX_PAYMASTER_URL` from the environment and builds an
 * {@link Erc7677Client} if it is set, or `null` if it is unset/blank —
 * `null` here means "no provider configured", the state
 * `PaymasterNotConfiguredError` (`../errors.js`) names. Provider
 * configuration comes ONLY from the environment (spec §5): no default
 * endpoint, no API key ever committed to the repo.
 */
export function paymasterClientFromEnv(): Erc7677Client | null {
  const url = process.env.GLAUX_PAYMASTER_URL;
  if (url === undefined || url.trim() === "") {
    return null;
  }
  return new Erc7677Client(url);
}

// Generous, fixed defaults for a paymaster's own validation/postOp gas when a
// response omits them — same "no bundler-grade estimator yet" rationale
// `../execute/userop.js`'s own `VERIFICATION_GAS_LIMIT`/`PRE_VERIFICATION_GAS`
// document (Task 11 owns a real calculator). A real provider is expected to
// supply its own values; these only cover a minimal/test paymaster that
// doesn't bother to.
const DEFAULT_PAYMASTER_VERIFICATION_GAS_LIMIT = 150_000n;
const DEFAULT_PAYMASTER_POSTOP_GAS_LIMIT = 50_000n;

/**
 * Decorates `op` with a sponsored `paymasterAndData`, built strictly from
 * `data`'s own fields (`paymaster` address, its chosen gas limits, and its
 * opaque `paymasterData` payload) laid out exactly as
 * `UserOperationLib`/`BasePaymaster` expect
 * (`lib/account-abstraction/contracts/core/UserOperationLib.sol:14-16`):
 * `paymaster (20 bytes) ‖ paymasterVerificationGasLimit (16) ‖
 * paymasterPostOpGasLimit (16) ‖ paymasterData`. Every other field of `op` is
 * carried through unchanged — the paymaster can only ever add its own
 * sponsorship fields, never influence `sender`/`callData`/the account's own
 * gas fields, which is exactly the boundary `docs/threat-model.md`'s
 * paymaster entry requires: a paymaster can at worst deny sponsorship, never
 * authorize an unsigned operation. The factors' own signature
 * (`signUserOp`, `../execute/userop.js`) is computed AFTER this decoration,
 * over the full resulting op, so nothing here is ever signed blind.
 */
export function applyPaymasterData(op: PackedUserOperation, data: PaymasterFinalData): PackedUserOperation {
  const verificationGasLimit = data.paymasterVerificationGasLimit ?? DEFAULT_PAYMASTER_VERIFICATION_GAS_LIMIT;
  const postOpGasLimit = data.paymasterPostOpGasLimit ?? DEFAULT_PAYMASTER_POSTOP_GAS_LIMIT;

  const paymasterAndData = concat([
    data.paymaster,
    encodePacked(["uint128", "uint128"], [verificationGasLimit, postOpGasLimit]),
    data.paymasterData,
  ]);

  return { ...op, paymasterAndData };
}
