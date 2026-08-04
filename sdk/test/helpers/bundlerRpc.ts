import { concat, hexToBigInt, numberToHex, slice, type Address, type Hex } from "viem";
import type { PackedUserOperation } from "../../src/execute/userop.js";
import { unpackAccountGasLimits, unpackGasFees } from "../../src/gas/erc7677.js";

/**
 * The ERC-4337 v0.7 bundler JSON-RPC wire shape for `eth_sendUserOperation`,
 * DISTINCT from `../../src/gas/erc7677.js`'s `RpcUserOperationV07`: that type
 * intentionally never carries paymaster fields, because ERC-7677 always
 * sends a paymaster-service the UNDECORATED operation it is being asked to
 * decorate. A real bundler submission is the opposite case — the paymaster
 * fields (when present) are exactly what must reach the bundler, split back
 * out of `paymasterAndData` the same way `../../src/gas/erc7677.js`'s
 * `applyPaymasterData` packed them in
 * (`paymaster (20 bytes) ‖ paymasterVerificationGasLimit (16) ‖
 * paymasterPostOpGasLimit (16) ‖ paymasterData`). Kept test-only and
 * separate from `src/` rather than folded into `toRpcUserOp`, per this
 * task's "no behavior change to `gas/*`" constraint.
 */
export interface BundlerRpcUserOperationV07 {
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
  readonly paymaster?: Address;
  readonly paymasterVerificationGasLimit?: Hex;
  readonly paymasterPostOpGasLimit?: Hex;
  readonly paymasterData?: Hex;
  readonly signature: Hex;
}

/** Converts a signed (optionally paymaster-decorated) `PackedUserOperation` into the bundler RPC wire shape. */
export function toBundlerRpcUserOp(op: PackedUserOperation): BundlerRpcUserOperationV07 {
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

  const withFactory =
    op.initCode === "0x"
      ? base
      : { ...base, factory: slice(op.initCode, 0, 20) as Address, factoryData: slice(op.initCode, 20) };

  if (op.paymasterAndData === "0x") {
    return withFactory;
  }
  const paymaster = slice(op.paymasterAndData, 0, 20) as Address;
  const paymasterVerificationGasLimit = hexToBigInt(slice(op.paymasterAndData, 20, 36));
  const paymasterPostOpGasLimit = hexToBigInt(slice(op.paymasterAndData, 36, 52));
  const paymasterData = slice(op.paymasterAndData, 52);
  return {
    ...withFactory,
    paymaster,
    paymasterVerificationGasLimit: numberToHex(paymasterVerificationGasLimit),
    paymasterPostOpGasLimit: numberToHex(paymasterPostOpGasLimit),
    paymasterData,
  };
}

/** A real bundler's JSON-RPC envelope carried an `error` instead of a `result`. */
export class BundlerRpcError extends Error {
  readonly code: number | undefined;
  readonly data: unknown;

  constructor(method: string, message: string, code?: number, data?: unknown) {
    super(`bundler ${method} failed: ${message}`);
    this.name = "BundlerRpcError";
    this.code = code;
    this.data = data;
  }
}

/** Thrown when a bundler's JSON-RPC response cannot be trusted at all (transport failure, malformed envelope). */
export class BundlerRpcTransportError extends Error {
  constructor(method: string, reason: string) {
    super(`bundler ${method} request failed: ${reason}`);
    this.name = "BundlerRpcTransportError";
  }
}

let nextRequestId = 1;

/**
 * A minimal ERC-4337 bundler JSON-RPC caller, structurally the same
 * plain-`fetch` JSON-RPC pattern `../../src/gas/erc7677.js`'s `callErc7677`
 * already uses for the ERC-7677 provider calls — kept test-only rather than
 * shared, since this task must not change `gas/*` behavior.
 */
export async function callBundlerRpc<T>(url: string, method: string, params: readonly unknown[]): Promise<T> {
  let response: Response;
  try {
    response = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: nextRequestId++, method, params }),
    });
  } catch (error) {
    throw new BundlerRpcTransportError(method, error instanceof Error ? error.message : "network error");
  }
  if (!response.ok) {
    throw new BundlerRpcTransportError(method, `HTTP ${response.status}`);
  }
  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    throw new BundlerRpcTransportError(method, "response was not valid JSON");
  }
  if (typeof payload !== "object" || payload === null) {
    throw new BundlerRpcTransportError(method, "response was not a JSON object");
  }
  const envelope = payload as Record<string, unknown>;
  if (envelope.error !== undefined && envelope.error !== null) {
    const error = envelope.error as Record<string, unknown>;
    const message = typeof error.message === "string" ? error.message : "bundler returned a JSON-RPC error";
    const code = typeof error.code === "number" ? error.code : undefined;
    throw new BundlerRpcError(method, message, code, error.data);
  }
  if (!("result" in envelope)) {
    throw new BundlerRpcTransportError(method, "response carried neither a result nor an error");
  }
  return envelope.result as T;
}

export interface BundlerUserOperationReceipt {
  readonly userOpHash: Hex;
  readonly success: boolean;
  readonly receipt: { readonly transactionHash: Hex };
}

/** `eth_sendUserOperation`: submits `userOp` for `entryPoint`, returning the bundler-assigned userOpHash. */
export async function sendUserOperation(
  bundlerUrl: string,
  userOp: BundlerRpcUserOperationV07,
  entryPoint: Address,
): Promise<Hex> {
  return callBundlerRpc<Hex>(bundlerUrl, "eth_sendUserOperation", [userOp, entryPoint]);
}

/**
 * Polls `eth_getUserOperationReceipt` until the bundler reports the
 * operation landed (a non-null receipt) or `timeoutMs` elapses. A `null`
 * result is the bundler's own documented "not yet included" answer, not an
 * error — polling is the correct, spec-defined way to observe inclusion.
 */
export async function waitForUserOperationReceipt(
  bundlerUrl: string,
  userOpHash: Hex,
  timeoutMs = 30_000,
): Promise<BundlerUserOperationReceipt> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const receipt = await callBundlerRpc<BundlerUserOperationReceipt | null>(bundlerUrl, "eth_getUserOperationReceipt", [
      userOpHash,
    ]);
    if (receipt !== null) return receipt;
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error(`no UserOperationReceipt for ${userOpHash} within ${timeoutMs}ms`);
}
