import { createServer, type IncomingMessage, type Server } from "node:http";
import type { AddressInfo, Socket } from "node:net";
import {
  concat,
  encodeAbiParameters,
  encodePacked,
  hashMessage,
  hexToBigInt,
  keccak256,
  type Address,
  type Hex,
} from "viem";
import { sign } from "viem/accounts";

export type Mock7677Method = "pm_getPaymasterStubData" | "pm_getPaymasterData";

/**
 * Thrown by a handler to force a raw, non-JSON-RPC HTTP failure — a real
 * infra outage (gateway timeout, load-balancer 5xx) rather than a
 * well-formed JSON-RPC decline. `sdk/test/gas.test.ts` uses this to prove
 * `Erc7677Client`/`GasPolicy` treat an HTTP 500 as
 * `PaymasterUnavailableError`, not as a parse failure of some JSON-RPC
 * envelope that never arrives.
 */
export class MockHttpError extends Error {
  readonly status: number;

  constructor(status: number, message = "mock provider error") {
    super(message);
    this.status = status;
  }
}

export interface Mock7677RequestParams {
  readonly userOp: Record<string, unknown>;
  readonly entryPoint: Address;
  readonly chainId: Hex;
  readonly context: Record<string, unknown>;
}

export type Mock7677Handler = (params: Mock7677RequestParams) => unknown | Promise<unknown>;

export interface Mock7677Handlers {
  readonly getPaymasterStubData?: Mock7677Handler;
  readonly getPaymasterData?: Mock7677Handler;
}

export interface Mock7677ServerHandle {
  readonly url: string;
  close(): Promise<void>;
}

const METHOD_TO_HANDLER_KEY: Record<Mock7677Method, keyof Mock7677Handlers> = {
  pm_getPaymasterStubData: "getPaymasterStubData",
  pm_getPaymasterData: "getPaymasterData",
};

async function readBody(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks).toString("utf8");
}

/**
 * A minimal in-process ERC-7677 paymaster-service mock on plain `node:http`
 * (no framework dependency, per the task brief). Binds an OS-assigned port
 * (`listen(0, ...)`) so parallel test files never collide on a fixed one,
 * and every caller MUST close it in a `finally` — including on a failing
 * test — so a failure never leaks a listening process.
 *
 * Unrecognized JSON-RPC methods, and handlers that return normally, produce
 * a well-formed `200` JSON-RPC envelope; a handler that throws
 * {@link MockHttpError} instead produces a raw HTTP failure at that status,
 * with no JSON-RPC envelope at all — the shape `Erc7677Client` must treat as
 * `!response.ok`, never as a parseable (if unlucky) JSON-RPC error.
 */
export async function startMock7677Server(handlers: Mock7677Handlers): Promise<Mock7677ServerHandle> {
  const sockets = new Set<Socket>();
  const server: Server = createServer((req, res) => {
    void (async (): Promise<void> => {
      let parsed: { id: unknown; method: string; params: readonly unknown[] };
      try {
        const raw = await readBody(req);
        parsed = JSON.parse(raw) as { id: unknown; method: string; params: readonly unknown[] };
      } catch {
        res.writeHead(400, { "content-type": "text/plain" });
        res.end("malformed JSON-RPC request body");
        return;
      }

      const method = parsed.method as Mock7677Method;
      const handlerKey = METHOD_TO_HANDLER_KEY[method];
      const handler = handlerKey ? handlers[handlerKey] : undefined;
      if (handler === undefined) {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(
          JSON.stringify({
            jsonrpc: "2.0",
            id: parsed.id,
            error: { code: -32601, message: `method not found: ${method}` },
          }),
        );
        return;
      }

      const [userOp, entryPoint, chainId, context] = parsed.params as [
        Record<string, unknown>,
        Address,
        Hex,
        Record<string, unknown>,
      ];

      try {
        const result = await handler({ userOp, entryPoint, chainId, context });
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ jsonrpc: "2.0", id: parsed.id, result }));
      } catch (error) {
        const status = error instanceof MockHttpError ? error.status : 500;
        const message = error instanceof Error ? error.message : "mock server error";
        res.writeHead(status, { "content-type": "text/plain" });
        res.end(message);
      }
    })();
  });
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address() as AddressInfo;

  return {
    url: `http://127.0.0.1:${address.port}`,
    close: () =>
      new Promise<void>((resolve, reject) => {
        for (const socket of sockets) socket.destroy();
        server.close((error) => (error ? reject(error) : resolve()));
      }),
  };
}

const PAYMASTER_GET_HASH_TYPES = [
  { type: "address" },
  { type: "uint256" },
  { type: "bytes32" },
  { type: "bytes32" },
  { type: "bytes32" },
  { type: "uint256" },
  { type: "uint256" },
  { type: "bytes32" },
  { type: "uint256" },
  { type: "address" },
  { type: "uint48" },
  { type: "uint48" },
] as const;

export interface VerifyingPaymasterSigningConfig {
  readonly paymaster: Address;
  readonly ownerPrivateKey: Hex;
  readonly chainId: bigint;
  readonly validUntil: number;
  readonly validAfter: number;
  readonly paymasterVerificationGasLimit: bigint;
  readonly paymasterPostOpGasLimit: bigint;
}

/**
 * Repacks the ERC-7677 wire-format UserOperation fields (as received by a
 * mock handler) back into `PackedUserOperation`'s on-chain
 * `accountGasLimits`/`gasFees` bytes32 words. Deliberately reimplemented
 * here rather than imported from `../../src/gas/erc7677.js`'s own
 * (inverse) packing helper: a bug that cancelled out between the two
 * directions would hide behind the SAME code on both sides, whereas the
 * sponsored e2e test's real cross-check is that the EntryPoint accepts the
 * resulting on-chain signature — an independent re-derivation here is what
 * makes that check meaningful rather than circular.
 */
function repackGasFields(userOp: Record<string, unknown>): { accountGasLimits: Hex; gasFees: Hex } {
  const verificationGasLimit = hexToBigInt(userOp.verificationGasLimit as Hex);
  const callGasLimit = hexToBigInt(userOp.callGasLimit as Hex);
  const maxPriorityFeePerGas = hexToBigInt(userOp.maxPriorityFeePerGas as Hex);
  const maxFeePerGas = hexToBigInt(userOp.maxFeePerGas as Hex);
  return {
    accountGasLimits: encodePacked(["uint128", "uint128"], [verificationGasLimit, callGasLimit]),
    gasFees: encodePacked(["uint128", "uint128"], [maxPriorityFeePerGas, maxFeePerGas]),
  };
}

/**
 * Computes `VerifyingPaymaster.getHash`
 * (`lib/account-abstraction/contracts/samples/VerifyingPaymaster.sol:42-63`)
 * from the ERC-7677 wire-format `userOp` a mock handler receives, and signs
 * it exactly as the contract's `_validatePaymasterUserOp` verifies it:
 * `ECDSA.recover` over
 * `MessageHashUtils.toEthSignedMessageHash(getHash(...))` — the EIP-191
 * personal-sign prefix, replicated via viem's `hashMessage({ raw })`.
 *
 * Returns the ready-to-embed `paymasterData` tail —
 * `abi.encode(validUntil, validAfter) ‖ signature`, exactly
 * `VerifyingPaymaster.sol`'s `parsePaymasterAndData` layout. The caller
 * (a mock handler) still owns prefixing `paymaster ‖
 * paymasterVerificationGasLimit ‖ paymasterPostOpGasLimit` ahead of it: that
 * happens in `../../src/gas/erc7677.js`'s `applyPaymasterData`, from the
 * ERC-7677 response shape the handler returns.
 *
 * Glaux never sends ERC-4337's counterfactual-deploy `initCode`
 * (`../../src/gas/erc7677.js`'s `toRpcUserOp` never emits `factory`), so
 * `initCode`'s hash is always `keccak256("0x")`; a `userOp.factory` would
 * mean that assumption broke, so this refuses rather than silently signing
 * the wrong hash.
 */
export async function signVerifyingPaymasterData(
  userOp: Record<string, unknown>,
  config: VerifyingPaymasterSigningConfig,
): Promise<Hex> {
  if (userOp.factory !== undefined) {
    throw new Error("signVerifyingPaymasterData: factory/factoryData is not supported (Glaux never sends it).");
  }

  const sender = userOp.sender as Address;
  const nonce = hexToBigInt(userOp.nonce as Hex);
  const initCodeHash = keccak256("0x");
  const callDataHash = keccak256(userOp.callData as Hex);
  const { accountGasLimits, gasFees } = repackGasFields(userOp);
  const preVerificationGas = hexToBigInt(userOp.preVerificationGas as Hex);
  const paymasterGasWord = hexToBigInt(
    encodePacked(["uint128", "uint128"], [config.paymasterVerificationGasLimit, config.paymasterPostOpGasLimit]),
  );

  const hash = keccak256(
    encodeAbiParameters(PAYMASTER_GET_HASH_TYPES, [
      sender,
      nonce,
      initCodeHash,
      callDataHash,
      accountGasLimits,
      paymasterGasWord,
      preVerificationGas,
      gasFees,
      config.chainId,
      config.paymaster,
      config.validUntil,
      config.validAfter,
    ]),
  );

  const signature = await sign({ hash: hashMessage({ raw: hash }), privateKey: config.ownerPrivateKey, to: "hex" });

  return concat([
    encodeAbiParameters([{ type: "uint48" }, { type: "uint48" }], [config.validUntil, config.validAfter]),
    signature,
  ]);
}
