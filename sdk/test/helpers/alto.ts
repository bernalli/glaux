import { spawn, type ChildProcessByStdio } from "node:child_process";
import { createServer } from "node:net";
import type { Readable } from "node:stream";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { Address, Hex } from "viem";
import { afterEach } from "vitest";

/**
 * Shared Alto (real ERC-4337 bundler) process lifecycle, mirroring
 * `./anvil.js`'s `spawnAnvil`: every scenario spawns its own bundler and MUST
 * tear it down, on pass or fail, so a failure never leaks a listening
 * process. Same per-test-file isolation rationale as `anvil.ts` — Vitest
 * gives each test file its own module graph, so `runningAltos` here is
 * independent of any other suite's set.
 */
const runningAltos = new Set<ChildProcessByStdio<null, Readable, Readable>>();

async function stopAlto(child: ChildProcessByStdio<null, Readable, Readable>): Promise<void> {
  if (child.exitCode !== null) return;
  const exited = (timeoutMs: number): Promise<boolean> =>
    new Promise((resolve) => {
      const timer = setTimeout(() => resolve(false), timeoutMs);
      child.once("exit", () => {
        clearTimeout(timer);
        resolve(true);
      });
    });
  child.kill("SIGTERM");
  if (await exited(2_000)) return;
  child.kill("SIGKILL");
  if (!(await exited(2_000))) throw new Error("alto did not exit after SIGKILL");
}

afterEach(async () => {
  await Promise.all([...runningAltos].map(stopAlto));
  runningAltos.clear();
});

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "../../..");
/**
 * `sdk/node_modules/.bin/alto` — the exact, pinned binary
 * `sdk/package.json`'s `devDependencies["@pimlico/alto"]` resolves to. Never
 * relies on a global `alto` on `PATH`, so the version under test is always
 * the one this repo pinned.
 */
const ALTO_BIN = join(REPO_ROOT, "sdk", "node_modules", ".bin", "alto");

export class AltoStartupError extends Error {
  constructor(reason: string, output: string) {
    super(`alto did not become ready: ${reason}\n${output}`);
    this.name = "AltoStartupError";
  }
}

/**
 * Finds a currently-free TCP port by binding to port 0 (OS-assigned), then
 * immediately releasing it. Unlike anvil's own `--port 0` (whose stdout
 * reports the port it actually bound), Alto's CLI takes a fixed `--port`
 * with no OS-assignment support and prints nothing about which address it
 * bound — see `@pimlico/alto`'s `esm/rpc/server.js`, whose `start()` calls
 * `fastify.listen({ port: this.config.port, ... })` and never reports the
 * result. Pre-allocating a free port this way (immediately closing the probe
 * socket before Alto binds the real one) is the same "let it choose or
 * allocate a free one" allowance the task requires, with a negligible,
 * accepted TOCTOU window on a local machine running nothing else against
 * that port.
 */
async function findFreePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const probe = createServer();
    probe.once("error", reject);
    probe.listen(0, "127.0.0.1", () => {
      const address = probe.address();
      if (typeof address !== "object" || address === null) {
        probe.close();
        reject(new Error("could not read the probed free port"));
        return;
      }
      const { port } = address;
      probe.close(() => resolve(port));
    });
  });
}

export interface SpawnAltoOptions {
  /** The anvil (or other EVM node) JSON-RPC URL Alto submits bundles against. */
  readonly rpcUrl: string;
  /** ERC-4337 EntryPoint addresses Alto accepts UserOperations for, comma-joined on the CLI. */
  readonly entryPoints: readonly Address[];
  /**
   * Funds the account Alto uses to submit `handleOps` bundle transactions.
   * Must already hold native balance on `rpcUrl`'s chain.
   */
  readonly executorPrivateKey: Hex;
  /**
   * Funds the account Alto uses to deploy its deterministic-deployer and
   * EntryPoint/Pimlico simulation contracts on startup (`deploySimulationsContract.ts`
   * in the pinned Alto's own source — enabled by default, `--deploy-simulations-contract`).
   * Must already hold native balance on `rpcUrl`'s chain.
   */
  readonly utilityPrivateKey: Hex;
}

export interface AltoHandle {
  readonly url: string;
}

/**
 * Polls Alto's `/health` endpoint (its own liveness route,
 * `esm/rpc/server.js`'s `fastify.get("/health", ...)`) until it answers, or
 * the child process exits first. Alto's CLI has no equivalent to anvil's
 * "Listening on ..." stdout line this repo's `spawnAnvil` parses, so
 * readiness here is observed the same way a real integrator would: by
 * asking the bundler's own health route, not by racing a fixed sleep.
 */
async function waitForAltoReady(
  child: ChildProcessByStdio<null, Readable, Readable>,
  url: string,
  timeoutMs: number,
): Promise<void> {
  let output = "";
  const onData = (chunk: Buffer): void => {
    output += chunk.toString("utf8");
  };
  child.stdout.on("data", onData);
  child.stderr.on("data", onData);

  const deadline = Date.now() + timeoutMs;
  let exited = false;
  const onExit = (): void => {
    exited = true;
  };
  child.once("exit", onExit);

  try {
    while (Date.now() < deadline) {
      if (exited) {
        throw new AltoStartupError("process exited before becoming ready", output);
      }
      try {
        const response = await fetch(`${url}/health`);
        if (response.ok) return;
      } catch {
        // Not listening yet; retry until the deadline.
      }
      await new Promise((resolve) => setTimeout(resolve, 200));
    }
  } finally {
    child.off("exit", onExit);
  }
  throw new AltoStartupError(`no healthy response within ${timeoutMs}ms`, output);
}

/**
 * Spawns the pinned `@pimlico/alto` bundler (`sdk/package.json`) against an
 * already-running anvil (or other EVM node) with the target EntryPoint(s)
 * already deployed at `rpcUrl`. Binds an OS-discovered free port (see
 * {@link findFreePort}) so parallel test runs never collide on a fixed one,
 * and is torn down by the shared `afterEach` above on pass or fail, same
 * guarantee `spawnAnvil` gives.
 *
 * Passes `--safe-mode false`, OVERRIDING the pinned version's own default of
 * `true` (`esm/cli/config/options.js`, "Enable safe mode (enforcing all
 * ERC-4337 rules)") — a deliberate, verified-necessary deviation, not a
 * convenience default kept out of laziness. With `--safe-mode true` (the
 * default this task originally tried), Alto's `SafeValidator`
 * (`esm/rpc/validation/SafeValidator.js`) validates the ERC-7562
 * opcode/storage-access rules via `debug_traceCall` with an inline
 * JavaScript tracer body (`esm/rpc/validation/BundlerCollectorTracerV07.js`,
 * the same Go-Ethereum "custom JS tracer" mechanism `eth-infinitism`'s own
 * reference bundler uses). Anvil's `debug_traceCall` does not implement
 * arbitrary inline JS tracers (only its fixed set of built-in tracer names),
 * so EVERY `eth_sendUserOperation` under safe mode fails identically,
 * regardless of the UserOperation's own content:
 *
 * ```
 * err: { message: "unsupported tracer type", code: -32602 }
 * "error reply (non-rpc)" ... "InvalidParamsRpcError"
 * ```
 *
 * This is confirmed to be an Anvil/Alto tooling gap, not a Glaux
 * storage-access violation: Alto's own upstream docs name this exact
 * limitation ("Run Geth node or any other node that support
 * debug_traceCall" for testing against `bundler-spec-tests`'
 * `--safe-mode true`), and Alto's own local-dev tooling
 * (`scripts/run-local-instance.sh` + `scripts/config.local.json`) ships
 * `"safe-mode": false` for exactly this reason — pairing Alto with a local
 * Anvil/Hardhat node. `--safe-mode false` still exercises everything this
 * task actually asks for — a real, independent bundler implementation's
 * JSON-RPC surface, its own mempool/staking/gas-limit checks, and its own
 * bundling and inclusion logic — it only skips the ERC-7562 opcode-banning
 * layer that upstream's own tooling says needs a Geth-family node. Full
 * opcode-banning coverage against Glaux is therefore an open gap, not
 * something this task silently papers over: see `sdk/test/bundler.e2e.test.ts`'s
 * suite-level doc comment and Task 11's report.
 */
export async function spawnAlto(options: SpawnAltoOptions): Promise<AltoHandle> {
  const port = await findFreePort();
  const url = `http://127.0.0.1:${port}`;

  const child = spawn(
    ALTO_BIN,
    [
      "--entrypoints",
      options.entryPoints.join(","),
      "--rpc-url",
      options.rpcUrl,
      "--executor-private-keys",
      options.executorPrivateKey,
      "--utility-private-key",
      options.utilityPrivateKey,
      "--port",
      String(port),
      "--min-executor-balance",
      "0",
      "--safe-mode",
      "false",
      "--log-level",
      "error",
    ],
    { stdio: ["ignore", "pipe", "pipe"] },
  );
  runningAltos.add(child);
  child.once("exit", () => runningAltos.delete(child));

  await waitForAltoReady(child, url, 60_000);

  return { url };
}
