import { spawn, type ChildProcessByStdio } from "node:child_process";
import type { Readable } from "node:stream";
import { createPublicClient, createTestClient, http, type PublicClient, type TestClient } from "viem";
import { afterEach } from "vitest";

/**
 * Shared anvil process lifecycle, extracted unchanged from
 * `sdk/test/eligibility.test.ts` so every e2e SDK test suite reuses one
 * harness rather than re-inventing it. Every scenario spawns its own anvil
 * on an OS-assigned port and MUST tear it down, on pass or fail, so failures
 * never leak a listening process or claim a fixed port. Because Vitest gives
 * each test file its own isolated module graph, importing this module from
 * two different test files still yields two independent `runningAnvils`
 * sets and two independent `afterEach` registrations, each scoped to its own
 * file's suite — exactly as if the code still lived inline in each file.
 */
const runningAnvils = new Set<ChildProcessByStdio<null, Readable, Readable>>();

async function stopAnvil(child: ChildProcessByStdio<null, Readable, Readable>): Promise<void> {
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
  if (await exited(1_000)) return;
  child.kill("SIGKILL");
  if (!(await exited(1_000))) throw new Error("anvil did not exit after SIGKILL");
}

afterEach(async () => {
  await Promise.all([...runningAnvils].map(stopAnvil));
  runningAnvils.clear();
});

export interface AnvilHandle {
  readonly url: string;
}

const LISTENING_RE = /Listening on 127\.0\.0\.1:(\d+)/;

export interface SpawnAnvilOptions {
  /**
   * Overrides anvil's default chain id (31337). Added for
   * `sdk/test/replay.e2e.test.ts`, which needs two anvils with genuinely
   * different chain ids to prove the same birth blob replays across chains
   * rather than merely across two identically-configured nodes. Omitted,
   * behavior is unchanged from before this option existed.
   */
  readonly chainId?: number;
}

/**
 * Spawns a fresh anvil on an OS-assigned port (`--port 0`, so parallel runs
 * never collide) pinned to `--hardfork prague`. Pinning matters: a bare
 * modern anvil already answers P-256 at `0x100` natively (its own default
 * "latest" hardfork has picked up EIP-7951/RIP-7212), which would make tests
 * that need a *controlled* verifier at that address untestable —
 * `anvil_setCode` cannot override a host-implemented precompile, so the only
 * way to put a *contract* at `0x100` under test control is a hardfork old
 * enough not to have the precompile baked in. `prague` already has EIP-7702
 * (needed for every authorization tuple these suites sign) but predates the
 * P-256 precompile — matching `docs/deployments.md`'s local two-chain proof,
 * which etches the same vendored Solidity verifier for the same reason.
 */
export async function spawnAnvil(options: SpawnAnvilOptions = {}): Promise<AnvilHandle> {
  const args = ["--port", "0", "--hardfork", "prague"];
  if (options.chainId !== undefined) args.push("--chain-id", String(options.chainId));
  const child = spawn("anvil", args, {
    stdio: ["ignore", "pipe", "pipe"],
  });
  runningAnvils.add(child);
  child.once("exit", () => runningAnvils.delete(child));

  const url = await new Promise<string>((resolve, reject) => {
    let buffer = "";
    const onData = (chunk: Buffer): void => {
      buffer += chunk.toString("utf8");
      const match = LISTENING_RE.exec(buffer);
      if (match?.[1]) {
        child.stdout.off("data", onData);
        child.off("exit", onExit);
        resolve(`http://127.0.0.1:${match[1]}`);
      }
    };
    const onExit = (code: number | null): void => {
      reject(new Error(`anvil exited before it started listening (code ${code ?? "unknown"})`));
    };
    child.stdout.on("data", onData);
    child.once("error", reject);
    child.once("exit", onExit);
  });

  return { url };
}

/** `PublicClient` + `TestClient` (anvil mode) pair against one anvil's URL. */
export function clientsFor(url: string): { client: PublicClient; test: TestClient } {
  const transport = http(url);
  const client = createPublicClient({ transport });
  const test = createTestClient({ mode: "anvil", transport });
  return { client, test };
}
