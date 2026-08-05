import { readFileSync, readdirSync } from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { P256_PROBE_VECTOR } from "../src/eligibility/probes.js";
import fixtures from "../../test/fixtures/sdk_parity.json" with { type: "json" };

const PACKAGE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SOURCE_ROOT = join(PACKAGE_ROOT, "src");

function sourceFiles(directory: string): string[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) return sourceFiles(path);
    return entry.isFile() && entry.name.endsWith(".ts") ? [path] : [];
  });
}

/**
 * Relative module specifiers of a TypeScript source file: the `from "..."` of
 * `import`/`export` statements and the argument of dynamic `import("...")`.
 * `tsc` copies these into the emitted JavaScript verbatim, so a specifier that
 * leaves the package directory here leaves it in `dist/` too.
 */
function relativeSpecifiers(source: string): string[] {
  const found: string[] = [];
  const pattern = /(?:\bfrom\s*|\bimport\s*\(\s*)(["'])(\.[^"']*)\1/gu;
  for (const match of source.matchAll(pattern)) {
    found.push(match[2]!);
  }
  return found;
}

describe("published package", () => {
  /**
   * `npm pack` cannot include a file that sits outside the package directory,
   * so a source file reaching above `sdk/` compiles and tests fine in this repo
   * and then throws `ERR_MODULE_NOT_FOUND` for every consumer of the published
   * tarball. Nothing in the local build catches this — the offending path
   * exists here and only here — which is why it is asserted directly.
   */
  it("has no source module reaching outside the package directory", () => {
    const escaping = sourceFiles(SOURCE_ROOT).flatMap((file) =>
      relativeSpecifiers(readFileSync(file, "utf8"))
        .filter((specifier) => {
          const target = relative(PACKAGE_ROOT, resolve(dirname(file), specifier));
          return target === ".." || target.startsWith(`..${sep}`);
        })
        .map((specifier) => `${relative(PACKAGE_ROOT, file)} -> ${specifier}`),
    );

    expect(escaping).toEqual([]);
  });

  /**
   * The price of inlining the P-256 probe vector into `src/`: the contract
   * remains its only source of truth, so the copy has to be pinned to the
   * fixture `test/SdkParity.t.sol` emits. Without this, a vector regenerated on
   * the Solidity side would leave the SDK probing with words the chain's
   * verifier rejects — every chain read as P-256-incapable, and the eligibility
   * gate the README makes mandatory would refuse every address.
   */
  it("keeps the inlined P-256 probe vector equal to the contract-emitted fixture", () => {
    expect(P256_PROBE_VECTOR).toEqual({
      digest: fixtures.p256Probe.digest,
      r: fixtures.p256Probe.r,
      s: fixtures.p256Probe.s,
      qx: fixtures.p256Probe.qx,
      qy: fixtures.p256Probe.qy,
    });
  });
});
