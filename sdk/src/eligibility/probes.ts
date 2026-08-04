import { keccak256, stringToBytes, toHex, type Address, type Hex, type PublicClient } from "viem";
import { designator } from "../core/constants.js";
import fixtures from "../../../test/fixtures/sdk_parity.json" with { type: "json" };

/**
 * RIP-7212 / EIP-7951 P-256 verifier precompile address. Mirrors
 * `SignatureVerify.P256_VERIFIER` in `src/lib/SignatureVerify.sol`.
 */
export const P256_VERIFIER: Address = "0x0000000000000000000000000000000000000100";

/**
 * Known-answer P-256 vector emitted by `test/SdkParity.t.sol` from the
 * `SignatureVerify` probe. The parity test fails if this vector no longer
 * drives the contract's positive and flipped-negative calls.
 */
const PROBE_DIGEST = fixtures.p256Probe.digest as Hex;
const PROBE_R = fixtures.p256Probe.r as Hex;
const PROBE_S = fixtures.p256Probe.s as Hex;
const PROBE_QX = fixtures.p256Probe.qx as Hex;
const PROBE_QY = fixtures.p256Probe.qy as Hex;

function stripPrefix(hex: Hex): string {
  return hex.slice(2);
}

function encodeP256Calldata(digest: Hex): Hex {
  return `0x${stripPrefix(digest)}${stripPrefix(PROBE_R)}${stripPrefix(PROBE_S)}${stripPrefix(PROBE_QX)}${stripPrefix(PROBE_QY)}` as Hex;
}

/** XORs the digest's lowest bit, mirroring `PROBE_DIGEST ^ bytes32(uint256(1))`. */
function flipLowestBit(digest: Hex): Hex {
  return toHex(BigInt(digest) ^ 1n, { size: 32 });
}

type P256Answer = "success" | "rejected" | "transportFailure";

export interface P256ProbeResult {
  available: boolean;
  transportFailure: boolean;
}

async function p256Answers(client: PublicClient, digest: Hex): Promise<P256Answer> {
  let data: Hex | undefined;
  try {
    ({ data } = await client.call({ to: P256_VERIFIER, data: encodeP256Calldata(digest) }));
  } catch {
    return "transportFailure";
  }
  // Mirrors `SignatureVerify._p256Verify`: only a full 32-byte word equal to
  // 1 counts as success. A completed call returning anything else is verifier
  // rejection; it is deliberately distinct from a call that never executed.
  return data !== undefined && data.length === 66 && BigInt(data) === 1n ? "success" : "rejected";
}

/**
 * True when `0x100` both verifies a known-good P-256 signature and rejects
 * the SAME signature against a different digest. Mirrors
 * `SignatureVerify.p256VerifierAvailable`'s two-armed check: the positive arm
 * alone would accept a verifier that answers `1` unconditionally, which is
 * worse than no verifier at all — a P-256 factor guarded by it would accept
 * every signature ever presented to that slot. See that function's `@dev`
 * note for the full hazard this closes.
 */
export async function probeP256Result(client: PublicClient): Promise<P256ProbeResult> {
  const [accepted, flipped] = await Promise.all([
    p256Answers(client, PROBE_DIGEST),
    p256Answers(client, flipLowestBit(PROBE_DIGEST)),
  ]);
  const transportFailure = accepted === "transportFailure" || flipped === "transportFailure";
  return { available: !transportFailure && accepted === "success" && flipped === "rejected", transportFailure };
}

/** True only when both contract-mirroring verifier calls execute and discriminate. */
export async function probeP256(client: PublicClient): Promise<boolean> {
  return (await probeP256Result(client)).available;
}

const EIP7702_PROBE_TARGET: Address = "0x000000000000000000000000000000000000dEaD";
// Well-shaped but never-valid signature words: an authorization tuple is
// priced whether or not it recovers to a real signer (docs/deployments.md:
// "Both nodes parse and account for an authorization list"), so this never
// needs to be valid, and it is never broadcast.
const DUMMY_SIGNATURE_WORD: Hex = toHex(1n, { size: 32 });

/**
 * True when this chain's `eth_estimateGas` prices an EIP-7702 authorization
 * list distinctly from a bare call — the read-only mechanism verified live
 * against Sepolia and Base Sepolia on 2026-07-31 (`docs/deployments.md`):
 * one authorization attached costs a fixed amount more there. A chain that
 * does not honour the field either rejects the call outright or silently
 * ignores it (an identical estimate); both read as unsupported here.
 */
export async function probeEip7702(client: PublicClient): Promise<boolean> {
  const bareCall = { to: EIP7702_PROBE_TARGET, value: 0n } as const;
  const bare = await client.estimateGas(bareCall).catch(() => undefined);
  if (bare === undefined) return false;
  const withAuthorization = await client
    .estimateGas({
      ...bareCall,
      authorizationList: [
        {
          address: EIP7702_PROBE_TARGET,
          chainId: 0, // 0 = "valid on any chain" per EIP-7702; irrelevant to pricing.
          nonce: 0,
          r: DUMMY_SIGNATURE_WORD,
          s: DUMMY_SIGNATURE_WORD,
          yParity: 0,
        },
      ],
    })
    .catch(() => undefined);
  return withAuthorization !== undefined && withAuthorization > bare;
}

/** True when `address` has non-empty deployed code. */
export async function probeDeployedCode(client: PublicClient, address: Address): Promise<boolean> {
  const code = await client.getCode({ address });
  return code !== undefined && code !== "0x";
}

// Mirrors `GlauxStorage.SLOT`/`IMPL_SLOT` and `scripts/submit_birth.py`'s
// `STORAGE_SLOT`/`IMPL_SLOT`: a header word followed by three `FactorSlot`
// entries (verifierType, then the `bytes data` head) at STORAGE_SLOT+1..+6.
const STORAGE_SLOT = BigInt(keccak256(stringToBytes("glaux.account.v1.storage")));
const IMPL_SLOT: Hex = keccak256(stringToBytes("glaux.account.v1.implementation"));
const UINT160_MAX = (1n << 160n) - 1n;
const P256_P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const P256_A = P256_P - 3n;
const P256_B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;

function wordValue(word: Hex | undefined): bigint | undefined {
  return word === undefined ? undefined : BigInt(word);
}

function dynamicDataSlot(headSlot: bigint): Hex {
  return keccak256(toHex(headSlot, { size: 32 }));
}

function isValidSecp256k1Key(word: bigint | undefined): boolean {
  return word !== undefined && word !== 0n && word <= UINT160_MAX;
}

function isValidP256Key(qx: bigint | undefined, qy: bigint | undefined): boolean {
  if (qx === undefined || qy === undefined || qx >= P256_P || qy >= P256_P || (qx === 0n && qy === 0n)) {
    return false;
  }
  const lhs = (qy * qy) % P256_P;
  const rhs = ((((qx * qx) % P256_P) * qx + P256_A * qx + P256_B) % P256_P + P256_P) % P256_P;
  return lhs === rhs;
}

async function hasValidFactorSlot(
  client: PublicClient,
  account: Address,
  typeSlot: bigint,
  dataHeadSlot: bigint,
): Promise<boolean> {
  const [verifierType, dataHead] = await Promise.all([
    client.getStorageAt({ address: account, slot: toHex(typeSlot, { size: 32 }) }),
    client.getStorageAt({ address: account, slot: toHex(dataHeadSlot, { size: 32 }) }),
  ]);
  const type = wordValue(verifierType);
  const head = wordValue(dataHead);
  if (head === undefined || (head & 1n) !== 1n) return false;

  if (type === 1n && head === 65n) {
    return isValidSecp256k1Key(
      wordValue(await client.getStorageAt({ address: account, slot: dynamicDataSlot(dataHeadSlot) })),
    );
  }
  if (type === 2n && head === 129n) {
    const dataSlot = BigInt(dynamicDataSlot(dataHeadSlot));
    const [qx, qy] = await Promise.all([
      client.getStorageAt({ address: account, slot: toHex(dataSlot, { size: 32 }) }),
      client.getStorageAt({ address: account, slot: toHex(dataSlot + 1n, { size: 32 }) }),
    ]);
    return isValidP256Key(wordValue(qx), wordValue(qy));
  }
  return false;
}

/**
 * True only when `account` has the exact delegation designator and coherent
 * operational Glaux state: a code-bearing implementation, an initialized
 * layout header, and three well-formed factor slots. This is intentionally
 * stricter than non-zero storage: poisoned words are not evidence that an
 * account can execute or recover funds. `eth_getCode` returns lowercase, and
 * so does `designator()`, so this is a plain string comparison.
 */
export async function probeAccountBorn(client: PublicClient, account: Address): Promise<boolean> {
  const code = await client.getCode({ address: account });
  if (code !== designator()) return false;
  const implWord = await client.getStorageAt({ address: account, slot: IMPL_SLOT });
  const implementation = wordValue(implWord);
  if (implementation === undefined || implementation === 0n || implementation > UINT160_MAX) return false;
  const implementationCode = await client.getCode({ address: toHex(implementation, { size: 20 }) });
  if (implementationCode === undefined || implementationCode === "0x") return false;

  const header = wordValue(
    await client.getStorageAt({ address: account, slot: toHex(STORAGE_SLOT, { size: 32 }) }),
  );
  if (header === undefined || (header & 0xffn) !== 1n) return false;

  return (
    await Promise.all(
      Array.from({ length: 3 }, (_, index) =>
        hasValidFactorSlot(
          client,
          account,
          STORAGE_SLOT + 1n + BigInt(index * 2),
          STORAGE_SLOT + 2n + BigInt(index * 2),
        ),
      ),
    )
  ).every(Boolean);
}
