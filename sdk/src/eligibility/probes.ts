import { keccak256, stringToBytes, toHex, type Address, type Hex, type PublicClient } from "viem";
import { designator } from "../core/constants.js";

/**
 * RIP-7212 / EIP-7951 P-256 verifier precompile address. Mirrors
 * `SignatureVerify.P256_VERIFIER` in `src/lib/SignatureVerify.sol`.
 */
export const P256_VERIFIER: Address = "0x0000000000000000000000000000000000000100";

/**
 * Known-answer P-256 vector: a valid signature `(r, s)` over `digest` by
 * public key `(qx, qy)`, whose private key is public. Mirrors
 * `test/P256Fixture.sol` (`P256_DIG`/`P256_R`/`P256_S`/`P256_QX`/`P256_QY`) —
 * a fixed vector meant only for probing the precompile, never for installing
 * as a real factor.
 */
const PROBE_DIGEST: Hex = "0x547c05d9093cf1004d4426a5d03202cf500c22777a87f05c18ac247e38fc572e";
const PROBE_R: Hex = "0x56464d0bb7014173461871178e264acd5e981572bc495d8978bb5b16ca4895bb";
const PROBE_S: Hex = "0x1018fa59ce5f3bdd39e7df090dd93309be390b068a7cd3123a492cccd3524e5d";
const PROBE_QX: Hex = "0xc9b91be23306ebbd29f0f1718a1db88a151200eb10c6aad04aa24f8006704de6";
const PROBE_QY: Hex = "0x0accddfa8e09bddc03677b1f83a1d4aced4155d44ca7c1fd5226b8d312b7de6f";

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

async function p256Answers(client: PublicClient, digest: Hex): Promise<boolean> {
  const { data } = await client
    .call({ to: P256_VERIFIER, data: encodeP256Calldata(digest) })
    .catch(() => ({ data: undefined as Hex | undefined }));
  // Mirrors `SignatureVerify._p256Verify`: only a full 32-byte word equal to
  // 1 counts as success. A short/empty return (no code at the address, or a
  // conforming verifier's rejection) and anything else both read as failure.
  return data !== undefined && data.length === 66 && BigInt(data) === 1n;
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
export async function probeP256(client: PublicClient): Promise<boolean> {
  const [accepted, rejectedFlipped] = await Promise.all([
    p256Answers(client, PROBE_DIGEST),
    p256Answers(client, flipLowestBit(PROBE_DIGEST)).then((accepts) => !accepts),
  ]);
  return accepted && rejectedFlipped;
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
// entries (verifierType, then the `bytes data` head) at STORAGE_SLOT+1..+6 —
// eight namespaced words in total, alongside IMPL_SLOT.
const STORAGE_SLOT = BigInt(keccak256(stringToBytes("glaux.account.v1.storage")));
const IMPL_SLOT: Hex = keccak256(stringToBytes("glaux.account.v1.implementation"));
const STORAGE_HEADER_WORDS = 7;

function isNonZeroWord(word: Hex | undefined): boolean {
  return word !== undefined && BigInt(word) !== 0n;
}

/**
 * True when `account`'s code is exactly the EIP-7702 delegation designator
 * for Glaux's router AND its namespaced storage is non-zero — the same
 * pristine-account gate `scripts/submit_birth.py:preflight_fresh_account`
 * runs before a birth blob can be submitted, read here in reverse: this
 * account already went through it. `eth_getCode` returns lowercase, and so
 * does `designator()`, so this is a plain string comparison — never
 * checksum either side.
 */
export async function probeAccountBorn(client: PublicClient, account: Address): Promise<boolean> {
  const code = await client.getCode({ address: account });
  if (code !== designator()) return false;
  const implWord = await client.getStorageAt({ address: account, slot: IMPL_SLOT });
  if (!isNonZeroWord(implWord)) return false;
  const headerWords = await Promise.all(
    Array.from({ length: STORAGE_HEADER_WORDS }, (_, offset) =>
      client.getStorageAt({
        address: account,
        slot: toHex(STORAGE_SLOT + BigInt(offset), { size: 32 }),
      }),
    ),
  );
  return headerWords.every(isNonZeroWord);
}
