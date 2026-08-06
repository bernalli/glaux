import {
  concat,
  createPublicClient,
  encodeAbiParameters,
  getAddress,
  hexToBytes,
  http,
  keccak256,
  recoverAddress,
  size,
  toHex,
  type Address,
  type Hex,
} from "viem";
import { p256 } from "@noble/curves/nist.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { AUTH_MSG_HASH, IMPL, IMPL_CODE_HASH, ROOTLESS_S_PREFIX, ROUTER } from "../core/constants.js";
import { initDigest, registrationDigest } from "../core/digests.js";
import { encodeInitData } from "../core/encoding.js";
import { VERIFIER_P256, VERIFIER_SECP256K1, type BirthBlob, type FactorSlot } from "../core/types.js";
import {
  BirthBlobSelfCheckError,
  BirthPossessionProofError,
  DuplicateBirthSlotError,
  ImplementationCodeHashMismatchError,
  ImplementationCompatibilityError,
  ImplementationNotDeployedError,
  InvalidBirthSlotError,
  InvalidBirthVerifierTypeError,
  ProbeKeyNotInstallableError,
  RootlessDerivationError,
} from "../errors.js";
import type { Signer } from "../signers/signer.js";

// Task 6's public naming contract calls this helper `buildInitDigest`; retain
// the pre-existing core name as well, with one implementation and no drift.
export { initDigest as buildInitDigest } from "../core/digests.js";

/**
 * Builds the three pairwise-distinct factor slots — paper (secp256k1),
 * device (P-256), cloud (secp256k1), in that fixed order — from their
 * signers. Ported from `scripts/birth.py:build_slots`: each signer's
 * `keyData()` already produces the same `abi.encode(address)` /
 * `abi.encode(uint256 qx, uint256 qy)` shapes that function hand-encodes, so
 * this is a straight structural mapping rather than a re-encoding.
 */
export function buildSlots(factors: readonly [Signer, Signer, Signer]): [FactorSlot, FactorSlot, FactorSlot] {
  const [paper, device, cloud] = factors;
  return [
    { verifierType: paper.verifierType, data: paper.keyData() },
    { verifierType: device.verifierType, data: device.keyData() },
    { verifierType: cloud.verifierType, data: cloud.keyData() },
  ];
}

const UINT160_MAX = (1n << 160n) - 1n;
const SECP256K1_N_DIV_2 = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0n;
const P256_P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const P256_A = P256_P - 3n;
const P256_B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;
const PROBE_QX = 0x6e116efa770f5c5455124d86df9b00525dab28db280c3c8f33bb64c0ef313489n;
const PROBE_QY = 0x8961e3da77e0f8d247f099835070289b64906c509ec256eec976858516ae8d81n;
const COMPATIBILITY_ID = keccak256(new TextEncoder().encode("GLAUX_ACCOUNT_V1"));

function isHexBytes(value: unknown): value is Hex {
  return typeof value === "string" && /^0x(?:[0-9a-fA-F]{2})*$/u.test(value);
}

function validP256Key(data: Hex): boolean {
  if (size(data) !== 64) return false;
  const qx = BigInt(`0x${data.slice(2, 66)}`);
  const qy = BigInt(`0x${data.slice(66)}`);
  if (qx >= P256_P || qy >= P256_P || (qx === 0n && qy === 0n)) return false;
  const lhs = (qy * qy) % P256_P;
  const xSquared = (qx * qx) % P256_P;
  const rhs = (((xSquared * qx + P256_A * qx + P256_B) % P256_P) + P256_P) % P256_P;
  return lhs === rhs;
}

/** Mirrors `GlauxAccount._validateSlot`'s locally decidable slot checks. */
function validateSlot(slot: FactorSlot, index: number): void {
  if (slot.verifierType !== VERIFIER_SECP256K1 && slot.verifierType !== VERIFIER_P256) {
    throw new InvalidBirthVerifierTypeError(index);
  }
  if (!isHexBytes(slot.data)) throw new InvalidBirthSlotError(index);
  if (slot.verifierType === VERIFIER_SECP256K1) {
    if (size(slot.data) !== 32 || BigInt(slot.data) === 0n || BigInt(slot.data) > UINT160_MAX) {
      throw new InvalidBirthSlotError(index);
    }
    return;
  }
  if (!validP256Key(slot.data)) throw new InvalidBirthSlotError(index);
  const qx = BigInt(`0x${slot.data.slice(2, 66)}`);
  const qy = BigInt(`0x${slot.data.slice(66)}`);
  if (qx === PROBE_QX && qy === PROBE_QY) throw new ProbeKeyNotInstallableError(index);
}

function validateDistinctSlots(slots: readonly [FactorSlot, FactorSlot, FactorSlot]): void {
  for (let first = 0; first < slots.length; first += 1) {
    for (let second = first + 1; second < slots.length; second += 1) {
      const a = slots[first]!;
      const b = slots[second]!;
      if (a.verifierType === b.verifierType && a.data.toLowerCase() === b.data.toLowerCase()) {
        throw new DuplicateBirthSlotError(first, second);
      }
    }
  }
}

async function validatePossessionProof(slot: FactorSlot, proof: Hex, index: number): Promise<void> {
  const digest = registrationDigest(index, slot.verifierType, slot.data);
  try {
    if (slot.verifierType === VERIFIER_SECP256K1) {
      const v = Number(`0x${proof.slice(130)}`);
      if (
        size(proof) !== 65 ||
        BigInt(`0x${proof.slice(66, 130)}`) > SECP256K1_N_DIV_2 ||
        (v !== 27 && v !== 28)
      ) {
        throw new BirthPossessionProofError(index);
      }
      const recovered = await recoverAddress({ hash: digest, signature: proof });
      const expected = getAddress(`0x${slot.data.slice(-40)}` as Hex);
      if (recovered !== expected) throw new BirthPossessionProofError(index);
      return;
    }
    // `lowS: false` mirrors the contract, which is NOT symmetric across the two
    // curves: `_verifySecp256k1` rejects `s > n/2` itself (checked above), while
    // `_verifyP256` hands `r, s` straight to the RIP-7212/EIP-7951 precompile,
    // which accepts either form. `@noble/curves` defaults to rejecting high-`s`,
    // so leaving the default here would refuse proofs the chain accepts — and
    // the primary production factor, a Secure Enclave, does not normalise `s`.
    if (
      size(proof) !== 64 ||
      !p256.verify(hexToBytes(proof), hexToBytes(digest), hexToBytes(`0x04${slot.data.slice(2)}`), {
        prehash: false,
        lowS: false,
      })
    ) {
      throw new BirthPossessionProofError(index);
    }
  } catch (error) {
    if (error instanceof BirthPossessionProofError) throw error;
    throw new BirthPossessionProofError(index);
  }
}

/**
 * Signs one possession proof per factor and ABI-encodes the
 * `(FactorSlot[3], bytes[3])` blob `GlauxAccount.initializeAccount` decodes
 * as `initData`. Ported from `scripts/birth.py:build_init_data`, except the
 * proofs are produced here rather than accepted as an argument: this SDK
 * already has `registrationProof` (`../signers/signer.js`) to do exactly
 * that, so there is nothing to re-implement.
 */
export async function buildInitData(
  slots: readonly [FactorSlot, FactorSlot, FactorSlot],
  factors: readonly [Signer, Signer, Signer],
): Promise<Hex> {
  const proofs = await Promise.all(factors.map((signer, index) => signer.sign(registrationDigest(index, slots[index]!.verifierType, slots[index]!.data))));
  return encodeInitData(slots, proofs as [Hex, Hex, Hex]);
}

/** Largest value the 19-byte tail of a tagged `s` can hold. */
const ROOTLESS_TAIL_MASK = (1n << 152n) - 1n;
/**
 * Attempts before giving up. Roughly half of candidate `r` values are not
 * curve x-coordinates, so two attempts is the expected cost and 256 is
 * unreachable in practice — it exists so a derivation can never spin forever.
 */
const MAX_CRAFT_ATTEMPTS = 256;

export interface RootlessAuthorization {
  /** The address this proof recovers to — the account, derived not chosen. */
  readonly account: Address;
  readonly salt: Hex;
  readonly r: Hex;
  readonly s: Hex;
  readonly yParity: 0;
}

/**
 * Builds the EIP-7702 authorization for an account whose private key never
 * existed, mirroring `GlauxDelegate.initialize`'s own reconstruction.
 *
 * The signature is assembled backwards instead of signed: `r` is fixed to a
 * hash committing to this exact birth configuration, `s` is tagged with the
 * router's constant prefix, and `ecrecover` then reveals which address that
 * pair is valid for — that address becomes the account. Nobody can hold its
 * key, because producing this signature from a key would require a nonce `k`
 * with `x(kG) = r` for a hash-chosen `r`.
 *
 * `yParity` is always 0: when `r` is a valid x-coordinate the recovery id 27
 * succeeds, and when it is not, no recovery id does — so the salt is advanced
 * instead. The router hard-codes the same constant.
 *
 * `authMsgHash` defaults to the canonical router's. It is a parameter only so
 * a test network running its own router deployment can derive against it; on
 * any real chain the router is at one deterministic address and the default is
 * the only correct value.
 *
 * @throws {RootlessDerivationError} if 256 salts yield no curve point, which
 * would mean the hash function had failed, not the caller.
 */
export function craftRootlessAuthorization(
  digest: Hex,
  authMsgHash: Hex = AUTH_MSG_HASH,
): RootlessAuthorization {
  for (let attempt = 0; attempt < MAX_CRAFT_ATTEMPTS; attempt += 1) {
    const salt = keccak256(
      encodeAbiParameters([{ type: "bytes32" }, { type: "uint256" }], [digest, BigInt(attempt)]),
    );
    const r = keccak256(encodeAbiParameters([{ type: "bytes32" }, { type: "bytes32" }], [digest, salt]));
    // The tag owns the top 13 bytes; shifting the tail hash down by 104 bits
    // leaves exactly the low 19, so the two can never overlap.
    const tail =
      BigInt(
        keccak256(
          encodeAbiParameters(
            [{ type: "bytes32" }, { type: "bytes32" }, { type: "uint8" }],
            [digest, salt, 1],
          ),
        ),
      ) >> 104n;
    const s = toHex((ROOTLESS_S_PREFIX << 152n) | (tail & ROOTLESS_TAIL_MASK), { size: 32 });

    const account = recoverPublicKeyAddress(r, s, authMsgHash);
    if (account !== null) return { account, salt, r, s, yParity: 0 };
  }
  throw new RootlessDerivationError(digest, MAX_CRAFT_ATTEMPTS);
}

/**
 * The address `(r, s)` recovers to against `authMsgHash`, or `null` when `r`
 * is not a curve x-coordinate — the outcome that simply costs one more salt,
 * never an error.
 */
function recoverPublicKeyAddress(r: Hex, s: Hex, authMsgHash: Hex): Address | null {
  try {
    const point = secp256k1.Signature.fromBytes(
      hexToBytes(concat([r, s])),
      "compact",
    ).addRecoveryBit(0).recoverPublicKey(hexToBytes(authMsgHash));
    return getAddress(`0x${keccak256(`0x${point.toHex(false).slice(2)}`).slice(-40)}`);
  } catch {
    return null;
  }
}

export interface BuildBirthBlobParams {
  /** The three factor signers, in fixed order: paper, device, cloud. */
  readonly factors: readonly [Signer, Signer, Signer];
  /** JSON-RPC endpoint used ONLY to read `IMPL`'s live deployed code. */
  readonly chainRpc: string;
}

/**
 * Crafts the EIP-7702 authorization tuple (chain-agnostic: `chainId 0`,
 * `nonce 0`, naming the canonical `ROUTER`) against the chain-agnostic init
 * digest, and returns the full birth blob — ported from
 * `scripts/birth.py:build_birth_blob`. JSON field names are identical to
 * that function's return dict, so a blob built here is submittable by
 * `scripts/submit_birth.py` unchanged (see `sdk/test/birth.e2e.test.ts`'s
 * schema-parity test).
 *
 * No key is generated here and none is destroyed afterwards, because none ever
 * exists: `r` is derived from the init digest, `s` carries the router's
 * rootless tag, and the account is the address that pair recovers to. That is
 * what closes the hazard `docs/threat-model.md` records as residual 1 — a
 * surviving birth key would have been a permanent master key.
 *
 * `expectedCodeHash` is read LIVE from `chainRpc` (`keccak256` of `IMPL`'s
 * deployed bytecode), never assumed from a local build artifact — the same
 * rule `docs/client-guidance.md`'s Birth section states for a human operator
 * ("verify the implementation is deployed... before broadcasting").
 *
 * @throws {ImplementationNotDeployedError} if `IMPL` has no code on `chainRpc`.
 */
export async function buildBirthBlob({ factors, chainRpc }: BuildBirthBlobParams): Promise<BirthBlob> {
  const slots = buildSlots(factors);
  slots.forEach((slot, index) => validateSlot(slot, index));
  validateDistinctSlots(slots);

  const client = createPublicClient({ transport: http(chainRpc) });
  const implementationCode = await client.getCode({ address: IMPL });
  if (implementationCode === undefined || implementationCode === "0x") {
    throw new ImplementationNotDeployedError(IMPL);
  }
  const expectedCodeHash = keccak256(implementationCode);
  if (expectedCodeHash !== IMPL_CODE_HASH) throw new ImplementationCodeHashMismatchError(expectedCodeHash);
  if (implementationCode.slice(0, 4).toLowerCase() === "0xef") throw new ImplementationCompatibilityError();
  try {
    const compatibilityId = await client.readContract({
      address: IMPL,
      abi: [{ type: "function", name: "glauxCompatibilityId", stateMutability: "view", inputs: [], outputs: [{ type: "bytes32" }] }],
      functionName: "glauxCompatibilityId",
    });
    if (compatibilityId !== COMPATIBILITY_ID) throw new ImplementationCompatibilityError();
  } catch (error) {
    if (error instanceof ImplementationCompatibilityError) throw error;
    throw new ImplementationCompatibilityError();
  }

  const proofs = await Promise.all(factors.map((signer, index) => signer.sign(registrationDigest(index, slots[index]!.verifierType, slots[index]!.data))));
  await Promise.all(proofs.map((proof, index) => validatePossessionProof(slots[index]!, proof, index)));
  const initData = encodeInitData(slots, proofs as [Hex, Hex, Hex]);

  // No key is generated here, and none is destroyed afterwards, because none
  // ever exists: the account address falls out of the configuration above.
  const digest = initDigest(ROUTER, IMPL, expectedCodeHash, initData);
  const authorization = craftRootlessAuthorization(digest);

  // Same self-check as before, now over the crafted tuple: recompute the
  // recovery from the blob's OWN fields and require it to be the account. A
  // blob whose parts disagree is never handed to a caller.
  if (assertRecoversTo(digest, authorization.salt, authorization.s, authorization.account) === false) {
    throw new BirthBlobSelfCheckError("authorization");
  }

  return {
    account: authorization.account,
    router: ROUTER,
    implementation: IMPL,
    expectedCodeHash,
    authorization: {
      chainId: 0,
      address: ROUTER,
      nonce: 0,
      yParity: authorization.yParity,
      r: authorization.r,
      s: authorization.s,
    },
    initData,
    salt: authorization.salt,
  };
}

/**
 * Recomputes `r` from `digest` and `salt` exactly as `GlauxDelegate.initialize`
 * does, checks the router's tag on `s`, and reports whether the resulting
 * authorization recovers to `expected`.
 *
 * This is the whole of the router's authentication, re-run locally. It is what
 * lets a client refuse a blob before spending a relayer's gas on a birth the
 * chain would reject — and, for a blob that arrived from elsewhere, before
 * trusting that its `account` field means anything at all.
 */
export function assertRecoversTo(
  digest: Hex,
  salt: Hex,
  s: Hex,
  expected: Address,
  authMsgHash: Hex = AUTH_MSG_HASH,
): boolean {
  if ((BigInt(s) >> 152n) !== ROOTLESS_S_PREFIX) return false;
  const r = keccak256(encodeAbiParameters([{ type: "bytes32" }, { type: "bytes32" }], [digest, salt]));
  const recovered = recoverPublicKeyAddress(r, s, authMsgHash);
  return recovered !== null && recovered === getAddress(expected);
}
