import { createPublicClient, getAddress, hexToBytes, http, keccak256, recoverAddress, size, type Hex } from "viem";
import { recoverAuthorizationAddress } from "viem/utils";
import { p256 } from "@noble/curves/nist.js";
import { generatePrivateKey, privateKeyToAddress, sign, signAuthorization } from "viem/accounts";
import { IMPL, IMPL_CODE_HASH, ROUTER } from "../core/constants.js";
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
    if (size(proof) !== 64 || !p256.verify(hexToBytes(proof), hexToBytes(digest), hexToBytes(`0x04${slot.data.slice(2)}`), { prehash: false })) {
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

/**
 * Signs `digest` with the ephemeral birth key using a raw (non-EIP-191)
 * secp256k1 signature — ported from `scripts/birth.py:sign_birth_digest`.
 * Returns the 65-byte `r || s || v` signature `GlauxDelegate.initialize`
 * recovers directly against `address(this)` (the birth key IS the delegated
 * EOA's own key). Unlike the Python side, no defensive low-s/`v` assertions
 * are needed here: `viem`'s `sign` already guarantees canonical low-s,
 * `v ∈ {27, 28}` output by construction (the same primitive
 * `LocalSecp256k1Signer.sign` relies on, verified by `sdk/test/signers.test.ts`).
 */
export function signBirthDigest(privateKey: Hex, digest: Hex): Promise<Hex> {
  return sign({ hash: digest, privateKey, to: "hex" });
}

export interface BuildBirthBlobParams {
  /** The three factor signers, in fixed order: paper, device, cloud. */
  readonly factors: readonly [Signer, Signer, Signer];
  /** JSON-RPC endpoint used ONLY to read `IMPL`'s live deployed code. */
  readonly chainRpc: string;
}

/**
 * Generates the ephemeral birth key, signs the EIP-7702 authorization tuple
 * (chain-agnostic: `chainId 0`, `nonce 0`, naming the canonical `ROUTER`) and
 * the chain-agnostic init digest, and returns the full birth blob — ported
 * from `scripts/birth.py:build_birth_blob`. JSON field names are identical to
 * that function's return dict, so a blob built here is submittable by
 * `scripts/submit_birth.py` unchanged (see `sdk/test/birth.e2e.test.ts`'s
 * schema-parity test).
 *
 * The birth key exists only in this function's stack: it is generated, used
 * for exactly two signatures, and never returned or persisted. See
 * `docs/client-guidance.md`'s "A surviving birth key is a permanent master
 * key" for why that matters.
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

  const birthPrivateKey = generatePrivateKey();
  const account = privateKeyToAddress(birthPrivateKey);

  const signedAuthorization = await signAuthorization({
    address: ROUTER,
    chainId: 0,
    nonce: 0,
    privateKey: birthPrivateKey,
  });

  const digest = initDigest(ROUTER, IMPL, expectedCodeHash, initData);
  const birthSig = await signBirthDigest(birthPrivateKey, digest);

  // `signAuthorization`'s return type allows either `yParity` or the
  // deprecated `v` (a `OneOf` union), even though `viem`'s own secp256k1
  // signer always populates both at runtime; the fallback below only ever
  // exercises the standard `v - 27` mapping if a future `viem` version ever
  // omitted `yParity`.
  const yParity = signedAuthorization.yParity ?? Number(signedAuthorization.v ?? 27n) - 27;

  try {
    const [birthSigner, authorizationSigner] = await Promise.all([
      recoverAddress({ hash: digest, signature: birthSig }),
      recoverAuthorizationAddress({ authorization: { ...signedAuthorization, yParity } }),
    ]);
    if (birthSigner !== account) throw new BirthBlobSelfCheckError("birth signature");
    if (authorizationSigner !== account) throw new BirthBlobSelfCheckError("authorization");
  } catch (error) {
    if (error instanceof BirthBlobSelfCheckError) throw error;
    throw new BirthBlobSelfCheckError("birth signature");
  }

  return {
    account,
    router: ROUTER,
    implementation: IMPL,
    expectedCodeHash,
    authorization: {
      chainId: signedAuthorization.chainId,
      address: signedAuthorization.address,
      nonce: signedAuthorization.nonce,
      yParity,
      r: signedAuthorization.r,
      s: signedAuthorization.s,
    },
    initData,
    birthSig,
  };
}
