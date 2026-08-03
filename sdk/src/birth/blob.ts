import { createPublicClient, http, keccak256, type Hex } from "viem";
import { generatePrivateKey, privateKeyToAddress, sign, signAuthorization } from "viem/accounts";
import { IMPL, ROUTER } from "../core/constants.js";
import { initDigest } from "../core/digests.js";
import { encodeInitData } from "../core/encoding.js";
import type { BirthBlob, FactorSlot } from "../core/types.js";
import { ImplementationNotDeployedError } from "../errors.js";
import { registrationProof, type Signer } from "../signers/signer.js";

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
  const proofs = await Promise.all(factors.map((signer, index) => registrationProof(signer, index)));
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
  const client = createPublicClient({ transport: http(chainRpc) });
  const implementationCode = await client.getCode({ address: IMPL });
  if (implementationCode === undefined || implementationCode === "0x") {
    throw new ImplementationNotDeployedError(IMPL);
  }
  const expectedCodeHash = keccak256(implementationCode);

  const birthPrivateKey = generatePrivateKey();
  const account = privateKeyToAddress(birthPrivateKey);

  const signedAuthorization = await signAuthorization({
    address: ROUTER,
    chainId: 0,
    nonce: 0,
    privateKey: birthPrivateKey,
  });

  const slots = buildSlots(factors);
  const initData = await buildInitData(slots, factors);
  const digest = initDigest(ROUTER, IMPL, expectedCodeHash, initData);
  const birthSig = await signBirthDigest(birthPrivateKey, digest);

  // `signAuthorization`'s return type allows either `yParity` or the
  // deprecated `v` (a `OneOf` union), even though `viem`'s own secp256k1
  // signer always populates both at runtime; the fallback below only ever
  // exercises the standard `v - 27` mapping if a future `viem` version ever
  // omitted `yParity`.
  const yParity = signedAuthorization.yParity ?? Number(signedAuthorization.v ?? 27n) - 27;

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
