import { concat, encodeAbiParameters, keccak256, type Address, type Hex } from "viem";
import { DOMAINS } from "./constants.js";
import type { Call, VerifierType } from "./types.js";
import { OperationExpiredError } from "../errors.js";

export { DOMAINS } from "./constants.js";

/**
 * EIP-191 personal-sign-style digest used by Glaux's v0 signature scheme:
 * `keccak256(0x19 || 0x00 || validator || structHash)`.
 */
export function eip191v0(validator: Address, structHash: Hex): Hex {
  return keccak256(concat(["0x1900", validator, structHash]));
}

/**
 * The digest a candidate key must sign to prove it exists before it can be
 * installed into a factor slot. Ported from
 * `GlauxAccount._requirePossession`/`scripts/birth.py:registration_digest`:
 * `keccak256(abi.encode(REG_DOMAIN, index, verifierType, keccak256(keyData)))`.
 *
 * Deliberately NOT wrapped in `eip191v0` and takes no validator/account: the
 * proof binds neither a chain id nor an account address, so it must be
 * producible before the account exists (see the `@dev` notes on
 * `GlauxAccount._requirePossession`).
 */
export function registrationDigest(index: number, verifierType: VerifierType, keyData: Hex): Hex {
  return keccak256(
    encodeAbiParameters(
      [{ type: "bytes32" }, { type: "uint8" }, { type: "uint8" }, { type: "bytes32" }],
      [DOMAINS.REG, index, verifierType, keccak256(keyData)],
    ),
  );
}

/**
 * The chain-agnostic digest the birth authorization is crafted against — its
 * `r` commits to this digest. Argument layout ported from
 * `scripts/birth.py:build_init_digest`: EIP-191 v0x00 with the ROUTER (not the
 * born account) as validator, over
 * `keccak256(abi.encode(INIT_DOMAIN, implementation, expectedCodeHash, keccak256(initData)))`.
 * `initData` is the already-encoded `(FactorSlot[3], bytes[3])` blob — see
 * `encodeInitData` in `./encoding.ts`.
 */
export function initDigest(
  router: Address,
  implementation: Address,
  expectedCodeHash: Hex,
  initData: Hex,
): Hex {
  const structHash = keccak256(
    encodeAbiParameters(
      [{ type: "bytes32" }, { type: "address" }, { type: "bytes32" }, { type: "bytes32" }],
      [DOMAINS.INIT, implementation, expectedCodeHash, keccak256(initData)],
    ),
  );
  return eip191v0(router, structHash);
}

const CALL_TUPLE_ARRAY_ABI = [
  {
    type: "tuple[]",
    components: [
      { name: "to", type: "address" },
      { name: "value", type: "uint256" },
      { name: "data", type: "bytes" },
    ],
  },
] as const;

/** `keccak256(abi.encode(calls))`, matching `GlauxAccount.executeWithSigs`. */
function hashCalls(calls: readonly Call[]): Hex {
  return keccak256(encodeAbiParameters(CALL_TUPLE_ARRAY_ABI, [calls]));
}

/**
 * The digest the 2-of-3 quorum signs for a direct `executeWithSigs` batch.
 * Layout ported from `GlauxAccount.executeWithSigs`/`GlauxFixture._execDigestAtNonce`:
 * EIP-191 v0x00 with the account itself as validator, over
 * `keccak256(abi.encode(EXEC_DOMAIN, chainId, account, execNonce, keccak256(abi.encode(calls)), validUntil))`.
 * This binds the chain id, account, nonce, calls, and deadline.
 *
 * @throws {OperationExpiredError} if `validUntil === 0`.
 */
export function execDigest(
  account: Address,
  chainId: bigint,
  nonce: bigint,
  calls: readonly Call[],
  validUntil: number,
): Hex {
  if (validUntil === 0) {
    throw new OperationExpiredError();
  }
  const structHash = keccak256(
    encodeAbiParameters(
      [
        { type: "bytes32" },
        { type: "uint256" },
        { type: "address" },
        { type: "uint64" },
        { type: "bytes32" },
        { type: "uint48" },
      ],
      [DOMAINS.EXEC, chainId, account, nonce, hashCalls(calls), validUntil],
    ),
  );
  return eip191v0(account, structHash);
}

/**
 * The digest the 2-of-3 quorum signs for an ERC-4337 user operation. Layout
 * ported from `GlauxAccount.validateUserOp`/`GlauxFixture._userOpDigest`:
 * EIP-191 v0x00 with the account as validator, over
 * `keccak256(abi.encode(USEROP_DOMAIN, userOpHash, validUntil))`.
 *
 * @throws {OperationExpiredError} if `validUntil === 0` — see the error's
 * documentation for why this path rejects zero at build time.
 */
export function userOpDigest(account: Address, userOpHash: Hex, validUntil: number): Hex {
  if (validUntil === 0) {
    throw new OperationExpiredError();
  }
  const structHash = keccak256(
    encodeAbiParameters(
      [{ type: "bytes32" }, { type: "bytes32" }, { type: "uint48" }],
      [DOMAINS.USEROP, userOpHash, validUntil],
    ),
  );
  return eip191v0(account, structHash);
}

/**
 * The digest the 2-of-3 quorum signs for an ERC-1271 message. Layout ported
 * from `GlauxAccount.isValidSignature`/`GlauxFixture._msgDigest`: EIP-191
 * v0x00 with the account as validator, over
 * `keccak256(abi.encode(MSG_DOMAIN, chainId, account, hash, validUntil))`.
 * Like `execDigest`, this binds `chainId`; `userOpDigest` instead binds the
 * EntryPoint-provided `userOpHash`, whose own construction is chain-specific.
 * `initDigest` is deliberately chain-agnostic so it can be signed before the
 * account exists.
 *
 * @throws {OperationExpiredError} if `validUntil === 0`.
 */
export function msgDigest(account: Address, chainId: bigint, hash: Hex, validUntil: number): Hex {
  if (validUntil === 0) {
    throw new OperationExpiredError();
  }
  const structHash = keccak256(
    encodeAbiParameters(
      [
        { type: "bytes32" },
        { type: "uint256" },
        { type: "address" },
        { type: "bytes32" },
        { type: "uint48" },
      ],
      [DOMAINS.MSG, chainId, account, hash, validUntil],
    ),
  );
  return eip191v0(account, structHash);
}
