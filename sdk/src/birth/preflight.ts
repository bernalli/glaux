import { concat, keccak256, stringToBytes, toHex, type Address, type Hex, type PublicClient } from "viem";
import { ROUTER } from "../core/constants.js";
import { BirthPreflightError, BirthPreflightReadError } from "../errors.js";

// Mirrors `GlauxStorage.SLOT`/`IMPL_SLOT` and `scripts/submit_birth.py`'s
// `STORAGE_SLOT`/`IMPL_SLOT`: a header word followed by three `FactorSlot`
// entries (verifierType, then the `bytes data` head) at STORAGE_SLOT+1..+6.
// Computed independently here (not imported from `../eligibility/probes.js`)
// so a derivation bug in that module cannot also hide in this preflight —
// the same isolation `sdk/test/eligibility.test.ts` already applies.
const STORAGE_SLOT = BigInt(keccak256(stringToBytes("glaux.account.v1.storage")));
const IMPL_SLOT: Hex = keccak256(stringToBytes("glaux.account.v1.implementation"));

function isHexBytes(value: unknown): value is Hex {
  return typeof value === "string" && /^0x(?:[0-9a-fA-F]{2})*$/u.test(value);
}

function isStorageWord(value: unknown): value is Hex {
  return isHexBytes(value) && value.length === 66;
}

async function readCode(client: PublicClient, account: Address): Promise<Hex> {
  try {
    // viem's `getCode` intentionally maps a real JSON-RPC `"0x"` response
    // to `undefined`. Birth needs to distinguish that known-empty response
    // from a missing response, so read the wire value directly.
    const code: unknown = await client.request({
      method: "eth_getCode",
      params: [account, "latest"],
    });
    if (!isHexBytes(code)) throw new BirthPreflightReadError(account, "code");
    return code;
  } catch (error) {
    if (error instanceof BirthPreflightReadError) throw error;
    throw new BirthPreflightReadError(account, "code");
  }
}

async function readStorageWord(client: PublicClient, account: Address, slot: Hex): Promise<Hex> {
  try {
    const word: unknown = await client.request({
      method: "eth_getStorageAt",
      params: [account, slot, "latest"],
    });
    if (!isStorageWord(word)) throw new BirthPreflightReadError(account, "storage", slot);
    return word;
  } catch (error) {
    if (error instanceof BirthPreflightReadError) throw error;
    throw new BirthPreflightReadError(account, "storage", slot);
  }
}

/**
 * Aborts before broadcasting if `account` is not a pristine EOA — port of
 * `scripts/submit_birth.py:preflight_fresh_account`, hardened per audit
 * finding H-2 (threat-model residual 17). See `BirthPreflightError`'s
 * documentation for the full rationale.
 *
 * Two halves, both required, mirroring the Python function exactly:
 * 1. Code must be empty OR exactly the EIP-7702 designator this account
 *    would carry once delegated to the canonical `ROUTER`
 *    (`0xef0100 ‖ ROUTER`) — the retry case for a birth whose `initialize()`
 *    call reverted, which EIP-7702 still applies the authorization for.
 *    Any other non-empty code refuses.
 * 2. `IMPL_SLOT` AND all seven namespaced words at `STORAGE_SLOT..+6` (the
 *    header plus the `verifierType`/`data`-head pair of each of the three
 *    `FactorSlot` entries) must be zero. Checking fewer than all eight lets a
 *    hostile prior delegate plant a forged `bytes data` length in an
 *    unchecked word and pass undetected.
 *
 * Always checks against the canonical `ROUTER`, not a caller-supplied one:
 * this SDK only ever builds and submits blobs for the one canonical
 * deployment (see `buildBirthBlob`), so there is no other router a genuine
 * blob from this SDK could name.
 *
 * Read-only: one `eth_getCode`, then up to eight `eth_getStorageAt` calls.
 * Every response must be well-formed (`0x`/whole-byte code, or a 32-byte
 * storage word); an unavailable or malformed read raises
 * `BirthPreflightReadError`, never a clean result. Resolves only if `account`
 * passes both checks.
 *
 * @throws {BirthPreflightError}
 * @throws {BirthPreflightReadError}
 */
export async function preflightFreshAccount(client: PublicClient, account: Address): Promise<void> {
  const expectedDesignator = concat(["0xef0100", ROUTER]).toLowerCase() as Hex;
  const code = await readCode(client, account);
  const normalizedCode = code.toLowerCase();
  if (normalizedCode !== "0x" && normalizedCode !== expectedDesignator) {
    throw new BirthPreflightError(
      `${account} already has code that is not the EIP-7702 designator for the canonical router (${ROUTER}) ` +
        "— it must be a fresh EOA that was never an EIP-7702 delegate, or the retry of a birth that reverted " +
        "while already delegated to this router (threat-model residual 17). Never migrate an EOA delegated to " +
        "a different target.",
    );
  }

  const implWord = await readStorageWord(client, account, IMPL_SLOT);
  if (BigInt(implWord) !== 0n) {
    throw new BirthPreflightError(
      `${account} has a non-zero Glaux implementation slot — its storage was pre-planted (threat-model residual 17).`,
    );
  }

  for (let offset = 0; offset < 7; offset += 1) {
    const slot = toHex(STORAGE_SLOT + BigInt(offset), { size: 32 });
    const word = await readStorageWord(client, account, slot);
    if (BigInt(word) !== 0n) {
      const kind = offset === 0 ? "storage header word" : `FactorSlot word (STORAGE_SLOT+${offset})`;
      throw new BirthPreflightError(
        `${account} has a non-zero Glaux ${kind} at slot ${slot} — its storage was pre-planted ` +
          "(threat-model residual 17).",
      );
    }
  }
}
