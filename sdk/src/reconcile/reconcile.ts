import {
  BaseError,
  ExecutionRevertedError,
  concat,
  decodeAbiParameters,
  encodeAbiParameters,
  getAddress,
  keccak256,
  slice,
  stringToBytes,
  toHex,
  type Address,
  type Hex,
  type PublicClient,
} from "viem";
import { ReconciliationReadError } from "../errors.js";

/**
 * TypeScript port of `scripts/reconcile.py`: raw-first reconciliation of a
 * Glaux account across chains. Verdict semantics are pinned to the Python
 * tool's exit codes (`docs/client-guidance.md`'s "Update-replay
 * reconciliation UX" section, normative):
 *
 * - `"consistent"`  <-> exit 0: every chain queried agrees.
 * - `"divergent"`   <-> exit 1: chains disagree (router, implementation
 *   pointer/codehash, `updateNonce`, or factor slots), but every chain's own
 *   getters agree with its own raw storage.
 * - `"unreadable"`  <-> exit 2: on at least one chain, the account's own
 *   getters (`updateNonce`, `execNonce`, `implementation()`, `getSlot`)
 *   disagree with -- or cannot even answer for -- the raw namespaced storage
 *   this module reads first. 2 outranks 1, exactly as in the Python tool:
 *   an implementation that misreports its own state invalidates every
 *   cross-chain comparison built on its answers, so it is reported ahead of
 *   a plain divergence.
 *
 * Order per chain, per `docs/client-guidance.md` (normative, "Read raw
 * storage first"): `eth_getCode(account)` for the EIP-7702 designator, the
 * raw `IMPL_SLOT` word, `eth_getCode` at that pointer for its live code
 * hash, the raw namespaced header + three factor slots, and ONLY THEN the
 * getters -- as a cross-check, never as the source.
 *
 * Slot arithmetic (`BASE_SLOT`/`IMPL_SLOT`/`headerSlot`/`typeSlot`/
 * `dataSlot`/`decodeHeader`/`decodeRawBytes`) is re-derived here from the
 * same literal seed strings `scripts/reconcile.py` uses, independently of
 * `../eligibility/probes.js`'s own independent derivation -- the same
 * defensive discipline `sdk/test/eligibility.test.ts` documents for itself:
 * a derivation bug in one module must not also hide in the other, and a
 * reconciliation tool that trusted the account's own eligibility module for
 * its slot math would no longer be an independent cross-check.
 *
 * DEVIATION from `scripts/reconcile.py`, required by this port's brief: the
 * Python tool's single `except Exception` around its getter reads
 * deliberately conflates a getter that reverts (a genuine reconciliation
 * finding -- the implementation cannot answer for its own state) with a
 * transport failure (the RPC call never completed at all). This port keeps
 * those two apart. A getter call whose failure is an EVM revert --
 * recognized here via `viem`'s `ExecutionRevertedError` walking the error's
 * cause chain, exactly as `../execute/direct.js` already does for its own
 * revert decoding -- or whose successful-but-empty/malformed return data
 * fails to ABI-decode, is folded into the `"unreadable"` verdict: the chain
 * answered, and the answer is that its own getters cannot describe its
 * state. Any OTHER failure reading raw storage, raw code, the implementation
 * pointer's code, or issuing a getter call at all (a dropped connection, a
 * timeout, a malformed JSON-RPC response) throws {@link ReconciliationReadError}
 * instead of silently reporting a verdict about state nothing was actually
 * read. Treating a transport failure as "the chain looks fine" or "the chain
 * looks unreadable" would both be wrong: the honest answer is "unknown, and
 * this must not be reported as reconciled."
 */

// Re-derived independently of `../core/constants.js` and
// `../eligibility/probes.js` -- see the module doc comment above.
const BASE_SLOT: bigint = BigInt(keccak256(stringToBytes("glaux.account.v1.storage")));
const IMPL_SLOT: bigint = BigInt(keccak256(stringToBytes("glaux.account.v1.implementation")));
const DESIGNATOR_PREFIX = "0xef0100";
const DESIGNATOR_HEX_LENGTH = 2 + 2 * 23; // "0x" + 23 designator bytes.
const UINT160_MAX = (1n << 160n) - 1n;
const UINT64_MAX = (1n << 64n) - 1n;

const UPDATE_NONCE_SELECTOR = keccak256(stringToBytes("updateNonce()")).slice(0, 10) as Hex;
const EXEC_NONCE_SELECTOR = keccak256(stringToBytes("execNonce()")).slice(0, 10) as Hex;
const IMPLEMENTATION_SELECTOR = keccak256(stringToBytes("implementation()")).slice(0, 10) as Hex;
const GET_SLOT_SELECTOR = keccak256(stringToBytes("getSlot(uint8)")).slice(0, 10) as Hex;

function headerSlot(): bigint {
  return BASE_SLOT;
}

function typeSlot(index: number): bigint {
  return BASE_SLOT + 1n + 2n * BigInt(index);
}

function dataSlot(index: number): bigint {
  return BASE_SLOT + 2n + 2n * BigInt(index);
}

function getSlotCalldata(index: number): Hex {
  return concat([GET_SLOT_SELECTOR, encodeAbiParameters([{ type: "uint8" }], [index])]);
}

interface DecodedHeader {
  readonly initialized: boolean;
  readonly updateNonce: bigint;
  readonly execNonce: bigint;
}

/**
 * Unpacks `(initialized, updateNonce, execNonce)` from the header word --
 * `initialized` at byte 0, `updateNonce` at bytes 1-8, `execNonce` at bytes
 * 9-16, proven against the real compiler by `test/StorageParity.t.sol`, not
 * derived here (same pinning `scripts/reconcile.py:decode_header` relies on).
 */
function decodeHeader(word: bigint): DecodedHeader {
  return {
    initialized: (word & 0xffn) !== 0n,
    updateNonce: (word >> 8n) & UINT64_MAX,
    execNonce: (word >> 72n) & UINT64_MAX,
  };
}

/** JSON-RPC `DATA` values are whole-byte hex strings.  Do not trust the
 * TypeScript declaration on a remote response: invalid wire data is a read
 * failure, not an observation about the account's state. */
function isHexBytes(value: unknown): value is Hex {
  return typeof value === "string" && /^0x(?:[0-9a-fA-F]{2})*$/u.test(value);
}

function isStorageWord(value: unknown): value is Hex {
  return isHexBytes(value) && value.length === 66;
}

async function readWord(client: PublicClient, chain: string, account: Address, slot: bigint): Promise<bigint> {
  try {
    const word: unknown = await client.getStorageAt({ address: account, slot: toHex(slot, { size: 32 }) });
    if (!isStorageWord(word)) throw new ReconciliationReadError(chain, "storage word");
    return BigInt(word);
  } catch {
    throw new ReconciliationReadError(chain, "storage word");
  }
}

async function readCode(
  client: PublicClient,
  chain: string,
  address: Address,
  target: "account code" | "implementation code",
): Promise<Hex | undefined> {
  try {
    const code: unknown = await client.getCode({ address });
    if (code !== undefined && !isHexBytes(code)) throw new ReconciliationReadError(chain, target);
    return code;
  } catch {
    throw new ReconciliationReadError(chain, target);
  }
}

/**
 * Decodes a Solidity `bytes` value at `slot`, reading whatever additional
 * words it needs one at a time. Short form: payload left-aligned in the
 * header word, `2 * len` in the low byte (even). Long form: `2 * len + 1` in
 * the header word (odd), payload words starting at `keccak256(slot)`. Mirrors
 * `scripts/reconcile.py:decode_bytes` exactly, adapted for async per-word RPC
 * reads instead of a synchronous local table lookup.
 */
async function decodeRawBytes(client: PublicClient, chain: string, account: Address, slot: bigint): Promise<Hex> {
  const header = await readWord(client, chain, account, slot);
  if ((header & 1n) === 0n) {
    const length = Number((header & 0xffn) / 2n);
    return slice(toHex(header, { size: 32 }), 0, length);
  }
  const length = Number((header - 1n) / 2n);
  const base = BigInt(keccak256(toHex(slot, { size: 32 })));
  const wordCount = Math.ceil(length / 32);
  const words: Hex[] = [];
  for (let j = 0; j < wordCount; j += 1) {
    words.push(toHex(await readWord(client, chain, account, base + BigInt(j)), { size: 32 }));
  }
  return slice(concat(words), 0, length);
}

/** One factor slot as read directly from storage -- deliberately untyped
 * beyond `bigint`/`Hex` (unlike `../core/types.js`'s `FactorSlot`, whose
 * `verifierType` is constrained to the two known verifier ids): reconciliation
 * must report a poisoned or out-of-range raw value exactly as read, not
 * coerce or reject it before the caller ever sees it. */
export interface FactorSlotRaw {
  readonly verifierType: bigint;
  readonly data: Hex;
}

export interface ActiveChainState {
  readonly name: string;
  readonly active: true;
  readonly router: Address;
  readonly implPointer: Address;
  readonly implCodehash: Hex | "no code at pointer";
  readonly initialized: boolean;
  readonly updateNonce: bigint;
  readonly execNonce: bigint;
  readonly slots: readonly [FactorSlotRaw, FactorSlotRaw, FactorSlotRaw];
  /**
   * Non-empty when the account's own getters disagree with -- or could not
   * answer for -- the raw state above. A non-empty array here, on ANY chain,
   * is what drives the overall verdict to `"unreadable"` (Python's exit 2).
   */
  readonly getterMismatches: readonly string[];
}

export interface InactiveChainState {
  readonly name: string;
  readonly active: false;
  /** Human-readable reason: "not yet active..." or "foreign code (N bytes)". */
  readonly note: string;
}

export type ChainState = ActiveChainState | InactiveChainState;

/** Thrown internally to short-circuit the getter-comparison sequence the
 * instant one getter call proves unreadable -- never escapes this module. */
class GetterUnreadable {
  constructor(readonly detail: string) {}
}

type RawCallOutcome = { readonly kind: "value"; readonly value: Hex } | { readonly kind: "unreadable"; readonly detail: string };

/**
 * Issues one raw `eth_call` against the account and classifies the result.
 * An EVM revert (recognized via `viem`'s `ExecutionRevertedError` in the
 * error's cause chain, the same walk `../execute/direct.js` uses to decode
 * its own reverts) is a reconciliation finding, not a transport failure --
 * see the module doc comment's DEVIATION note. Anything else viem could not
 * classify as an on-chain revert is a genuine transport failure and throws.
 */
async function callRaw(client: PublicClient, chain: string, account: Address, data: Hex): Promise<RawCallOutcome> {
  try {
    const result = await client.call({ to: account, data });
    const returnData: unknown = result.data;
    // viem's public `call` API deliberately normalises a successful RPC
    // response of `0x` to `data: undefined`. It exposes no provenance with
    // which to distinguish that empty EVM return from a hypothetical client
    // that omitted `data`, so treat undefined as valid empty bytes. This
    // matches scripts/reconcile.py, where bytes(w3.eth.call(...)) is b"" and
    // the subsequent ABI decode records an unreadable getter, rather than a
    // transport error. Present data remains strictly wire-validated below.
    if (returnData === undefined) return { kind: "value", value: "0x" };
    if (!isHexBytes(returnData)) throw new ReconciliationReadError(chain, "getter call");
    return { kind: "value", value: returnData };
  } catch (error) {
    const revertError =
      error instanceof BaseError ? error.walk((candidate) => candidate instanceof ExecutionRevertedError) : null;
    if (revertError !== null) {
      return { kind: "unreadable", detail: revertError.message };
    }
    throw new ReconciliationReadError(chain, "getter call");
  }
}

function wordToNonce(data: Hex): bigint {
  // Mirrors `scripts/reconcile.py`'s `int.from_bytes(..., "big")`: any
  // returned byte string, including empty, decodes to a value rather than
  // failing -- there is nothing here for a getter to malform.
  return data === "0x" ? 0n : BigInt(data);
}

interface RawState {
  readonly updateNonce: bigint;
  readonly execNonce: bigint;
  readonly implPointer: Address;
  readonly slots: readonly [FactorSlotRaw, FactorSlotRaw, FactorSlotRaw];
}

/**
 * Compares the account's getters against the raw state already read, in the
 * exact sequence and stop-on-first-unreadable-result semantics of
 * `scripts/reconcile.py:inspect_chain`'s getter section: `updateNonce`,
 * `execNonce`, `implementation()`, then `getSlot(0..2)`. A getter that
 * reverts, or whose return data fails to ABI-decode, ends the sequence with
 * one final `"getter call failed: ..."` entry appended to whatever mismatches
 * were already collected -- it does not discard them, matching the Python
 * `except` clause appending to the same list the `try` block already wrote.
 */
async function collectGetterMismatches(
  client: PublicClient,
  chain: string,
  account: Address,
  raw: RawState,
): Promise<readonly string[]> {
  const mismatches: string[] = [];
  try {
    const updateNonceOutcome = await callRaw(client, chain, account, UPDATE_NONCE_SELECTOR);
    if (updateNonceOutcome.kind === "unreadable") throw new GetterUnreadable(updateNonceOutcome.detail);
    const gotUpdateNonce = wordToNonce(updateNonceOutcome.value);
    if (gotUpdateNonce !== raw.updateNonce) {
      mismatches.push(`updateNonce: raw ${raw.updateNonce} vs getter ${gotUpdateNonce}`);
    }

    const execNonceOutcome = await callRaw(client, chain, account, EXEC_NONCE_SELECTOR);
    if (execNonceOutcome.kind === "unreadable") throw new GetterUnreadable(execNonceOutcome.detail);
    const gotExecNonce = wordToNonce(execNonceOutcome.value);
    if (gotExecNonce !== raw.execNonce) {
      mismatches.push(`execNonce: raw ${raw.execNonce} vs getter ${gotExecNonce}`);
    }

    const implementationOutcome = await callRaw(client, chain, account, IMPLEMENTATION_SELECTOR);
    if (implementationOutcome.kind === "unreadable") throw new GetterUnreadable(implementationOutcome.detail);
    let gotImplementation: Address;
    try {
      [gotImplementation] = decodeAbiParameters([{ type: "address" }], implementationOutcome.value);
    } catch (error) {
      throw new GetterUnreadable(
        `implementation(): ${error instanceof Error ? error.message : "malformed return data"}`,
      );
    }
    if (gotImplementation !== raw.implPointer) {
      mismatches.push(`implementation: raw ${raw.implPointer} vs getter ${gotImplementation}`);
    }

    for (let index = 0; index < 3; index += 1) {
      const outcome = await callRaw(client, chain, account, getSlotCalldata(index));
      if (outcome.kind === "unreadable") throw new GetterUnreadable(outcome.detail);
      let verifierType: number;
      let data: Hex;
      try {
        [verifierType, data] = decodeAbiParameters([{ type: "uint8" }, { type: "bytes" }], outcome.value);
      } catch (error) {
        throw new GetterUnreadable(
          `getSlot(${index}): ${error instanceof Error ? error.message : "malformed return data"}`,
        );
      }
      const expected = raw.slots[index]!;
      if (BigInt(verifierType) !== expected.verifierType || data.toLowerCase() !== expected.data.toLowerCase()) {
        mismatches.push(
          `slot ${index}: raw (${expected.verifierType}, ${expected.data}) vs getter (${verifierType}, ${data})`,
        );
      }
    }
  } catch (error) {
    if (error instanceof GetterUnreadable) {
      mismatches.push(`getter call failed: ${error.detail}`);
      return mismatches;
    }
    throw error;
  }
  return mismatches;
}

/**
 * Steps 1-5 for one chain, raw reads first, getters as cross-check only --
 * the TypeScript counterpart of `scripts/reconcile.py:inspect_chain`.
 *
 * @throws {ReconciliationReadError} if any raw code/storage read, or issuing
 * a getter call at all, fails for a reason that is not itself an EVM revert
 * (see the module doc comment's DEVIATION note) -- chain state is unknown,
 * never reported as a verdict.
 */
export async function inspectChain(client: PublicClient, name: string, account: Address): Promise<ChainState> {
  const code = await readCode(client, name, account, "account code");
  if (code === undefined || code === "0x") {
    return { name, active: false, note: "not yet active (no code at the account)" };
  }
  if (code.length !== DESIGNATOR_HEX_LENGTH || !code.toLowerCase().startsWith(DESIGNATOR_PREFIX)) {
    const byteLength = (code.length - 2) / 2;
    return { name, active: false, note: `foreign code (${byteLength} bytes)` };
  }
  const router = getAddress(`0x${code.slice(DESIGNATOR_PREFIX.length)}` as Hex);

  const implWord = await readWord(client, name, account, IMPL_SLOT);
  const implPointer = getAddress(toHex(implWord & UINT160_MAX, { size: 20 }));
  const implCode = await readCode(client, name, implPointer, "implementation code");
  const implCodehash: Hex | "no code at pointer" =
    implCode === undefined || implCode === "0x" ? "no code at pointer" : keccak256(implCode);

  const headerWord = await readWord(client, name, account, headerSlot());
  const { initialized, updateNonce, execNonce } = decodeHeader(headerWord);

  const rawSlots: FactorSlotRaw[] = [];
  for (let index = 0; index < 3; index += 1) {
    const verifierType = await readWord(client, name, account, typeSlot(index));
    const data = await decodeRawBytes(client, name, account, dataSlot(index));
    rawSlots.push({ verifierType, data });
  }
  const slots = rawSlots as [FactorSlotRaw, FactorSlotRaw, FactorSlotRaw];

  const getterMismatches = await collectGetterMismatches(client, name, account, {
    updateNonce,
    execNonce,
    implPointer,
    slots,
  });

  return {
    name,
    active: true,
    router,
    implPointer,
    implCodehash,
    initialized,
    updateNonce,
    execNonce,
    slots,
    getterMismatches,
  };
}

function slotsEqual(a: readonly FactorSlotRaw[], b: readonly FactorSlotRaw[]): boolean {
  if (a.length !== b.length) return false;
  return a.every((slot, index) => {
    const other = b[index];
    return other !== undefined && slot.verifierType === other.verifierType && slot.data.toLowerCase() === other.data.toLowerCase();
  });
}

export type ReconcileVerdict = "consistent" | "divergent" | "unreadable";

/**
 * Verdict across the chains already inspected, matching
 * `scripts/reconcile.py:compare` field for field: `execNonce` is
 * deliberately NOT compared cross-chain (executions are per-chain by
 * design); what must agree is `updateNonce`, the three factor slots, the
 * implementation pointer and its live code hash, and the router. `2`
 * (`"unreadable"`) outranks `1` (`"divergent"`) exactly as in the Python
 * tool's `exit_code < 2` guards.
 */
export function compareChainStates(states: readonly ChainState[], expectedRouter?: Address): ReconcileVerdict {
  let verdict: ReconcileVerdict = "consistent";
  const active = states.filter((state): state is ActiveChainState => state.active);

  for (const state of active) {
    if (state.getterMismatches.length > 0) verdict = "unreadable";
  }

  if (expectedRouter !== undefined) {
    const want = getAddress(expectedRouter);
    if (verdict !== "unreadable" && active.some((state) => state.router !== want)) {
      verdict = "divergent";
    }
  }

  if (active.length >= 2) {
    const first = active[0]!;
    for (const state of active.slice(1)) {
      const diverges =
        state.updateNonce !== first.updateNonce ||
        !slotsEqual(state.slots, first.slots) ||
        state.implPointer !== first.implPointer ||
        state.implCodehash !== first.implCodehash ||
        state.router !== first.router;
      if (verdict !== "unreadable" && diverges) verdict = "divergent";
    }
  }

  return verdict;
}

/** One chain to reconcile against -- named, like `scripts/reconcile.py`'s
 * `--rpc NAME=URL`, so `perChain` in the result can be attributed back to a
 * chain rather than only an array index. */
export interface ReconcileClient {
  readonly name: string;
  readonly client: PublicClient;
}

export interface ReconcileOptions {
  /** Expected router address, compared against every active chain -- mirrors `--router`. */
  readonly router?: Address;
}

export interface ReconcileResult {
  readonly verdict: ReconcileVerdict;
  readonly perChain: readonly ChainState[];
}

/**
 * Reconciles a Glaux account across every chain in `clients`: raw storage
 * first, the account's own getters only as a cross-check -- the TypeScript
 * port of `scripts/reconcile.py`. See the module doc comment for the exact
 * verdict-to-exit-code mapping and the one deliberate behavioral deviation
 * (transport failures throw rather than folding into a verdict).
 *
 * @throws {ReconciliationReadError} if any chain's raw state, or a getter
 * call itself, cannot be read for a reason other than an EVM revert.
 */
export async function reconcile(
  clients: readonly ReconcileClient[],
  account: Address,
  options: ReconcileOptions = {},
): Promise<ReconcileResult> {
  const perChain = await Promise.all(clients.map((entry) => inspectChain(entry.client, entry.name, account)));
  const verdict = compareChainStates(perChain, options.router);
  return { verdict, perChain };
}
