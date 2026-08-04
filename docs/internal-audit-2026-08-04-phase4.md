# Internal security audit — 2026-08-04 — Phase 4 client code

The second internal pass. Phase 3 audited the deployed contracts; this one audits
the client code written afterwards — the TypeScript SDK and the off-chain tooling
it claims parity with. Code that did not exist when the contracts were reviewed
does not inherit their review.

The distinction matters for a specific reason: **this code decides what the user
signs**. A contract defect is caught by the contract audit; a defect here makes a
correct contract authorise the wrong thing, or makes the client accept as valid
something the chain would reject.

## Method — blind parallel

The whole client surface (18 TypeScript files, ~3600 LOC across
`sdk/src/{core,signers,birth,execute,gas,eligibility,reconcile}`, plus
`scripts/reconcile.py` as the parity reference) was audited by two reviewers,
**blind to each other**, on the same adversarial mandate:

- **Reviewer A** — read the code in three separate passes, one per subsystem, at
  its highest reasoning tier.
- **Reviewer B** — a reviewer from a different vendor, read-only, taking the
  entire surface in a single pass.

The mandate named four adversaries rather than a list of bug classes: a hostile
or compromised RPC endpoint that answers every read; a hostile ERC-7677 paymaster
provider; a hostile prior delegate leaving pre-poisoned account state
(threat-model residual 17); and a counterparty supplying slot indices, key
material, call arrays, deadlines and birth blobs built elsewhere. Each finding
had to carry its precondition and a way to reproduce or falsify it, and each
reviewer had to state which areas it checked and found clean.

## Headline: both said BLOCK, and again the divergence was the finding

Both reviewers returned **BLOCK**, but not for the same reasons — and the most
serious defect was seen by only one of them.

Reviewer B found that `signExecution` asserts the chain id against a
caller-supplied value and then, one line later, reads the execution nonce from
the same RPC and places it in the signed digest. Reviewer A had that exact file
in its assigned scope and placed the vector among its clean areas, on the grounds
that "nonce lies can produce stale or invalid signatures, but cannot change
authorized calls". That is true and beside the point: the damage is not an
altered call, it is the **replay** of an authorised one.

This repeats the Phase 3 pattern, where the same reviewer returned MERGE on code
in which the other found a total seizure path. Two independent reviewers are
worth their cost precisely here.

Every finding below was reproduced or falsified against the real code before any
fix was written, and no finding was accepted on a reviewer's word.

## Findings, triaged one by one

### H-1 — HIGH — FIXED (2026-08-04) — The execution nonce was read from the RPC and signed

**File**: `sdk/src/execute/direct.ts` (`signExecution`), with the same defect on
the ERC-4337 path in `sdk/src/execute/userop.ts`.

`execNonce()` came from the endpoint and entered the signed digest, while
`SignExecutionParams` offered no way to assert it. On-chain, `executeWithSigs`
signs over the *current* nonce and increments after, and is permissionless.

An endpoint reporting `real + 1` therefore obtains a quorum signature that is
invalid now and becomes valid after exactly one legitimate execution. It already
holds the blob: `submitExecution` sends it there for simulation before
broadcasting. Once the user's next execution succeeds, anyone re-broadcasts the
harvested blob and the same batch executes a second time, at a moment of the
attacker's choosing anywhere inside `validUntil` — which nothing bounded.

**Fix.** Three layers, because no single one is sufficient. The nonce is now read
from two independent sources at the same pinned block — the getter and the raw
storage header — and a disagreement refuses to sign. An optional `expectedNonce`
lets a caller assert the value from an independently trusted source. And the
deadline is capped at one hour by default, with an explicit per-call override,
which bounds the window in which a harvested blob remains spendable.

**What this does not close**, recorded as threat-model residual 18: a fully
hostile endpoint lies consistently on both sources. Only an independently sourced
`expectedNonce` authenticates the nonce. The cross-check is a consistency
tripwire, not a proof of authenticity, and is described that way in the code, the
threat model and the client guidance.

### H-2 — HIGH — FIXED (2026-08-04) — Birth blobs were never bound to their authorization signer

**Files**: `sdk/src/birth/submit.ts` (`assertCanonicalBlob`), and identically
`scripts/submit_birth.py`.

The canonical check validated router, implementation, authorization target and
code hash, but never recovered the EIP-7702 authorization's signer to compare it
with `blob.account`. So `preflightFreshAccount` inspected one address while the
authorization in the same transaction delegated whichever address the tuple
recovered to. That preflight is the only client-side gate for residual 17, so the
gate was unsound as written. The code already performed this recovery when
*building* a blob; it simply never repeated it for blobs arriving from elsewhere
— and blobs are long-lived interchange artifacts, meant to be retained and
replayed on other chains.

The same area did not require the authorization's `chainId` to be zero. Zero is
what makes an authorization universal, which is the project's central promise; a
current-chain authorization silently yields a blob that works on one chain and
cannot install the router anywhere else.

**Fix.** Signer recovery and `chainId == 0` enforced in both languages, before
the freshness preflight.

### M-1 — MEDIUM — FIXED (2026-08-04) — An empty reconciliation reported success

**Files**: `sdk/src/reconcile/reconcile.ts`, `scripts/reconcile.py`.

`compareChainStates([])` entered no loop and returned its initial `consistent`,
while the Python CLI refuses the equivalent invocation. A reconciliation that
observed no chain must not be a positive verdict. Both implementations now refuse
an empty observation set.

### M-2 — MEDIUM — FIXED (2026-08-04, in two passes) — Parity break on non-canonical ABI returns

**File**: `sdk/src/reconcile/reconcile.ts`.

The TypeScript reconciler is a port of the Python tool and the two must return the
same verdict on the same state — that agreement is the whole reason the pair
exists. Return data with non-zero ABI padding is a hard decode failure in the
Python decoder and a silent mask-and-accept in the TypeScript one, so the same
state produced `consistent` on one side and `unreadable` (exit 2) on the other.

**This finding took two passes, and the first one is worth recording.** The
initial fix closed the hole only above the address returned by `implementation()`
— exactly where the audit had pointed — and left the identical defect three lines
below, in the `getSlot` decode, which concerns the factor slots: the set of
authorised signers. An independent review of the fix caught it.

**Fix.** The decoded pair is re-encoded canonically and compared byte-for-byte
against the raw return data, which closes the whole family rather than one case
at a time. The comparison is *stricter* than the Python decoder on two shapes it
tolerates (bytes appended past the tuple, a non-minimal payload offset); that
asymmetry is one-directional and therefore safe — the port may report `unreadable`
where the Python tool is milder, never the reverse — and it is documented in the
code. Differential testing over 4,548 adversarial vectors found no input the
TypeScript side accepts and the Python side rejects; 16,832 canonical vectors
decode under both.

## Open — reported by the reviewers, not fixed in this pass

These are real and were not addressed. They are recorded here rather than
silently carried forward.

- **Gas and fee values are taken from the RPC and signed with no ceiling**
  (converged on by three of the four reviewer passes). On the direct path the
  exposure is the relayer's hot key; on the ERC-4337 path the signed gas fields
  become prefund charged to the account, so there the exposure is the user's
  funds. No caller-authored maximum exists on any path.
- **Success can be fabricated by a hostile endpoint**: receipts, logs and the
  post-birth readback all come from the same source that broadcasts. There is no
  independent receipt, block proof or provider quorum anywhere in the client.
- **Presence probes validate existence, not identity**: the eligibility probes
  accept any non-empty bytecode at the canonical addresses instead of comparing
  pinned runtime code hashes — which the birth path already does, so the omission
  is inconsistent rather than principled.
- **Paymaster responses have no size bound** before parsing and concatenation
  (converged on by two passes). Client-side denial of service only; a paymaster
  cannot reach `sender` or `callData`.
- **`preVerificationGas` is a fixed constant** regardless of calldata size, so a
  relayer may be under-compensated for large operations.

The first four share one root: before this audit the threat model did not
contemplate the RPC endpoint as an adversary at all. Residual 18 is the first
entry that does.

## Verified and clean, so as not to re-litigate

Both reviewers, independently:

- Digests, domain separators and ABI layouts match the Solidity consumers
  field-for-field, including nonce and deadline widths, and are pinned by a
  contract-generated fixture asserted both positively and negatively.
- `computeUserOpHash` matches the vendored EntryPoint v0.7 byte-for-byte:
  dynamic fields hashed not embedded, signature excluded, correct high/low
  `uint128` packing, correct protocol ceiling.
- Paymaster decoration happens before the quorum signature and is enforced
  structurally, not by convention: the decorated data is inside the signed hash,
  so reversing the order fails closed. A paymaster cannot influence `sender`,
  `callData` or the account's own gas fields, and prefund drain is unreachable
  when a paymaster is set.
- The birth preflight reads the implementation slot plus all seven namespaced
  words, which is the coverage residual 17 demands, and fails closed on malformed
  or absent reads.
- The storage-layout derivation agrees across all four copies and with the
  compiler-generated parity fixture, including the short/long-form `bytes` bounds
  and the padding rejection.
- Signature handling is correct in both curves: low-s and `v ∈ {27,28}` enforced
  for secp256k1; P-256 deliberately not low-s-restricted on verification, since
  the precompile accepts either form, while the local signer still normalises on
  the way out with raw-digest signing.
- A zero deadline is refused at every entry point on both execution paths.

## Verdict

The four blocking findings are fixed, each with a test that was demonstrated to
fail without its fix — by removing the defended line and observing the suite go
red, not by assertion. Suites at the close of this pass: 142 SDK, 47 Python, 209
Solidity, all CI jobs green.

The items under *Open* remain. They do not block the current state of the
repository, but the gas/fee ceiling on the ERC-4337 path touches user funds and
should be closed before this client is used with real value.

Still out of scope, as in Phase 3: the external audit itself, and the public
testnet redeploy at the current implementation address.
