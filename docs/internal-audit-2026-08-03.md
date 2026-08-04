# Internal security audit — 2026-08-03

Phase 3 of the roadmap: the contract is audited *by us* before it is audited by
anyone else. This is the record of that pass. It does not replace an external
audit; it precedes it, so that whoever funds the external one starts from code
already put through the sieve.

## Method — blind parallel

The four deployed sources (`src/GlauxDelegate.sol`, `src/GlauxAccount.sol`,
`src/GlauxStorage.sol`, `src/lib/SignatureVerify.sol`,
`src/lib/ImplementationCheck.sol`, ~960 LOC) were audited by two reviewers at
maximum tier, **blind to each other**, on the same adversarial mandate:

- **Reviewer A** — an independent code-review agent at its highest reasoning tier.
- **Reviewer B** — a second agent, from a different vendor, read-only, also at
  maximum tier.

The mandate covered: 2-of-3 threshold bypass, signature malleability/reuse,
cross-chain replay via nonce, storage/transient slot collisions,
delegatecall/upgrade to a hostile target, reentrancy on shared paths, the
ERC-4337 path (prefund, validationData packing, missing execNonce), birth-blob
splicing, and DoS/gas.

## Headline: the two reviewers diverged, and the divergence was the finding

- **Reviewer A**: 0 findings, verdict **MERGE**. It verified the router-mediated
  paths thoroughly (including a 256×128 invariant campaign) and explicitly
  concluded that birth "closes double-init and reentrant splice" and that "all
  external-execution paths converge on the same transient guard".
- **Reviewer B**: one **HIGH** and one **MEDIUM**, both with passing PoC
  tests, plus two LOW and several Info items.

The roadmap treats a divergence between the two as itself a risk to report.
Here the higher-capability adversarial reviewer found a total, irreversible
seizure path that the other declared clean — because Reviewer A modelled the system
as *router + implementation reached through the router*, and never modelled the
adversarial EIP-7702 configuration where an EOA delegates **directly to the
implementation**, bypassing the router. That is exactly H-1.

The orchestrating reviewer then reproduced H-1 and H-2 independently by running the
PoC tests against the real code in an isolated copy: **5 passed, 0 failed**,
including `test_poc_directDelegationToImplementationIsSeizableByAnyone`, which
drains the victim's full balance to the attacker. The repository was not
modified during the audit.

## Findings, triaged one by one

### H-1 — HIGH — FIXED (2026-08-03) — An EOA delegated directly to `GlauxAccount` is seizable by anyone

**Fix**: `initializeAccount` now reads the router's transient
`DELEGATE_BIRTH_GUARD_SLOT` as its first statement and reverts `NotDuringBirth()`
when it is zero, so it can run only inside a router-mediated birth. Three files:
`src/GlauxStorage.sol` (new error), `src/GlauxAccount.sol` (guard), `test/Birth.t.sol`
(new negative test `test_initializeAccountRevertsWhenNotDuringBirth` + four
pre-existing `expectRevert` selectors updated from `AlreadyInitialized` to
`NotDuringBirth`, since the guard is strictly stronger and fires first on those
paths). Baseline: `forge test` 203 passed / 0 failed / 2 skipped; `forge fmt`
green. Two-chain proof re-run: router unchanged (`0x6f90a8ec…`), impl moved to
`0x3d5ACEfE…` / codehash `0x7a799e77…`, replay still consistent — see
`docs/deployments.md` banner.


**File**: `src/GlauxAccount.sol:58-82` (guards at `:60`, `:66`).

`initializeAccount` defends only with `l.initialized == false` and
`IMPL_SLOT == 0`, both read from the current context's storage. On the
implementation contract those are false (constructor, `:55`); through the router
they are unreachable (`fallback` reverts `NotInitialized` while `IMPL_SLOT` is
zero). **But on an EOA whose EIP-7702 authorization tuple names the
implementation instead of the router, both are true**, and `initializeAccount`
is `external` with no caller constraint. Anyone installs their own three keys
(possession proofs are trivial — the keys are theirs), then calls
`executeWithSigs` and drains the account. No birth signature is involved.

Not theoretical: `birth.py` takes adjacent `--router`/`--impl` flags,
`docs/deployments.md` lists the two addresses side by side with the
implementation first, and `docs/client-guidance.md` says only "sign the single
EIP-7702 authorization tuple with `chainId = 0`" without ever naming *which*
address goes in it. `submit_birth.py` sends the authorization and `initialize`
in one transaction; the `initialize` reverts but, per EIP-7702, the
authorization is applied before the top-level frame and is **not** undone by the
revert — the wrong delegation lands permanently and the race to
`initializeAccount` starts from there.

**Irreversible**: the birth key is destroyed by design, so no second
authorization can fix the target; and in the delegated-to-implementation
configuration `SetImplementation` writes `IMPL_SLOT`, which is never read there.

**Fix (on-chain, one line)**: the router sets `DELEGATE_BIRTH_GUARD_SLOT`
(transient) to 1 for the whole birth delegatecall (`GlauxDelegate.sol:60`, `:101`)
and `GlauxStorage.sol:44-45` already declares it visible to every
implementation. `initializeAccount` must `tload` it and revert when it is 0 —
i.e. refuse to run outside a router-mediated birth. Verified observable from the
implementation (`test_poc_birthGuardIsObservableFromTheImplementation`). This is
the second half of the standard rule for upgradeable systems: protect
init/upgrade with state **and** with a check on the logic contract itself, so the
logic cannot be initialized outside the proxy — currently only half-satisfied.

Changing `src/` moves the implementation code hash and CREATE2 address and
invalidates every unspent birth/update blob → the two-chain proof and the
testnet deployment tables must be redone (roadmap Phase 3 discipline). No real
funds are at stake (testnet only), so fixing now is the correct trade.

### H-2 — MEDIUM — ADDRESSED (2026-08-03, documental + tooling) — Storage pre-poisoned by a prior hostile delegate (undeclared residual)

**Remedy shipped**: declared as threat-model residual 17; client-guidance gains a
pre-birth rule (account must have no code and zero Glaux namespaced slots, and
"never migrate an already-delegated EOA") and now names the ROUTER in the
signing step; `scripts/submit_birth.py` enforces it with `preflight_fresh_account`
(reads code + `IMPL_SLOT` + header word, aborts before broadcasting), covered by
`scripts/test_submit_birth_preflight.py` (8 cases, network-free). No on-chain fix
is possible by design.


**Files**: `src/GlauxStorage.sol:29-35`, `src/GlauxDelegate.sol:106-115`,
`src/GlauxAccount.sol:59-66`.

The threat model reasons only about *accidental* occupation of the shared
ERC-1967 slot by a previous wallet. But an EIP-7702 re-delegation does not clear
storage and Glaux's slot constants are public, so a hostile prior delegate can
deliberately write `glaux.account.v1.implementation` and
`glaux.account.v1.storage`. Two outcomes, both reproduced by permanent
regression tests in `test/Birth.t.sol`
(`test_residual17_plantedImplPointerBricksBirthAndIsExecuted`,
`test_residual17_plantedFullStateMakesAccountAttackerOwned`):

- **Brick + hostile execution**: plant only `IMPL_SLOT` → birth reverts
  `AlreadyInitialized` forever, and the router's `fallback` delegatecalls the
  planted address on every call.
- **Full takeover**: plant `IMPL_SLOT = <real GlauxAccount>`, the header word with
  `initialized = true`, and three attacker `FactorSlot`s → the instant the user
  delegates to the correct router, the account is a fully working Glaux account
  owned by the attacker.

Precondition: the EOA was previously delegated to hostile code on that chain —
unreachable in the canonical ephemeral-birth-key flow, but squarely on the
planned migration path where "the birth key IS a long-lived user key", i.e. the
population the threat model itself describes as drained by CrimeEnjoyor.

**No honest on-chain fix** (whoever can write one slot can write them all). The
H-1 birth-guard fix does *not* cover it (H-2 never goes through
`initializeAccount`). Remedy is documental + client-side: declare it as a
residual in the threat model, add a normative rule ("before submitting a birth
blob on a chain, verify the account never carried a delegation designator and
that `IMPL_SLOT` and the namespaced header word are zero"), and discourage
migrating an already-delegated EOA. The reconciliation step catches it only
*after* the fact.

### L-1 — LOW — FIXED (2026-08-03) — `applyUpdate` does not converge on the `executing` guard

**Fix**: `applyUpdate` now reverts `ReentrantCall()` if `executing` is set, so a
callee reached mid-batch can no longer land a quorum-signed update inside a
running `_execute`. Changes bytecode (impl moved to `0x21b5D576…`). The existing
`test_executeCannotRouteApplyUpdateWithoutUpdateSigs` now asserts `ReentrantCall`
(signature-validation coverage for `applyUpdate` is retained by five direct
`UpdateChannel.t.sol` tests and the `tryForgeUpdate` invariant).


**File**: `src/GlauxAccount.sol:179` vs `:339-347`. `_execute` takes the transient
guard; `applyUpdate` does not, so a callee reached by a signed batch can land a
quorum-signed update (including `SetImplementation`) *in the middle* of the
batch, the remaining calls running on the old code with the new configuration.
Not an authorization bypass (both need signatures) and no exploit found, but
residual 10 grants the relayer only "whether and when", not "interleaved within
one transaction". Close by extending the guard to `applyUpdate` (which makes no
external call, so the cost is only semantics) or declare it.

### L-2 — LOW — FIXED (2026-08-03) — Invariant coverage is single-channel, with `fail_on_revert = false`

**Fix**: the invariant handler gains stateful coverage of `executeWithSigs` (a
valid `execute()` action against a benign sink + a `tryExecuteForge` attack, an
`execNonce` ghost, and `invariant_execNonceMatchesGhost`), and `foundry.toml`
sets `fail_on_revert = true`. `validateUserOp`/`executeFromEntryPoint` and
`isValidSignature` are not driven statefully because all three channels funnel
through the single `_checkTwoSigs` → live `l.slots[]` read
(`GlauxAccount.sol:409-414`): with one shared choke point a per-channel
divergence after a rotation is implausible, so the stateful campaign on the
update/exec channels already exercises the authorization logic they share. The
narrower gap — no test today rotates a factor and then re-checks the 4337 or
1271 path with the old/new key — is tracked as a follow-up. Reinforced campaign
512×128 (65536 calls/invariant) green.


**Files**: `test/invariant/Handler.sol`, `foundry.toml`. The handler drives only
`applyUpdate`. `executeWithSigs`, `validateUserOp`/`executeFromEntryPoint` and
`isValidSignature` — the fund-moving channels — have no stateful coverage.
Reviewer A's 256×128 campaign passing says nothing about those channels because the
handler never drives them. This is precisely the "single-channel handler gives
false confidence" case. Extend the handler and
set `fail_on_revert = true`. Test-only, no bytecode impact.

### Info (no fix required, worth recording)

- `SignatureVerify._p256Verify` (`:161-162`) forwards all gas to `0x100`; on a
  chain where that address is a gas-burning contract, the probe and every P-256
  verify lose 63/64 of the submitter's gas. Same class as residual 15, undeclared
  for `0x100`.
- `_tryDecodeSigs` (`:312`) makes an external self-call during ERC-4337
  validation — ERC-7562 compliant, but adds two frames and a bundler-policy
  dependency an in-memory bounds-checked decoder would avoid.
- `MAX_SIGNATURE_BLOB_LENGTH = 576` (`:44`) fits secp256k1/P-256 but is
  incompatible with the PQ ambition stated in the design spec; lives in the
  upgradeable half, so not permanent — worth writing down.
- The `_validateSlot` → `_requirePossession` order (`:70-71`, `:203-204`) is
  load-bearing (the raw-hash proof is safe only because the digest has no
  attacker-controllable entropy, which `isValidKey` guarantees by enforcing
  canonical `data` first) and undocumented as such.
- No `validAfter` on either execution path.

## Verified and clean (both reviewers, so as not to re-litigate)

2-of-3 threshold (no path accepts fewer than two distinct verified indices;
`_requirePossession` holds; `_isDuplicateSlot` complete because `data` is
canonical); secp256k1 low-s / `v` / zero-address / dirty-padding all rejected;
P-256 field range, point-at-infinity, on-curve; separate non-confusable domains;
`eip191` v0x00 collides with neither 7702 MAGIC nor transaction RLP; 4337
`validationData` packing, `validUntil == 0` refused on both paths, prefund
bounded and unwound by the EntryPoint, replay nonce owned by the EntryPoint;
`isInstallable` code hash / `0xEF` rejection / 32-byte returndata window; no
selector collisions; no write to the ERC-1967 slot; birth splice closed by the
namespaced transient guard.

## Verdict

**All internal findings closed (2026-08-03).** H-1 (HIGH) fixed on-chain
(birth-guard); L-1 (LOW) fixed on-chain (applyUpdate reentrancy guard); L-2 (LOW)
fixed (invariant coverage + `fail_on_revert = true`); H-2 (MEDIUM) addressed by
threat-model residual 17 + client-guidance + a `submit_birth.py` pre-birth check
(no on-chain fix possible). Remaining before real funds is out of scope for the
internal audit: the external audit itself, and the public testnet redeploy at the
new impl address (`0x21b5D576…`), pending a funded key. `forge test`: 202 at
audit time → **207 passed, 0 failed, 2 skipped** post-batch.
