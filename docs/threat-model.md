# Glaux — Threat Model

This document analyzes the security properties of the Glaux account as
implemented in `src/GlauxDelegate.sol`, `src/GlauxAccount.sol`,
`src/GlauxStorage.sol`, `src/lib/SignatureVerify.sol` and
`src/lib/ImplementationCheck.sol`. It is written for an auditor or an
integrator who needs to know exactly what the contract protects, against whom,
and where that protection deliberately ends. Every claim below is checkable
against the cited function.

The corresponding signer-side rules live in `docs/client-guidance.md`. Several
residuals here have **no on-chain mitigation at all** and are closed only by a
rule in that document; those are marked.

## Assets

**Funds.** Held by one address that exists on every EVM chain. Note precisely
what is replicated and what is not: the *address* and the *EIP-7702 delegation*
are the same everywhere, but balances, tokens and positions are strictly
chain-local. An account "on ten chains" holds ten independent balances.
Reachable through `executeWithSigs` or, via an ERC-4337 bundler, through
`executeFromEntryPoint`.

**The three factor keys.** F2 the paper key at slot 0, F1 the device key at slot
1, F3 the cloud co-signer at slot 2. Their compromise, singly or in
combination, determines what an adversary can do.

**The birth key.** The ephemeral EOA private key that signs the one EIP-7702
authorization tuple and the initialization blob. It is meant to exist only
until the account is born. If it survives, it is a permanent master key — see
the first residual, which is the most serious property in this document.

**The update nonce and the configuration it gates.** `updateNonce` in
`GlauxStorage.Layout` and the three `FactorSlot` entries: whoever can produce
two valid signatures over the next nonce controls the account's future signers,
verifier types, and implementation.

**The implementation pointer.** Held in a Glaux-owned namespaced slot,
`keccak256("glaux.account.v1.implementation")` — deliberately *not* the shared
ERC-1967 slot, which Glaux never reads and never writes. Written once by
`GlauxDelegate.initialize` and thereafter only by `applyUpdate` under
`ACTION_SET_IMPLEMENTATION`. It decides which logic every delegatecall from the
immutable router executes.

## Adversaries

**A remote attacker with no factors.** Can read all on-chain state and submit
any calldata, but cannot produce a valid signature from any slot.
`_checkTwoSigs` requires two signatures from two distinct slot indices, each
verified against stored key material through `SignatureVerify.verify`; no path
accepts fewer than two independently verified signatures. *Guarantee:* total
denial of state-changing operations. *Non-guarantee:* none — this is the
baseline the whole design exists to hold.

**A compromised cloud provider, holding F3.** Gains one of three signatures,
which is worth nothing alone. *Non-guarantee:* if the same breach also yields
F1 or F2 — because a client stored two factors on one backend — the threshold
is met. The contract cannot know whether two slots are genuinely independent;
independence is a client-integration property.

**A device thief, device locked.** *Guarantee, conditional:* possession without
unlock yields nothing — but only if the client created F1 with an access policy
that requires user verification for every signature. Hardware backing alone
does not provide this: a hardware-backed key can be configured to sign without
prompting, and then a locked device is no obstacle. This guarantee is entirely
a client/platform property; the contract has no visibility into device state.

**A device thief, device unlocked.** Can produce F1 signatures on demand.
Combined with F3 — which routinely co-signs on the same device for daily UX —
this reaches 2-of-3 and grants full control, including `applyUpdate` calls that
rotate F1 and F3 themselves and lock the legitimate owner out unless they hold
F2 and act first. Glaux does not defend against this; it is a declared
residual.

**Runtime malware on an unlocked device.** Equivalent to the unlocked-device
thief for anything the malware can get the device to sign. No on-chain check
distinguishes a user-initiated signature from a malware-triggered one; this is
inherent to any signature-based scheme.

**A malicious or censoring relayer or bundler.** Cannot forge a signature,
cannot alter `u.payload` or `calls` without invalidating the digest the
signatures cover, and cannot replay an applied operation past its nonce check.
*Guarantee:* integrity and ordering are enforced regardless of relayer
behaviour. *Non-guarantee:* liveness — see the permissionless-relay residual.

**A paymaster.** `validateUserOp` decides validity independently of the
paymaster: the `msg.sender != ENTRYPOINT` gate plus the two-signature check
over `userOpHash`. *Guarantee:* paymaster misbehaviour can at worst deny
sponsorship, never authorize an unsigned operation.

**A compromised birth environment.** Holds the key that authorizes
initialization — and, as the first residual explains, far more than that.

**An attacker who already holds two factors.** Meets the threshold for every
operation the contract exposes. This is not a partial compromise; it is the
definition of control under a 2-of-3 threshold, and every "guard" described
below stops accidents rather than this adversary.

## Guarantees, summarized

Two independent signatures from two of the three factor slots are necessary and
sufficient to change configuration or move funds; no single factor and no
non-factor actor can do either alone.

Execution digests bind `block.chainid`, so a signed execution authorized for
one chain cannot be replayed on another. Update digests deliberately carry no
chain-id, so one signed configuration change reaches every chain without
re-signing — a feature whose consequence is declared below.

The three factor slots must be **pairwise distinct as `(verifierType, data)`
pairs** — `_isDuplicateSlot` is checked pairwise in `initializeAccount` and
against the other two slots on any single-slot update, reverting
`DuplicateSlot()`. Without it, the same key in two slots would let one
signature be submitted under two indices, collapsing 2-of-3 to 1-of-1.

**Birth and upgrade install code under identical rules**, both through
`ImplementationCheck.isInstallable`: the implementation must have deployed
code, its runtime code hash must equal the hash the signers bound into the
digest, it must not be an EIP-7702 delegation designator, and it must answer
`glauxCompatibilityId()` with `GlauxStorage.COMPAT_ID` through a bounded
32-byte output window. Birth additionally requires the implementation's own
initializer to leave `initialized == true` before the pointer is written, so a
delegatecall into an implementation that silently no-ops cannot produce a
live-looking but unconfigured account.

**Glaux touches no storage slot it does not own.** The implementation pointer
lives in a Glaux namespace, and the router's birth guard lives in a namespaced
*transient* slot rather than the transient slot 0 that Solidity would assign it
— which the implementation's own first transient variable also occupies, since
both execute with `address(this)` set to the account. The shared ERC-1967 slot
is neither read nor written: an EIP-7702 account can be re-delegated at any
time, so a value left there would be adopted as its own by whatever wallet the
account moves to next. Tooling should read `GlauxAccount.implementation()`.

> **Why designators are rejected.** For an EIP-7702 delegated EOA,
> `EXTCODEHASH` hashes the 23-byte delegation designator while `DELEGATECALL`
> executes the delegation *target's* code. Binding the hash would therefore
> bind nothing: the identical designator can point at an address holding
> different code on another chain — exactly the substitution the binding
> exists to prevent. EIP-3541 forbids deploying code beginning with `0xEF`,
> so a leading `0xEF` byte identifies a designator exactly. This hole was
> found by review after the code-hash binding had already landed, and closing
> it is the reason both paths now share one implementation of the check.

## Declared residuals

These are not omissions found during review; they are properties of the design
that the project states openly rather than implies away. They are ordered by
how much damage they do.

### 1. A surviving birth key is a permanent master key

**No on-chain mitigation. Closed only by process.**

The birth key *is* the account's EOA key. EIP-7702 delegation does not strip
the EOA of its own authority: a delegated EOA can still originate ordinary
transactions, and can still sign further authorization tuples. A surviving copy
of the birth key can therefore spend the account's funds directly — bypassing
the 2-of-3 entirely — and can re-delegate the account to a contract of the
attacker's choosing, permanently.

Rotating all three factors does **not** revoke it: the factors govern the
delegate's state, not the EOA's authority. This is not a race to initialize
first, and it does not end when the account is born. It is unlimited authority,
for the lifetime of the address.

The only remedy for a suspected compromise is **migrating every asset to a
newly born account**. EIP-7851, if it ships, would let a delegated EOA disable
its residual ECDSA authority at the protocol level and is the only real fix;
Glaux does not depend on it existing.

The entire security of the account therefore rests on the birth key never
leaving the process that generated it, and being destroyed immediately after
producing exactly two signatures. That is a process guarantee, not a contract
guarantee, and the contract cannot help: it verifies the birth signature
against `address(this)` precisely because the birth key and the account address
are the same authority, so "the owner's key" and "a copy of the owner's key"
are indistinguishable at the cryptographic level.

### 2. Two compromised factors is full control, by design

An attacker holding any two factor keys can execute arbitrary calls, rotate all
three slots, change verifier types, and upgrade the implementation. There is no
defence inside the contract and none is claimed. Security depends entirely on
keeping any two factors from falling to the same adversary — the design's
central assumption, stated without hedging.

Every check described in this document — code hashes, compatibility markers,
duplicate-slot rejection — filters mistakes and incompatible code. None of them
filters a quorum that has already reached the threshold.

### 3. Same-nonce cross-chain equivocation

**No on-chain mitigation. Closed only by signer-side discipline.**

Because update digests carry no chain-id, two different `Update` payloads signed
by the same quorum for the *same* nonce are each independently valid, and each
is accepted on whichever chain sees it first. `applyUpdate` only checks
`u.nonce != l.updateNonce + 1` against that chain's own storage; it cannot know
another payload consumed that nonce elsewhere. The result is a genuine fork:
chain A holds configuration X at nonce N, chain B holds configuration Y at nonce
N, and both have advanced past it.

Per-chain nonces cannot prevent this by construction — the point of the
chain-agnostic channel is that one signature reaches every chain, which
requires a shared nonce space. The rule is therefore absolute and signer-side:
**never sign two distinct updates for one nonce**, treating an update as
consumed the moment it is signed rather than when it is observed.

**Detection must include the implementation pointer.** A `SetImplementation`
update changes only the implementation pointer while advancing the nonce like any
other update. Two chains can therefore show an identical `updateNonce` *and*
identical factor slots while running entirely different logic. Comparing nonce
and slots alone hides precisely the divergence that matters most; clients must
also compare the implementation pointer, its live code hash, and the delegation
target.

**Recovery is harder than "sign a higher nonce."** `applyUpdate` requires
exactly `updateNonce + 1`, never merely a greater value, so there is no jump to
a convergence point: each branch must be walked forward step by step. If the
branches rotated *different* slots, one signature pair may not be valid on both
— the payloads must be identical while the signatures may have to be produced
per branch, by whichever quorum each branch still recognizes, potentially over
several sequential updates. And if one branch installed logic that broke
`applyUpdate`, that branch cannot be recovered at all. Divergence is not
reliably repairable; it is to be prevented.

### 4. Losing the public artifacts makes future chains unreachable

**No on-chain mitigation. Closed only by client retention policy.**

Because the birth key is destroyed, the EIP-7702 authorization tuple and the
initialization blob can never be regenerated — and without them the account can
never be activated on a chain it has not yet reached. The same applies to the
update history: `applyUpdate` accepts only `updateNonce + 1`, so a lagging chain
can be caught up only by replaying every signed update in order. A missing
update at nonce N permanently strands every chain still below it, even with all
three current factors in hand, because that update's signatures came from
factors that may since have been rotated away.

All of this data is public and needs no secrecy — only durability. A client
that treats it as ephemeral transaction data has quietly made the account's
future chains unreachable.

### 5. A code hash binds bytecode, not behaviour

The installed bytecode is provably byte-for-byte what the signers intended.
What that bytecode *does* is not thereby fixed across chains.

Note what is *not* a source of divergence, since it is easy to get backwards:
constructor-set immutables are embedded in the runtime bytecode and therefore
*are* covered by the hash, and an implementation's own storage is never read
when the router delegatecalls into it, because execution uses the account's
storage. The real sources are:

- **the account's own state**, which differs per chain;
- **the chain environment** — chain id, block properties, and whether a
  precompile the code depends on exists at all;
- **external contracts at fixed addresses** whose *code* differs per chain, or
  which are contracts on one chain and empty accounts on another;
- **an implementation that is itself a proxy**, where identical bytecode
  forwards to different logic per chain.

Signers verifying `expectedCodeHash` are verifying "this exact bytecode", not
"this exact behaviour". Client guidance requires reviewing storage-layout
compatibility, external dependencies and the preservation of `applyUpdate`
itself, none of which any on-chain check can see.

### 6. The compatibility marker is self-attestation

The candidate must answer `glauxCompatibilityId()` with
`keccak256("GLAUX_ACCOUNT_V1")` — a 32-byte value it reports about itself, not
a proof of interface conformance beyond that single function. It stops
installing something that was never meant to be Glaux logic, and it stops an
incompatible future version that deliberately changed its marker to signal a
break. It does not stop an attacker who already controls a quorum, who can
deploy a contract returning the correct marker and doing anything else.

The bounded 32-byte output window means a candidate returning enormous
returndata is rejected cleanly rather than exhausting the gas of the
transaction that carries it.

### 7. A key must prove possession before it is installed — enforced on chain

This was a declared residual in an earlier draft. It is now a contract check,
because review demonstrated it was not a hygiene issue but the foundation the
whole threshold stands on.

`SignatureVerify.isValidKey` checks a candidate key's *shape*: a clean non-zero
address for secp256k1, a point actually on the curve for P-256. Shape is not
possession, and the gap is exploitable rather than merely untidy. **ECDSA
verifies by recovery, so a signature can be created before the key it verifies
under is chosen**: run the recovery over arbitrary signature values for a digest
known in advance and you obtain an address for which that signature is valid.
Two such addresses installed as slots meet the 2-of-3 threshold **with no
private keys in existence at all**, while every slot looks distinct and
well-formed on chain and `DuplicateSlot()` never fires. Anyone who supplies or
nominates two of the three slot addresses could pre-arm one specific operation —
a chain, a nonce and a payload, all knowable before birth — and execute it alone,
months later, through any unprivileged relayer.

`GlauxAccount._requirePossession` closes it. Every slot, at birth and on every
rotation, must carry a signature by its own key over

```
keccak256(abi.encode(REG_DOMAIN, slotIndex, verifierType, keccak256(keyData)))
```

Because the challenge **commits to the key material**, deriving a key from a
chosen signature no longer helps: an attacker would need a signature valid under
a key that a digest committing to that same key recovers to — a hash-preimage
search, not a curve computation.

The challenge deliberately binds neither chain nor account. The proof rides
inside the birth blob and the update payload, both of which replay everywhere;
and a factor must be able to produce its proof **before the account exists**,
because the paper factor is generated on an air-gapped machine and never comes
back online. A proof is therefore a portable, reusable artifact per key. That is
harmless: it authorizes nothing. Installing someone else's proven public key
into your own account grants you no ability to sign with it.

Two consequences worth stating plainly:

- **A P-256 factor can only be installed on a chain that has a working
  P256VERIFY precompile**, since the proof is verified with it and since
  installation probes the verifier first (v0.6). Birth fails cleanly there,
  with `P256VerifierUnavailable()`, rather than producing an account with an
  unusable factor, and the blob stays retryable if the chain gains the
  precompile later. See residual 8.
- The residual that remains is the ordinary one: possession is not exclusivity.
  A proof shows someone held the key at signing time, not that only the intended
  party holds it. That is residual 2's territory, not this one's.

### 8. P-256 verification depends on a precompile that not every chain has

`SignatureVerify._verifyP256` staticcalls address `0x100` (RIP-7212 /
EIP-7951). On a chain without that precompile the call returns empty and
verification returns `false` — proven by
`test/SignatureVerify.t.sol::test_p256_noPrecompile_false`.

The failure mode *was* quiet and asymmetric: slot installation validated only
the key's shape and therefore succeeded anywhere, while signing with that factor
was impossible on such a chain — and with TWO P-256 slots the account was born
inert, since every possible pair then contains a factor that cannot sign, so no
quorum can form at all and `applyUpdate` cannot rotate out either, rotation
being itself an operation that needs a quorum. Birth submission is
permissionless, so a third party could bring an account up in that state on any
chain it had not yet reached.

*(closed at installation, v0.6)* `GlauxAccount._validateSlot` now probes the
verifier before installing any P-256 slot, at birth and at rotation alike, and
reverts `P256VerifierUnavailable()`. The probe is a known-answer test with two
arms — a valid signature that must be accepted, the same signature against a
different message that must be rejected — because a one-armed probe would
accept any code that answers `1`, and a verifier that never says no is worse
than no verifier: every signature presented to that slot would be valid. That
second arm is what makes the check meaningful on a chain that put something
unrelated at `0x100`. secp256k1 is deliberately not probed: `ecrecover` is in
the protocol everywhere, and probing it would close the one rescue that matters
— rotating a factor *away* from P-256 on the chain that lacks the verifier.

What remains is not a bug but a consequence, and clients must design for it:

- **A chain without the verifier cannot host the account's chosen
  configuration.** The same signed birth blob succeeds where the verifier
  exists and reverts where it does not, so a chain reached later may hold no
  account at all rather than a degraded one. That is the intended trade — an
  account that cannot be born is recoverable, an account born inert is not —
  but it means the supported-chain matrix is still a client obligation.
- **The probe speaks for the moment it runs.** It cannot bind the chain's
  future: a fork that removes or weakens whatever answers at `0x100` degrades
  or breaks a P-256 factor already installed. No on-chain control can prevent
  that; it is a chain-trust assumption, and it is the reason client guidance
  still refuses two P-256 slots unless every target chain has the precompile.
- **The probe stops accidents, not a chain that is out to get you.** Its vector
  is a constant in public source, so code at `0x100` written to defeat it —
  answer honestly for those exact 160 bytes, answer "valid" to everything else
  — passes both arms. That cannot be fixed by a better vector: verifying a
  *fresh* challenge on chain would require the very verifier under test, so a
  known answer must be a known answer. It also does not need fixing. A chain
  whose P-256 verifier is adversarial owns every P-256 signature check the
  account will ever make, at signing time as much as at installation, so no
  install-time control could save the factor there. What the probe rules out is
  the reachable accident: no verifier at all, or unrelated code at that address.

This is a chain-availability limit, not an ERC-4337 limit: **ERC-7562 rule
OP-062** explicitly permits the `P256VERIFY` precompile of EIP-7951 during the
validation phase, so a P-256 factor is compatible with bundlers on networks that
have it. The direct `executeWithSigs` path needs no bundler in any case.

### 9. P-256 signature malleability is deliberately not normalised on-chain

`_verifySecp256k1` rejects the high-`s` form; `_verifyP256` performs no
equivalent check, so a valid P-256 signature `(r, s)` and its counterpart
`(r, n-s)` are both accepted for the same message and key.

This is safe *in this design specifically* because replay protection is
nonce-based, never signature-based: `applyUpdate` and `executeWithSigs` check a
monotonic nonce, and no signature value or hash of one is ever used as an
identifier, idempotency key, or uniqueness constraint anywhere in the contract.
Malleability matters only where a system infers "have I seen this before?" from
signature bytes. Glaux never does, so a differently-encoded signature over an
already-consumed nonce is rejected by the nonce check exactly as a duplicate
would be.

### 10. Permissionless relay: censorship is possible, alternatives are not guaranteed

Anyone may submit a validly-signed payload, and whoever submits it pays. That
is what makes a cross-chain gas account possible at all, and it means a relayer
chooses only *whether* and *when* to include a payload, never *what* it says: a
relayer can never forge a signature, alter a signed payload, or make a delayed
operation land out of nonce order.

The honest limit: because relaying requires no authorization, a censored payload
**can be offered to another relayer** — but that is the removal of an
allowlist, not a guarantee of inclusion. Nothing here promises that an
alternative sponsor exists, that a sequencer will include the transaction, or
that the chain is live.

### 11. Chains never touched

Before an authorization and an `initialize` land on a given chain, the address
there is a plain undelegated EOA with no Glaux state at all; after some updates
but not others, it holds a configuration that lags. There is no global registry
the contract consults. A client that queries one chain and presents its
configuration as universal misleads the user; UIs must query every chain of
interest and represent staleness and divergence honestly.

### 12. Upgrade is irreversible in one direction

`initialize` reverts `AlreadyInitialized()` the moment Glaux's own
implementation slot is non-zero, and nothing anywhere clears it back to zero. Once born, an account's
logic can change only through `applyUpdate`, which depends on the currently
installed implementation still working. A quorum that installs an
implementation which passes the code-hash and marker checks but whose
`applyUpdate` is unreachable or always reverts has stranded the account on that
implementation permanently.

This is the direct cost of birth being a strictly one-time event: it buys the
guarantee that a live account can never be re-initialized out from under its
owners, and it provides no safety net if an upgrade breaks the upgrade path.
Client guidance therefore requires staged rollout — land an upgrade on one
low-value chain and verify the account still functions before propagating it.

### 13. A signed birth blob never expires and cannot be revoked

The update channel has an absolute signer-side rule — never sign two updates for
one nonce. Birth has no equivalent, and it needs one: **any birth blob ever
signed stays a live takeover primitive, forever, on every chain the account has
not yet been born on.** The digest carries no deadline, the immutable router has
no mechanism to invalidate one, and the birth key that could have signed a
replacement is destroyed by design. `test_birth_noCodeImplementationRevertsAndOriginalBlobIsRetryable`
deliberately proves that durability, because a blob must survive to reach chains
that do not exist yet; the same property means a second, differently-configured
blob signed during setup is an unrevokable backdoor.

The rule is therefore: **sign exactly one birth blob, ever.** If a client's flow
can produce two — a retry, a "regenerate", an aborted setup that already
signed — that flow is broken, and no on-chain check will catch it.

### 14. Direct execution has no deadline

The execution digest binds the chain, the account, the nonce and the calls — but
not *when*. A relayer holding a signed batch may submit it at any later moment,
and for a value-moving operation that is not a neutral choice: sitting on a
signed swap and submitting it after the price has moved extracts real value. The
only cancellation available is racing a different batch at the same nonce
against the party who is holding yours.

ERC-4337 has `validUntil` for exactly this reason, and **v1 does not use it
either**: `validateUserOp` returns `0`, which the EntryPoint interprets as a
`validUntil` of `type(uint48).max`. So the sponsored path is valid forever too,
and preferring it buys no protection — an earlier draft of this document said it
did, which was wrong. Both paths live in the upgradeable implementation and can
gain a deadline through an ordinary upgrade. Until they do, clients must treat
every signed operation as live indefinitely and must not sign a time-sensitive
one they are not willing to see executed at an arbitrary later moment.

### 15. Point-in-time code checks, and other narrow residuals

- **The implementation code hash is checked at install, never again.** A
  metamorphic address combined with EIP-6780 semantics could let quorum-signed
  logic be swapped afterwards under an already-verified hash. This requires the
  quorum to have signed a metamorphic implementation in the first place.
- **A pointer to an address holding no code fails silently.** A delegatecall to
  a codeless address succeeds with empty returndata, so calls appear to succeed
  and `view` calls appear to return zero. Reachable only through
  create/install/selfdestruct within one transaction, all quorum-authorized.
- **The marker staticcall forwards all remaining gas.** The returndata window is
  bounded, so nothing can be copied back, but a hostile candidate can still burn
  the submitter's gas. The submitter is whoever chose to relay the operation.
- **`executeFromEntryPoint` emits `Executed` without advancing the nonce it
  reports**, by design — the EntryPoint owns replay protection on that path — so
  every 4337 execution logs the same value and an indexer cannot distinguish
  them by nonce alone.

## Not implemented in v1 (scope, not oversight)

- **No ERC-721/ERC-1155 receiver hooks.** `safeTransferFrom` of an NFT to a
  Glaux account reverts. Any unknown selector reverts through the router.
- **No ERC-1271.** The account cannot produce contract signatures, so it cannot
  be used with Permit2, Seaport, or other signature-consuming protocols.

Both live in the upgradeable implementation and are additive. They are called
out here because a reference smart account is expected to have them, and their
absence should be a stated decision rather than a surprise.

## Resolved: EIP-191 version 0x00, not EIP-712 typed data

All three digests are raw `keccak256(abi.encode(...))` values, each prefixed
with a distinct domain constant (`GLAUX_INIT_V1`, `GLAUX_UPDATE_V1`,
`GLAUX_EXEC_V1`), and the update and execution digests additionally bind the
account address. That provides domain separation *between Glaux operations and
between Glaux and other protocols*, which is the security property usually meant
by the phrase.

What it does not provide is **legibility**. A signer sees an opaque 32-byte
hash, not a rendered description of what they are authorizing. For a project
whose stated ambition is an ERC draft and third-party adoption, that is a real
weakness.

**And there is a security half, which is the stronger argument.** The domain
constants separate Glaux from other *structured* signing schemes; they do not
separate it from **raw-hash signing**. Any factor key that is also an ordinary
EOA key, and that can be induced to sign a bare 32-byte digest through
`eth_sign` or an equivalent, produces a valid Glaux signature. On the migration
path this project plans, the birth key *is* a long-lived user key — so a single
raw-hash signature obtained before birth installs an attacker's implementation
and an attacker's slot set. Until this is addressed, the rule in client guidance
against ever exposing a factor key to an unprefixed-digest API is the only thing
standing in the way.

This also admits a third option, which dissolves the chain-agnosticism tension
entirely: **EIP-191 version `0x00`** — `0x19 ‖ 0x00 ‖ validator ‖ data`. It
makes a Glaux digest unreachable by raw-hash signing and binds the validator
address, and it has **no `chainId` field at all**, so it costs nothing in
replayability. It buys no legibility, being untyped, but it closes the security
half independently of how the adoption half is decided.

Two things are true and pull in opposite directions. The birth digest lives in
the **immutable** router, so this choice is permanent for birth once the router
is deployed at a canonical address. But EIP-712's usual chain-id domain field
would break the deliberate chain-agnosticism of the birth and update blobs, so
adopting it means adopting a domain separator that omits `chainId` — unusual,
and something wallet tooling may render or reject inconsistently.

**Resolved: EIP-191 version `0x00` is adopted.** The birth, update and execution
digests are each wrapped as `0x19 ‖ 0x00 ‖ validator ‖ structHash`, with the
router as validator for birth and the account for the other two. This closes the
raw-hash-signing hole — a bare 32-byte value signed through `eth_sign` can no
longer be a Glaux digest — and it binds the validating contract into every
signature, while carrying **no `chainId` field**, so blobs keep replaying on
every chain. It buys no legibility, being untyped; adopting full EIP-712 on top
remains open for a future version and would be a spec change, not a security
fix. The decision was taken before deployment: nothing here has been deployed
anywhere except local test chains.

## Declared residual: deployment reproducibility

The cross-chain claim rests on the router and the implementation existing at the
same CREATE2 addresses on every chain, and on the birth blob's `expectedCodeHash`
matching the implementation deployed there. Both are functions of the exact
compilation output.

`bytecode_hash = "none"` is set in `foundry.toml` for this reason: Foundry
otherwise appends a CBOR metadata hash that covers compiler settings, source
unit names and the keccak of every source file **including its comments** — so
editing a comment would move the canonical address and silently invalidate every
unspent blob. With it stripped, the bytecode is a function of the code alone.

What remains a client obligation: deploying on a new chain requires reproducing
the same compilation (same solc version, same settings) and requires the
canonical CREATE2 deployer `0x4e59b448...` to exist there. If either fails, the
account cannot be born on that chain — and because the router's `receive()`
accepts value regardless, an address that can never be born on is still an
address that can receive funds. **Never accept funds at the account address on a
chain where the router and implementation are not already deployed at the
canonical addresses.**
