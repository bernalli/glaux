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

**The ERC-1967 implementation pointer.** Written once by
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
initializer to leave `initialized == true` before the ERC-1967 slot is written,
so a delegatecall into an implementation that silently no-ops cannot produce a
live-looking but unconfigured account.

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
update changes only the ERC-1967 pointer while advancing the nonce like any
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

### 7. Key-shape validation cannot prove key possession

`SignatureVerify.isValidKey` checks that a secp256k1 slot holds a clean
non-zero address, and that a P-256 slot holds a point actually on the curve.
Both are checks of *well-formedness*, never evidence that anyone holds the
corresponding private key. A quorum can install — by mistyping a value or
restoring the wrong backup — a slot nobody can ever sign with.

The consequence is graded, and it is worth stating precisely rather than
dramatically: **one** unusable slot does not brick the account, because the
other two still form a quorum; it silently degrades a 2-of-3 into a 2-of-2 with
no remaining margin, and nothing on chain shows this. **Two** unusable slots
are unrecoverable on every chain born from that configuration.

Mitigation is signer-side and cheap: require every candidate factor to sign a
random registration challenge, verify that signature locally under exactly the
contract's rules, and never install a factor that has not signed. After a
rotation, re-run the challenge against the slot data read back from the chain.

### 8. P-256 verification depends on a precompile that not every chain has

`SignatureVerify._verifyP256` staticcalls address `0x100` (RIP-7212 /
EIP-7951). On a chain without that precompile the call returns empty and
verification returns `false` — proven by
`test/SignatureVerify.t.sol::test_p256_noPrecompile_false`.

The failure mode is quiet and asymmetric: slot *installation* validates only
the key's shape and therefore succeeds anywhere, while *signing* with that
factor is impossible on such a chain. An account whose F1 is P-256 silently
operates as 2-of-2 there.

**With TWO P-256 slots it is worse than degraded — the account is born inert.**
Every possible pair of slots then contains at least one P-256 factor, so no
quorum can be formed at all: nothing executes, and `applyUpdate` cannot rotate
out of the situation either, because rotating is itself an operation requiring a
quorum. Client guidance permits F3 to be P-256, so this configuration is
reachable by following the documentation. Birth submission is permissionless, so
a third party can bring an account up in this state on any chain it has not yet
reached. Clients must maintain a supported-chain matrix and probe the precompile
before relying on a chain, and must ensure at least two slots are verifiable on
every chain the account is meant to operate on.

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

`initialize` reverts `AlreadyInitialized()` the moment the ERC-1967 slot is
non-zero, and nothing anywhere clears it back to zero. Once born, an account's
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

ERC-4337 has `validUntil` for exactly this reason; the direct path has no
equivalent in v1. This lives in the upgradeable implementation, so it can be
fixed by an ordinary upgrade rather than a redeployment — but until it is,
clients should treat a signed batch as live indefinitely and prefer the 4337
path for anything time-sensitive.

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

## Open design decision: no EIP-712 typed data

All three digests are raw `keccak256(abi.encode(...))` values, each prefixed
with a distinct domain constant (`GLAUX_INIT_V1`, `GLAUX_UPDATE_V1`,
`GLAUX_EXEC_V1`), and the update and execution digests additionally bind the
account address. That provides domain separation *between Glaux operations and
between Glaux and other protocols*, which is the security property usually meant
by the phrase.

What it does not provide is **legibility**. A signer sees an opaque 32-byte
hash, not a rendered description of what they are authorizing. For a project
whose stated ambition is an ERC draft and third-party adoption, that is a real
weakness, and it is worth stating plainly that the argument for typed data here
is an adoption argument, not merely an aesthetic one.

Two things are true and pull in opposite directions. The birth digest lives in
the **immutable** router, so this choice is permanent for birth once the router
is deployed at a canonical address. But EIP-712's usual chain-id domain field
would break the deliberate chain-agnosticism of the birth and update blobs, so
adopting it means adopting a domain separator that omits `chainId` — unusual,
and something wallet tooling may render or reject inconsistently.

**Status: open, and deliberately not resolved unilaterally.** It must be decided
before the router is deployed to any address intended to be canonical, because
after that it cannot be revisited. Nothing in this repository has been deployed
anywhere except local test chains.
