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

**The birth blob — and no birth key.** Until 2026-08-05 the account was born
from an ephemeral EOA key that signed its own delegation tuple, and a surviving
copy of that key was the most serious property in this document. That key no
longer exists at any point: the delegation tuple is *crafted*, never signed, and
the address is whoever `ecrecover` reports for it (residual 1). What remains is
the blob itself, and its asset property is availability rather than secrecy — it
is public by construction, and losing it makes chains the account has not
reached yet unreachable (residual 4).

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

**An attacker who supplies the delegation target.** Not a Glaux adversary at
all, and the most common one in practice: the user is persuaded to sign an
EIP-7702 authorization pointing at the attacker's contract instead of Glaux's
router. This is the dominant failure mode of 7702 in the wild — more than 97% of
delegations on chain point at copies of one sweeper contract ("CrimeEnjoyor"),
which has drained 450,000+ wallets, and an April 2026 incident routed a call
through a delegated admin EOA to drain a token pool. *Guarantee:* none. Glaux's
contracts are not reached at all in this scenario; the account never becomes a
Glaux account. *What it demands of the design:* the delegation target must be
worth pointing at and cheap to check — immutable, deployed deterministically at
the same address on every chain, with a code hash a client can compare against a
published constant before signing anything. That is why the router is frozen and
CREATE2-deployed rather than upgradeable, and why `initialize` binds the
implementation's code hash into the birth proof. A wallet integrating Glaux
must show the user the target address and verify it against the canonical one;
no on-chain check can help a user who signed for someone else's contract. Under
rootless birth the user signs no delegation at all, which removes the phishing
surface at birth but not the need for that check: the router's address is inside
the authorization preimage the account address is recovered from, so crafting
against the wrong router produces an account delegated to it, born correctly and
irrevocably.
Sources: [CrimeEnjoyor
analysis](https://dev.to/ohmygod/the-crimeenjoyor-epidemic-how-eip-7702-delegation-phishing-drained-450k-wallets-and-how-to-e2g),
[QNT pool drain via a delegated admin
EOA](https://www.darknavy.org/web3/exploits/qnt-pool-drain-via-eip-7702-admin-eoa-delegation/).

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

### 1. A surviving birth key was a permanent master key *(closed by construction, 2026-08-05)*

The account's EOA key used to be a real key. EIP-7702 delegation does not strip
an EOA of its own authority — a delegated EOA can still originate ordinary
transactions and sign further authorization tuples — so a surviving copy of the
key that signed the birth could spend the account's funds directly, bypassing
the 2-of-3 entirely, and re-delegate the account permanently. Rotating all three
factors did not revoke it: the factors govern the delegate's state, not the
EOA's authority. The mitigation was a promise about a process: generate the key
in one process, destroy it after exactly two signatures. A promise is not a
guarantee, and nothing on chain could tell "the owner's key" from "a copy of the
owner's key".

**No key is generated any more, so there is none to survive.** The delegation
tuple is crafted rather than signed: `r` is `keccak256(digest ‖ salt)`, a
commitment to this exact birth configuration; `s` carries a 13-byte tag; and the
account *is* whatever address `ecrecover` returns for that pair against the
authorization preimage. The router recomputes all three facts at birth and
reverts unless they hold. Producing the same tuple with a real key would require
either a nonce `k` with `x(kG) = r` — inverting the discrete log — or a private
key whose signature happens to carry 13 chosen bytes of `s`, about 2^103 work.
So a born Glaux account is *provably* one for which no private key has ever
existed. This is the property [EIP-8164](https://eips.ethereum.org/EIPS/eip-8164)
(Draft, February 2026) names as a goal for protocol-level rootless accounts;
Glaux now has it in userland, without depending on 8164 or on EIP-7851 shipping.

Precisely what is claimed: no party has ever *held* the key. A private key for
that address exists mathematically — every curve point has a discrete log — and
an adversary who breaks secp256k1 recovers it from the public key the
authorization tuple exposes, exactly as for any EOA. Rootlessness removes the
custody problem, not the cryptographic assumption — which is why the crypto
agility of the factor slots stops at the delegation itself, as the README says
in the same terms.

Two limits, stated because they are the price:

- **The delegation is irrevocable, and now unconditionally so.** There is no key
  that could sign a different authorization tuple, so the account can never be
  re-delegated to another wallet — not by an attacker, and not by its owner
  either. Everything the account will ever do it does through this router, and
  the only way its logic changes is a `SetImplementation` update signed by the
  quorum (residual 12 covers what that direction does and does not allow).
- **Rootlessness is verifiable from the birth, not from current state.** The
  router checks the proof at birth and stores nothing about it afterwards, so an
  observer looking only at the account's *state* sees an ordinary delegated EOA.
  The proof is public anyway, in two places: the birth blob, and the birth
  transaction itself, whose calldata carries the configuration and the salt and
  whose authorization list carries `(r, s)`. Anyone with either can re-derive
  `r`, check the tag, recover the address and confirm it. So an account whose
  blob is lost remains demonstrably rootless to anyone who can still reach that
  transaction's history — the blob matters for *reaching new chains* (residual 4),
  not for proving what the account is.

### 2. Two compromised factors is full control, by design *(accepted, see below)*

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

The authorization tuple is derived deterministically from the birth digest, so
in principle it can always be recomputed — but only from the *same* `initData`,
and `initData` carries the three possession proofs. Under a random-nonce signer,
re-signing a proof produces a different `initData`, a different digest, and
therefore a **different account**; under a deterministic (RFC 6979) signer it
reproduces the same one. Recomputation is recovery only in the second case.

Two qualifications keep this from being read as worse than it is. Once the
account has been born anywhere, that transaction publishes the entire blob — the
calldata carries `implementation`, `expectedCodeHash`, `initData` and the salt,
the authorization list carries the tuple — so it can be rebuilt from chain
history for as long as that history is reachable. The retention rule is
therefore absolute only before the first birth. The same applies to the
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

### 13. A birth blob never expires and cannot be revoked *(narrowed by rootless birth)*

A birth blob stays valid forever, on every chain the account has not yet been
born on. The digest carries no deadline and the immutable router has no
mechanism to invalidate one.
`test_birth_noCodeImplementationRevertsAndOriginalBlobIsRetryable` deliberately
proves that durability, because a blob must survive to reach chains that do not
exist yet.

Until 2026-08-05 that durability was also a takeover primitive: the account
address was the birth key's address, so a *second*, differently-configured blob
signed during setup was a valid birth for **the same address** — an unrevokable
backdoor that could be spent on any chain the account had not reached, installing
factors the owner never chose. Rootless birth removes that: the address is
recovered from `r`, which commits to the digest, which covers the implementation,
its code hash and `initData`. Change any of them, or the salt, and the proof
recovers to a different address. Two blobs are therefore two accounts, and a
blob is only ever a birth for the account it names. Hitting an existing account
with a different configuration would mean searching for a colliding recovery —
2^160 work, not a setup mistake.

What survives is a different failure, and it is not an attacker's: **a client
flow that can produce two blobs may produce two accounts.** Whether it does
depends on the signers, and the two reference clients in this repository differ
on exactly this point — which is itself worth knowing before integrating:

- with **deterministic (RFC 6979) signers**, which the TypeScript reference
  signers are, re-signing yields identical proofs, so a second craft from the
  same factors reproduces the same `initData` and the same address;
- with a **random-nonce signer** — the Python `prove_possession.py`, which
  signs through OpenSSL, and any signer that draws a fresh `k` — each craft
  yields a different proof, hence a different address. Hardware backing does not
  settle which of the two a factor is; its nonce policy does.

Production uses the second kind, so the second is the case to design for. Both
addresses answer to the same factors, so nothing is handed to anyone else; the
danger is that funds sent to an address whose blob was discarded as "the failed
attempt" are **unrecoverable** when the proofs cannot be reproduced. That address
cannot be born without its blob, cannot be reached without being born, and has no
key that could move anything directly. Craft once, keep the blob, and treat a
second craft as a new account rather than a repair of the first.

### 14. Execution deadlines *(closed, v0.7)*

The execution digest bound the chain, the account, the nonce and the calls — but
not *when*. A relayer holding a signed batch could submit it at any later moment,
and for a value-moving operation that is not a neutral choice: sitting on a
signed swap and submitting it after the price has moved extracts real value. The
only cancellation available was racing a different batch at the same nonce
against the party holding yours. The 4337 path was no better: `validateUserOp`
returned `0`, which the EntryPoint reads as a `validUntil` of `type(uint48).max`,
so preferring it bought no protection — an earlier draft of this document said it
did, which was wrong.

Both paths now carry a deadline the factors sign.

- **Direct**: `executeWithSigs(calls, validUntil, sigs)` binds `validUntil` into
  the digest and reverts `OperationExpired(validUntil, block.timestamp)` once
  `block.timestamp` passes it. The check runs *before* signature verification, so
  a dead operation costs a comparison rather than two curve operations.
- **ERC-4337**: the deadline rides in the signature blob,
  `abi.encode(uint48 validUntil, SlotSig[2] sigs)`, and the factors sign
  `eip191(account, keccak256(abi.encode(USEROP_DOMAIN, userOpHash, validUntil)))`.
  It cannot ride in `userOpHash` — that is the EntryPoint's construction and has
  no room for an account field — so signing over both is what stops a bundler
  from widening the window while the signature stays valid. The account reports
  the window through `validationData` and the EntryPoint enforces it, which is
  what makes an expired operation get dropped rather than landed and reverted.

`validUntil == 0` is refused on both paths, and deliberately so: on the direct
path zero is a deadline in the past like any other, while the EntryPoint reads a
zero as "no expiry" — the exact unbounded state this closes. Rather than let the
two paths disagree about what zero means, `validateUserOp` fails validation on
it. An operation that genuinely should live a long time says so with an explicit
far-future timestamp, in a field the signers can see.

What remains is a bounded version of the same thing: within its window an
operation is still submittable at any moment of the holder's choosing, and there
is still no revocation short of racing the nonce. A deadline shrinks the window;
it does not hand the signer a cancel button. Clients must size the window to the
operation — minutes for a swap, not a year for convenience.

`applyUpdate` deliberately has no deadline. Update blobs are chain-agnostic by
construction and must stay valid for chains the account has not yet reached; a
timestamp would silently strand them there. That trade is residual 4's territory,
not this one's.

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

### 16. ERC-1271: authorized movement leaves no nonce trace *(accepted, see below)*

With the message channel live, `execNonce` is no longer a complete record of
authorized value movement: the quorum can sign a Permit2 witness or a Seaport
order and funds move when a THIRD party consumes the signature, with no Glaux
nonce advancing and no on-chain trace beforehand. The deadline inside the blob
bounds the window; nothing restores the record. Client rule: a request to sign
a message IS a request to authorize an action, and must be presented as one —
see `client-guidance.md`.

What the channel does enforce: the consumer's hash is wrapped under
`MSG_DOMAIN` with `block.chainid`, the account address and the deadline, so a
message signature is useless on any other channel, any other chain, and any
other account, and expires. Failure is the `0xffffffff` sentinel, never a
revert — except on an account never born, where the ROUTER reverts
`NotInitialized` before implementation code runs.

### 17. Storage pre-poisoned by a prior hostile delegate

**No on-chain mitigation. Closed only by a client-side pre-birth check.**
Found in the 2026-08-03 internal audit (`docs/internal-audit-2026-08-03.md`).

An EIP-7702 re-delegation does **not** clear the account's storage, and Glaux's
slot constants are public. So if an EOA was ever delegated to hostile code on a
chain, that code could have deliberately written Glaux's own namespaced slots —
`keccak256("glaux.account.v1.implementation")` and
`keccak256("glaux.account.v1.storage")` — before the user ever chose Glaux. Two
outcomes, both reproduced by passing regression tests in `test/Birth.t.sol`
(`test_residual17_plantedImplPointerBricksBirthAndIsExecuted`,
`test_residual17_plantedFullStateMakesAccountAttackerOwned`):

- **Brick plus hostile execution.** Plant only the implementation pointer: the
  user's later birth through the router reverts `AlreadyInitialized` forever
  (the router reads a non-zero pointer), while the router's `fallback`
  delegatecalls the planted address on every call in the meantime.
- **Full takeover.** Plant the implementation pointer at the real
  `GlauxAccount`, the header word with `initialized = 1`, and three attacker
  factor slots: the instant the user delegates to the correct router, the
  account is a fully working Glaux account owned by the attacker —
  `implementation()` and `getSlot()` all answer plausibly, and two attacker
  signatures are a quorum.

Note what this is **not**: it is not the direct-delegation-to-implementation
seizure (residual-free after the H-1 fix — `initializeAccount` now refuses to
run outside a router birth). This residual never passes through
`initializeAccount` at all; the state is pre-planted, so the birth-guard cannot
see it.

**Precondition**: the EOA carried a hostile delegation designator on that chain
at some earlier point. Rootless birth makes that precondition unreachable rather
than merely unlikely. Writing an account's storage requires executing code as
that account, which requires a delegation, which requires an authorization tuple
that recovers to that exact address — and nobody holds a key for a rootless
address, including whoever crafted it. Crafting cannot help either: it yields
whatever address the chosen digest happens to recover to, never a chosen one, so
aiming a craft at an address someone is about to use is the 2^160 search again.
The address is also unknown to everyone until the blob exists.

What kept this residual alive was the migration path — birthing an account from
a long-lived user EOA, where the address is old, public, and may well have been
delegated before. That path is not available under rootless birth (an address
that answers to a key is not reachable from a proof that no key exists) and is
deferred until the protocol can neutralise an EOA's signing authority; see the
roadmap. The pre-birth verification below stays in the client as defence in
depth, and because it costs one `eth_getStorageAt` per word.

There is no honest on-chain fix: whoever can write one namespaced slot can
write them all, so no in-contract check can distinguish planted state from
genuine state. The defence is client-side and normative — see the pre-birth
verification and the "never migrate an already-delegated EOA" rule in
`client-guidance.md`. The reconciliation step catches a mismatch only *after*
birth, which for the takeover case is already too late.

A sharper third variant, found in the fix re-review: instead of planting a
pointer, a prior delegate plants a **fabricated `bytes` length** in a factor
slot's data-head word (`BASE + 2 + 2i`). At birth, the memory→storage struct
copy `l.slots[i] = s` must zero the old array's tail, and an enormous planted
length turns that into an unbounded loop — birth runs out of gas and can never
succeed on that chain, and no key exists that could reach the address by any
other route. Because
`IMPL_SLOT` and the header word both stay zero, a check that reads only those
two would pass. The pre-birth verification therefore reads **all** namespaced
words (the implementation pointer, the header, and the six slot words
`BASE+1..BASE+6`) and requires every one to be zero.

### 18. A hostile RPC can solicit a future-nonce execution *(narrowed client-side, accepted, see below)*

Both outbound execution paths put an RPC-supplied sequential nonce under the
factor signatures. Direct execution signs the account's `execNonce`; ERC-4337
signs EntryPoint's `getNonce(account, 0)` inside `userOpHash`. A hostile endpoint
can answer with the real value plus one and retain the resulting signed payload.
It is invalid immediately, but after one legitimate execution advances that
nonce it becomes valid and permissionlessly submittable until `validUntil`.
For a value-moving batch this is a delayed double spend, not merely a failed
transaction. Direct submission exposes the blob to the RPC during preflight
simulation, while a 4337 bundler/submission endpoint necessarily receives the
signed UserOperation.

The SDK now reads each nonce twice at one pinned block: through the getter and
through raw storage (the packed Glaux header for direct execution; the vendored
EntryPoint v0.7 nonce mapping for 4337). It refuses disagreement, optionally
requires an independently obtained `expectedNonce`, and defaults to refusing a
`validUntil` more than one hour beyond the client's local clock. The local clock
is deliberate: asking the suspect RPC for a timestamp would add no independent
bound.

This does **not** close the residual. A fully hostile endpoint can forge getter
and raw-storage replies consistently. The default deadline only limits how long
the harvested future-nonce payload can become useful, and it remains replayable
inside that hour; an integrator can explicitly widen the ceiling. The nonce is
authenticated only when `expectedNonce` comes from a genuinely independent
trusted state view. The normative integration rule and override warning are in
`client-guidance.md`.

The same limit applies to **birth**, and is worth naming because the SDK's
postconditions there look like independent confirmation and are not: `submitBirth`
broadcasts, takes its receipt, and reads the resulting code and storage back
through the one client it was given. An endpoint that answers dishonestly can
report a mined, successful birth that never happened, and satisfy every readback
that follows — after which the caller has an address it believes is a live Glaux
account. Nothing on chain can distinguish this: the account either exists on that
chain or it does not, and only a state view the endpoint does not control can say
which. Confirm a birth against a second, independently operated endpoint before
funding the address — the same rule as `expectedNonce`, applied one step earlier.

### 19. Gas and fee fields were signed without a ceiling *(closed on the 4337 path)*

Every gas and fee field of a user operation was proposed by an endpoint and
signed as given. That is not a quotation the account can shop around: the
signature authorizes the EntryPoint to collect a prefund of
`(verificationGasLimit + callGasLimit + preVerificationGas + the paymaster's two
limits) * maxFeePerGas`, so an endpoint that inflated any factor of that product
was inflating what the quorum agreed to, and the unspent remainder only returns
after the fact. The prefund is taken from the account when the operation is
self-funded and from the paymaster's deposit when it is sponsored; the cap
bounds the authorization in both cases.

`signUserOp` now refuses two things before any factor signs. A mandatory
`maxCostWei` bounds that whole product — no default, because a default is a
number nobody chose standing in for the one decision this exists to force. And
`maxFeePerGas` is measured against a baseline the SDK computes itself from
`eth_feeHistory` (the next block's base fee and the median of the sampled
blocks' median tips), refusing anything beyond a sanity multiple of it; the
proposed value cannot also be the yardstick it is judged by. Both checks sit at
the signing choke point rather than where the operation is built, because a
paymaster decorates it in between and a caller may supply one the SDK never
built.

What this does not do: a hostile endpoint asked for both the fee quote and the
fee history can lie consistently, so the baseline check degrades to nothing
against it — which is why the cap is absolute and independent of every
endpoint-supplied value, and why `client-guidance.md` requires the baseline
from a second, independent endpoint when the value at stake justifies it. On a
chain whose base fee is negligible next to the tips actually paid, the derived
lane can be tighter than legitimate operations need; a caller that sees
`FeeExceedsBaselineError` on healthy traffic there should supply its own
baseline rather than raise the multiple blindly.

The direct execution path is deliberately not covered. Its gas is fronted by
the relayer's own hot key, never charged to the account, so the exposure there
belongs to whoever operates the relayer and is bounded by what they fund it
with.

## Accepted residuals

Three of the residuals above will not be fixed. They were reviewed one by one on
2026-08-05 and accepted as properties of the design, in writing, so that nobody
later reads them as work still owed. The distinction that matters: residual 1
and the fee ceiling of residual 19 were *defects* and were closed; these three
are what the design is, and closing them would mean designing something else. A
fourth item below — A2, pinning the EntryPoint code hash — is not a design
property but a hardening that was considered and declined on a
cost-versus-threat basis.

**Residual 2 — two compromised factors is full control.** This is the definition
of a 2-of-3 threshold, not a gap in it. A contract that could tell a legitimate
quorum from a stolen one would be enforcing some other rule, and that rule would
become the real security boundary. Accepted as stated. The mitigation is entirely
in how factors are distributed — three genuinely independent custody domains, the
property `client-guidance.md` makes normative and the contract cannot verify.

**Residual 16 — ERC-1271 signatures carry no nonce.** The standard is stateless
by construction: the consumer decides when to redeem a signature, so nothing the
account does at signing time can make the redemption traceable in advance.
Adding a Glaux nonce would break compatibility with every protocol the channel
exists to reach (Permit2, Seaport), which is the whole value of supporting 1271.
Accepted. Mitigated by what the channel does bind — chain id, account address
and a deadline inside the blob — and by the client rule that a request to sign a
message is presented as a request to authorize an action.

**Residual 18 — a hostile RPC can misreport anything.** An endpoint is not a
trust anchor and was never treated as one; a client that reads state through a
single endpoint it does not control has already accepted whatever that endpoint
says. No amount of in-contract logic reaches this, because the contract never
sees the lie. Accepted, with two mitigations that are normative rather than
optional in `client-guidance.md`: confirm a birth and source an `expectedNonce`
from a second, independently operated endpoint, and note that the guards which
do not depend on any endpoint — the absolute `maxCostWei` cap, the local clock
bounding `validUntil` — keep holding against a fully hostile one.

**A2 — the EntryPoint code hash is not pinned.** Verifying `EXTCODEHASH` of the
EntryPoint on every ERC-4337 operation was considered and declined. The only
threat it addresses is a chain whose EntryPoint, at the canonical address, has
been replaced with hostile code — but a chain manipulated to that depth already
controls `EXTCODEHASH` itself and the execution, so the check would verify a
value the attacker supplies. Pinning would cost gas on every 4337 operation,
forever, on an immutable contract, and — because the pinned hash would enter the
signed code hash and the CREATE2 address — force a redeploy that invalidates
every unspent blob. The account already refuses any caller other than the
immutable EntryPoint it was deployed against; the marginal defense does not
justify a permanent cost against a threat model in which, at that depth, nothing
holds. Accepted.

## Formerly out of scope, shipped in Phase 2

The receiver hooks (ERC-721/ERC-1155), ERC-165 and ERC-1271 were v1's two
"scope, not oversight" exclusions. Both shipped in the upgradeable
implementation — see
`docs/specs/2026-07-29-glaux-phase2-account-surface-design.md`. The receiver
hooks deliberately do not take the reentrancy guard: the common case is the
account moving a token in a batch and the token calling back in while
`_execute` holds it.

## Resolved: EIP-191 version 0x00, not EIP-712 typed data

> **The section below is the argument that produced the decision, and describes
> the design as it stood BEFORE it.** The resolution is at the end: the birth,
> update and execution digests are wrapped as `0x19 ‖ 0x00 ‖ validator ‖
> structHash` and have been since v0.6. Read the past tense as past tense.

Before the wrap, all three digests were raw `keccak256(abi.encode(...))` values, each prefixed
with a distinct domain constant (`GLAUX_INIT_V1`, `GLAUX_UPDATE_V1`,
`GLAUX_EXEC_V1`), and the update and execution digests additionally bind the
account address. That provides domain separation *between Glaux operations and
between Glaux and other protocols*, which is the security property usually meant
by the phrase.

What it does not provide is **legibility**. A signer sees an opaque 32-byte
hash, not a rendered description of what they are authorizing. For a project
whose stated ambition is an ERC draft and third-party adoption, that is a real
weakness.

**And there was a security half, which was the stronger argument.** The domain
constants separate Glaux from other *structured* signing schemes; they did not
separate it from **raw-hash signing**. Any factor key that was also an ordinary
EOA key, and that could be induced to sign a bare 32-byte digest through
`eth_sign` or an equivalent, produced a valid Glaux signature. The sharpest form
of that argument was the migration path — where the account's own key would have
been a long-lived user key, so a single raw-hash signature obtained before birth
would have installed an attacker's implementation and slot set. Rootless birth
has since removed that path, but the argument holds without it: every factor key
is long-lived by definition, and a raw-hash signature from two of them is a
quorum. That is what the wrap adopted below
closes. It does not, and cannot, protect a key exposed to a genuinely raw
`sign-this-hash` primitive that applies no prefix at all, which is why the rule
in client guidance against ever exposing a factor key to such an API still
stands.

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
hole for the *prefixing* APIs — `personal_sign` and `eth_sign` wrap what they
are given under a different prefix, so what they produce can no longer be a
Glaux digest — and it binds the validating contract into every signature, while
carrying **no `chainId` field**, so blobs keep replaying on every chain. It does
not close, and cannot close, a signer that will put its key on an arbitrary
32-byte value with no prefix at all: hardware signers and low-level libraries
expose exactly that, and against it the client-guidance rule remains the only
protection. It buys no legibility, being untyped; adopting full EIP-712 on top
remains open for a future version and would be a spec change, not a security
fix. The decision was taken before any public deployment — at that time nothing
had been deployed beyond local test chains — so the Sepolia and Base Sepolia
deployments recorded in `docs/deployments.md` have carried the v0x00 wrap from
the start.

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
