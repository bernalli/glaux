# Glaux — Client Reference Guidance

This is guidance for anyone integrating Glaux into a wallet, on any
platform. The contract (`src/GlauxDelegate.sol`, `src/GlauxAccount.sol`,
`src/GlauxStorage.sol`, `src/lib/SignatureVerify.sol`) verifies signatures
and enforces a fixed 2-of-3 threshold; it knows nothing about platforms,
clouds, or key storage. Everything below is client responsibility, not
protocol behavior — where a claim depends on the contract, the function
that enforces it is named so it can be checked directly.

Read the threat model alongside this document. Several rules below are the
*only* mitigation for a residual the contract cannot close, and they are
marked as such.

## F1 — the device factor

F1 is a P-256 key (`GlauxStorage.VERIFIER_P256`, `FactorSlot.data` encoding
`abi.encode(uint256 qx, uint256 qy)`), and it should be hardware-backed on
whatever device the user owns:

- Apple platforms: Secure Enclave, key non-extractable.
- Android: StrongBox if the device has it, otherwise TEE-backed keystore.
- Windows: TPM via Windows Hello.

**Hardware backing alone is not the guarantee.** A hardware-backed key can
be created with an access policy that never asks the user for anything, in
which case any code running on an unlocked — or in some configurations even
a locked — device can sign with it. The threat model's promise that a thief
holding a locked device gets nothing from F1 depends entirely on the client
setting an access-control policy that gates *every single signature* on
user presence and device unlock:

- Apple: an access control with `.userPresence` or
  `.biometryCurrentSet` combined with `kSecAttrAccessibleWhenUnlocked...`,
  never a policy that permits background use.
- Android: `setUserAuthenticationRequired(true)`, with a per-use
  authentication validity rather than a long time-bound window, and
  `setInvalidatedByBiometricEnrollment(true)` so enrolling a new biometric
  invalidates the key.
- Windows: a Hello-gated key, not a bare TPM key usable without prompting.

Document the fallback behaviour on each platform when biometrics are
unavailable (passcode fallback, enrollment changes, device without secure
hardware) and refuse to install F1 at all rather than silently degrading to
a key that signs without user verification.

**Prove the P-256 precompile exists before you rely on it.** P-256 is the
primary verifier for one concrete reason — it is the only signature
algorithm present in secure hardware across every consumer platform *and*
the only one with an EVM precompile the contract can call. But
`SignatureVerify._verifyP256` hard-codes address `0x100`
(RIP-7212 / EIP-7951), and on a chain where that precompile is absent the
staticcall returns empty and verification returns `false` — the repository
proves exactly this in
`test/SignatureVerify.t.sol::test_p256_noPrecompile_false`. Signing with such
a factor is impossible there.

The contract refuses to install one rather than let you find out later:
`_validateSlot` probes the verifier before every P-256 slot installation, at
birth and at rotation, and reverts `P256VerifierUnavailable()`. Do not read
that as permission to stop checking. The probe answers for the chain the
transaction is running on, and only at that moment; your account's
configuration has to work on every chain you intend to reach, including the
ones you have not touched yet. Maintain a **supported-chain matrix** and probe
`0x100` yourself — before birth, and again before adding any chain — with a
known valid vector *and* with a signature that must be rejected, checking that
the first returns one word equal to 1 and the second does not. A verifier that
answers "valid" to everything is worse than an absent one, and only the second
half of that check finds it. Treat a chain that fails either half as one where
F1 does not exist.

**Never configure two P-256 slots unless every target chain has the
precompile.** With two, every possible pair of slots contains one, so on a chain
without it the account would be not degraded but *inert*: nothing can execute,
and `applyUpdate` cannot rotate out of it either, because rotating is itself an
operation that needs a quorum. The installation probe means such an account
cannot be born there at all — the failure is a clean revert instead of a
stranded account — but that is a backstop against the accident, not a licence to
plan the configuration. A chain where your account cannot exist is still a chain
your account cannot reach, and the probe cannot speak for a chain the
transaction has not run on.

Glaux is deliberately platform-neutral: nothing in the contract or in this
guidance ties F1 to Apple, Google, or any single vendor, and integrators
should preserve that neutrality rather than hard-coding one platform's
key-storage API as the only supported path.

## F2 — the paper factor

F2 is a secp256k1 key (`GlauxStorage.VERIFIER_SECP256K1`, `FactorSlot.data`
encoding `abi.encode(address)`) generated and handled as a cold, offline
factor:

- Generate it on a machine that is offline for the duration of generation,
  ideally one that is never connected to a network again (or is wiped
  immediately after).
- Print it. Do not store it in any form that touches a synced or networked
  device — no photograph, no cloud note, no password manager entry, no
  screenshot, ever, at any point in its lifecycle.
- Treat the printed copy as a bearer secret: physical possession is
  equivalent to signing capability, so store it as securely as the user
  would store a will or a physical safe-deposit key.
- F2 exists for recovery and for the rarer privileged operations, not for
  daily use — it should be signed with deliberately, never automated,
  never left connected to any signing service.

## F3 — the cloud co-signer

F3 is a secp256k1 or P-256 key held in software and synced through the
user's cloud provider of choice. The contract does not distinguish where a
factor's key material lives; conformance is a client responsibility against
three requirements: end-to-end encryption (the provider must not be able to
read the key material, only store and sync ciphertext the client controls),
authenticated access (the user's own authentication gates decryption, not
just account possession), and revocability (the user can invalidate that
copy of the key and rotate it out through `applyUpdate`'s
`ACTION_SET_SLOT`, without needing any other factor's cooperation from
the provider itself). iCloud Keychain, Google's equivalent secure sync,
and any generic E2E-encrypted storage backend all qualify against these
requirements — none of them is required and none is disqualified by name.

**Never Apple-only.** This is a hard project constraint, not a
preference: an integration that only offers an iCloud-backed F3 with no
alternative locks non-Apple users out of the third factor entirely and
contradicts the platform-neutrality this project commits to. Every client
must offer at least one non-Apple-only path to F3, even if iCloud remains
one of the supported backends.

## Prove possession of every factor before installing it

**The contract now enforces this.** It was client discipline in an earlier
draft; review showed it is the integrity control the whole threshold rests on,
so it moved on chain. You still have to *produce* the proofs — this section
tells you how and why.

`GlauxAccount._validateSlot` checks a candidate key's *shape*, never possession:
`SignatureVerify.isValidKey` confirms a secp256k1 slot holds a clean non-zero
address and that a P-256 slot holds a point actually on the curve, and nothing
more.

The mild consequence is availability. A key that is well-formed but whose
private half was never generated, was lost, or was mistyped installs
successfully: **one** such slot degrades 2-of-3 to 2-of-2 with no margin left,
invisibly; **two** are unrecoverable on every chain born from that
configuration.

The serious consequence is that **an address nobody ever held a key for can
still be a working credential — for an attacker.** ECDSA verifies by recovery,
so a signature can be produced *before* the key it verifies under is chosen: run
the recovery over arbitrary signature values for a digest you know in advance,
and you get an address for which that signature is valid. Anyone who supplies or
nominates two of the three slot addresses can therefore pre-arm one specific
operation — a specific chain, nonce and payload, all knowable before birth — and
meet the threshold alone. On chain, all three slots look distinct and
well-formed.

So, before birth and before every rotation:

> Every slot, at birth and on every rotation, must carry a signature by its own
> key over
> `keccak256(abi.encode(REG_DOMAIN, slotIndex, verifierType, keccak256(keyData)))`.
> `scripts/prove_possession.py` computes it. Committing the key material into
> the challenge is what stops pre-arming: an attacker would have to satisfy the
> digest and the key it commits to at once, which is a hash-preimage search
> rather than a curve computation.

The challenge binds neither chain nor account, and that is deliberate: a factor
must be able to sign it **before the account exists**, so an air-gapped paper
factor signs once, at generation time, and never comes back online. The proof is
public data and valid on every chain. It authorizes nothing, so its portability
costs nothing.

For a hardware-backed device key the private half is not exportable: use
`--digest-only` to obtain the 32-byte challenge, have the platform's signing API
sign it, and encode the resulting `(r, s)` as two padded 32-byte words.

**A P-256 factor can only be installed on a chain that has a working P256VERIFY
precompile**, because the proof is verified with it and because installation
probes the verifier first. Birth fails cleanly on a chain without it —
`P256VerifierUnavailable()` — rather than installing an unusable factor, and the
blob stays valid and retryable there if the precompile arrives later.

**Never install the probe vector's own public key as a factor.** The constants
`SignatureVerify.PROBE_QX` / `PROBE_QY` exist so the contract can ask the chain
a question whose answer it already knows; the matching private key is published
with them and belongs to everyone. A possession proof does not protect you here
— anyone can produce one for that key — so the contract refuses it outright with
`ProbeKeyNotInstallable()`. Never seed a slot, not even a test slot, from those
constants.

Treat any slot address proposed by a counterparty — a vendor-supplied recovery
factor, a co-signing service — as unverified until it has answered a challenge
you generated.

## Never expose a factor key to a raw-hash signing API

Glaux digests are EIP-191 version `0x00` payloads, not EIP-712 typed data —
a decision the threat model records as *resolved*, not open. The `0x19 0x00`
prefix and the router as validator keep a Glaux digest out of reach of the
prefixing APIs (`personal_sign` / `eth_sign` and their equivalents), which
wrap what they are given under a different prefix and therefore cannot be
tricked into producing a Glaux signature.

What the wrap does **not** cover is a signer that will put its key on an
arbitrary 32-byte value with no prefix at all — a raw `sign-this-hash`
primitive, which hardware signers and low-level libraries do expose. Against
that, domain constants separate Glaux operations from other structured
schemes, but nothing separates them from anything else.

Therefore: a Glaux factor key is used for Glaux and nothing else. Never reuse an
existing wallet key as a factor and never wire a factor key into a generic
signing API — a raw-hash signature from any two factors is a quorum, which is
every operation the account exposes.

## Birth

Birth follows the sequence in `GlauxDelegate.initialize` and the
`GLAUX_INIT_V1` domain it checks:

**Before anything else — two preconditions that no on-chain check can enforce.**
Under rootless birth the first of them is close to self-enforcing, because the
address is derived rather than chosen and nobody can delegate it in advance
(threat-model residual 17). Both checks stay in the client anyway: they are cheap,
and they are the difference between a design argument and an observation.

- **The account must be a fresh address that has never carried a delegation
  designator — or, exactly once, be retrying a birth whose `initialize()`
  call reverted.** An EIP-7702 re-delegation does not clear storage, and
  Glaux's slot constants are public, so an EOA previously delegated to
  hostile code may arrive with Glaux's own namespaced slots pre-planted —
  either bricking birth or, worse, presenting as an attacker-owned Glaux
  account the moment you delegate to the router (threat-model residual 17).
  Before submitting a birth blob on a chain, verify with raw reads that the
  account's code is either empty, or exactly the EIP-7702 designator this
  same blob would install (`0xef0100 ‖ router`, 23 bytes) — never any other
  non-empty code — and that **every** Glaux namespaced word is zero: both
  `keccak256("glaux.account.v1.implementation")` and, at the header word
  `keccak256("glaux.account.v1.storage")` (call it `BASE`), all seven words
  `BASE`..`BASE+6` — the header plus the `verifierType` and `bytes data` head
  of each of the three `FactorSlot` entries. Checking only the first two of
  these eight words lets a hostile delegate plant a forged `bytes data`
  length in one of the six slot words and pass undetected. **Never migrate an
  EOA whose code is non-empty and is not this blob's own designator.**
  `scripts/submit_birth.py` performs this check before broadcasting.
- **The authorization tuple names the ROUTER.** The address you sign into it is
  `GlauxDelegate`, never the implementation. Delegating straight to the
  implementation used to hand the account to anyone; the H-1 fix now makes that
  configuration fail-closed (`initializeAccount` reverts `NotDuringBirth`), but a
  bricked account is still a lost one — get the address right. For every retained
  or imported blob, recover the authorization tuple's signer and require it to
  equal `blob.account` *before* running the freshness preflight against that
  address; also require `authorization.chainId == 0`. The SDK and Python submitter
  enforce both checks. Without the signer binding, the preflight can inspect one
  EOA while the transaction delegates another; without zero chain id, the blob is
  silently unusable on every other chain.

**No key is generated, at any point.** The account does not sign its own birth;
the authorization tuple is *crafted* so that it recovers to an address for which
no private key exists, and the router re-derives the same facts on chain. The
account address is an output of this derivation, not something chosen.

1. Build `initData` — the three `FactorSlot` entries, F2 at index 0, F1 at
   index 1, F3 at index 2, each carrying its possession proof. This is the
   moment the three factor keys are committed to the account.
2. Compute the birth digest: the EIP-191 version `0x00` wrap of the struct
   hash, with the **router** as validator.

   ```
   structHash = keccak256(abi.encode(GlauxStorage.INIT_DOMAIN, implementation,
                                     expectedCodeHash, keccak256(initData)))
   digest     = keccak256(abi.encodePacked(hex"1900", ROUTER, structHash))
   ```

   Omitting the wrap produces a digest the router rejects: it computes
   `GlauxStorage.eip191(SELF, structHash)` and compares against that.
3. Craft the authorization tuple for `[chainId = 0, address = ROUTER,
   nonce = 0]`, whose preimage hashes to `AUTH_MSG_HASH =
   keccak256(0x05 ‖ rlp([0, ROUTER, 0]))`. For `i = 0, 1, 2, …`:

   ```
   salt = keccak256(abi.encode(digest, uint256(i)))
   r    = keccak256(abi.encode(digest, salt))
   s    = ROOTLESS_S_PREFIX ‖ top19bytes(keccak256(abi.encode(digest, salt, uint8(1))))
   ```

   with `ROOTLESS_S_PREFIX = 0x476c6175785f524f4f544c4553` occupying the top 13
   bytes (its leading `0x47` is what keeps `s` below `secp256k1n/2`, which
   EIP-7702 requires of the tuple) and the tail hash shifted right by 104 bits,
   so tag and tail cannot overlap.

   and take the first `salt` whose `r` is a valid curve x-coordinate — about
   half of them are, so this terminates in a couple of attempts. The account is
   `ecrecover(AUTH_MSG_HASH, 27, r, s)`. Recovery id 27 is not a choice: when
   `r` is on the curve it always recovers, and when it is not, neither parity
   does. `chainId = 0` is what makes the tuple valid on every chain, present or
   future.
4. Verify what you crafted before you transmit it, against the same three
   checks `GlauxDelegate.initialize` performs: `s` carries the 13-byte prefix,
   `r` recomputes from `(digest, salt)`, and the recovery equals `blob.account`.
   A blob failing any of them is a wasted broadcast at best; the SDK and the
   Python submitter both refuse it locally rather than spend gas on it.

There is no key to destroy at the end, and no window during which one exists.

**The birth blob binds the implementation's code, not just its address.**
`expectedCodeHash` is checked against `implementation.codehash`, and the
implementation must additionally answer a `glauxCompatibilityId()`
staticcall with `keccak256("GLAUX_ACCOUNT_V1")`, both before the router
delegatecalls anything. Compute `expectedCodeHash` from a deployment you
have verified, and understand what the binding buys: because the blob
carries no chain id and is public, anyone can replay it anywhere, and the
same address does not hold the same bytecode on every chain. Without the
binding, a replay on a chain where that address holds different code would
initialize the account against foreign logic running in its own storage.
One blob now installs byte-identical logic everywhere, or fails cleanly.

**Deploy before you submit.** `initialize` reverts with
`InvalidImplementation()` when the implementation has no code on the target
chain, when its code hash differs from the signed one, or when the marker
is missing. This fails safely — under EIP-7702 the authorization is applied
before the transaction executes and is not undone by a revert, so the
delegation designator is written and stays on the account, but no Glaux
namespaced state is: `initialize` reverts before touching storage, so the
same blob stays valid and resubmittable on that chain once the correct
implementation is deployed there. That is the ordinary case, not an error: a
birth blob is expected to outrun deployment on chains the account has not
reached yet. `scripts/submit_birth.py`'s preflight accounts for exactly this:
a retry against an account already carrying this blob's own router
designator is accepted, not mistaken for a poisoned account.
Still, verify the implementation is deployed *and* that its live code hash
equals the one in the blob before broadcasting, rather than discovering it
at submission time.

### ⚠️ Never introduce a key for the account

The account's security rests on there being no key at all. Do not "improve" the
flow by generating an EOA and signing the authorization tuple with it, and do
not accept a blob whose tuple was signed rather than crafted — the router
accepts only a crafted one, but a client that builds one is building an account
whose EOA key is a permanent master key, bypassing the 2-of-3 entirely and able
to re-delegate the account for good. That was the design until 2026-08-05 and
the reason it changed (threat-model residual 1).

The check that keeps this honest is the same one the router performs, and any
client can run it on any blob, at any time: recompute `r` from the digest and
the salt, confirm `s` carries the 13-byte tag, and confirm the tuple recovers to
the account address. A tuple that satisfies all three cannot have come from a
signer — producing one with a key means either inverting the discrete log or a
2^103 search for chosen bytes of `s`.

### Craft exactly one birth blob per account

A birth blob **never expires and cannot be revoked**: there is no deadline in
the digest and no mechanism in the immutable router to invalidate one. Under
rootless birth that durability is no longer a takeover risk — the address is
recovered from `r`, which commits to the whole configuration, so a differently
configured blob is a different account rather than a second key to the same one.

The hazard is now a bookkeeping one, and whether it is recoverable depends on
your signers. The address covers `initData`, which carries the three possession
proofs, so whether a second craft reproduces the first address is exactly the
question of whether your signers reproduce their proofs:

- **A deterministic signer (RFC 6979)** — which is what this repository's
  reference `LocalP256Signer` and `LocalSecp256k1Signer` are — re-signs the same
  digest to the same bytes, so crafting again from the same three factors lands
  on the **same** address, and a lost blob can be rebuilt by repeating the craft.
- **A random-nonce signer** — every hardware P-256 factor, the Secure Enclave
  included, and this repository's Python `prove_possession.py`, which signs
  through OpenSSL — produces different bytes each time, hence a different
  `initData`, a different digest and a **different** address. A blob discarded
  as "the failed attempt" then names an address that can never be born, and
  anything sent to it is **gone**: there is no key, and no way back to the proof.

Since the production configuration is the second one, treat it as the rule:
craft once, keep the blob that names the address you publish, and treat any later
craft as a new account rather than a repair of the first.

### Retain the public artifacts durably — forever

Every one of them is public data with no secrecy requirement. What is hard to
reconstruct is `initData`: with a hardware signer, re-signing a possession proof
produces different bytes, hence a different digest and a different account. The
tuple and salt are recomputable *from* the rest of the blob, and worth storing
anyway so that verification needs no derivation code.

One qualification, so retention is not treated as more fragile than it is: once
the account has been born on **any** chain, that birth transaction carries the
whole blob in public — `initialize`'s calldata holds `implementation`,
`expectedCodeHash`, `initData` and `salt`, and the transaction's authorization
list holds the tuple. A client that has lost its local copy can rebuild it from
that transaction. The retention rule is therefore absolute only *before* the
first birth; after it, the chain is the backup, provided that chain's history
stays reachable to you.

- **the EIP-7702 authorization tuple**, without which the account can never
  be delegated on a chain it has not yet reached;
- **the initialization blob** (`implementation`, `expectedCodeHash`,
  `initData`, `salt`), without which it can never be initialized there;
- **every quorum-signed update, in order, from nonce 1 onward.**
  `applyUpdate` accepts exactly `updateNonce + 1` and nothing else, so a
  lagging chain can only be caught up by replaying the whole sequence. Lose
  update 4 and no chain still at nonce 3 can ever advance — even with all
  three current factors in hand, because the signatures on update 4 came
  from factors that may since have been rotated away.

Back these up with the same care as the account's address itself. A client
that treats them as ephemeral transaction data has quietly made future
chains unreachable.

## Never write the same key into two slots

`GlauxAccount.initializeAccount` and `applyUpdate`'s `ACTION_SET_SLOT`
branch both check every candidate slot against the other two via
`_isDuplicateSlot` and revert with `DuplicateSlot()` on a match. Two slots
count as duplicates when they match as a **`(verifierType, data)` pair** —
the same key material under a different verifier type is not a duplicate,
and neither is different key material under the same type.

This is enforced by the contract, not merely recommended, but a client
should never construct a configuration that attempts it — presenting the
user with a transaction guaranteed to revert wastes a round trip and
signing effort. Validate distinctness client-side first. The reason the
check exists is that duplicate credentials silently collapse 2-of-3 into
1-of-1: one key signs once, and the identical signature is submitted under
two different slot indices.

## Never sign two updates for one nonce

`applyUpdate` cannot detect that two different payloads were signed for the
same `u.nonce`: its only check is `u.nonce != l.updateNonce + 1`, evaluated
independently against each chain's own storage. The contract has no way to
prevent this; the discipline is entirely signer-side.

Treat an update as consumed the instant the quorum signs it, before it is
observed anywhere, and never present a second, different proposal at a
nonce already signed. If client state ever shows two signed-but-unconfirmed
updates at one nonce, that is a bug in the client's bookkeeping, not a
contract edge case to route around.

**The most tempting way to violate this rule is an upgrade.** See below.

## Upgrades

`applyUpdate`'s `ACTION_SET_IMPLEMENTATION` branch decodes
`abi.decode(u.payload, (address, bytes32))` as `(newImplementation,
expectedCodeHash)` and requires non-empty code, an exact
`newImplementation.codehash == expectedCodeHash` match, and a successful
`glauxCompatibilityId()` staticcall returning `keccak256("GLAUX_ACCOUNT_V1")`
before installing it.

**One signed payload names exactly one address and one hash.** So the rule
is not "compute the code hash per chain" — it is:

> Verify that every target chain has the *same* candidate address holding
> the *same* code hash, then sign one common update. If they differ
> anywhere, **abort**. Signing per-chain updates at the same nonce to
> paper over the difference is precisely the equivocation forbidden above,
> and it permanently diverges the account.

Then, before proposing it to signers:

- Read the candidate's code hash **live from each target chain**, never
  from a local build artifact assumed to match.
- Confirm the candidate answers `glauxCompatibilityId()` correctly on
  chain, so a failing `applyUpdate` is never how anyone learns it is
  incompatible.
- Review what the on-chain checks cannot see, because they are only two:
  **storage-layout compatibility** with the namespaced layout at
  `keccak256("glaux.account.v1.storage")` (a layout change silently
  corrupts live accounts); **preservation of `applyUpdate` itself**, since
  installing logic that cannot upgrade is terminal — the birth path can
  never re-run once the implementation pointer is non-zero; the **immutable
  `ENTRYPOINT`** baked into the candidate's constructor; and any
  **external dependency** whose address or behaviour differs per chain.
- Test against the exact deployed bytecode from current production state,
  not a local re-compilation.
- **Stage the rollout**: relay the update on one low-value chain first and
  verify the account still functions before propagating it everywhere. The
  update is replayable at leisure; there is no reason to land it
  simultaneously.

The code-hash check guarantees the same *bytecode* everywhere. It does not
guarantee the same *behaviour* — see the threat model.

## Update-replay reconciliation UX

Because the update channel carries no chain-id and replays "in order" on
each chain at first touch, a client must query every chain it cares about
independently and present the result honestly.

**Read raw storage first. The order below is normative.** The getters —
`getSlot`, `updateNonce`, `execNonce`, `implementation()` — are answered by
the implementation whose identity is the thing reconciliation verifies: an
implementation that is hostile, or merely an unexpected build, can report a
nonce and a slot set that do not exist in storage. Per chain:

1. `eth_getCode(account)` — expect exactly the EIP-7702 designator,
   `0xef0100 ‖ router` (23 bytes). Anything else, including empty code, means
   the account is not a Glaux account on this chain and nothing below is
   meaningful.
2. `eth_getStorageAt(account, keccak256("glaux.account.v1.implementation"))` —
   the authoritative implementation pointer.
3. `eth_getCode(pointer)` → `keccak256` — the live code hash of the logic
   actually installed.
4. The raw namespaced state: the packed header word at
   `keccak256("glaux.account.v1.storage")` (`initialized` byte 0,
   `updateNonce` bytes 1-8, `execNonce` bytes 9-16), then the three factor
   slots.
5. **Only now** the getters — and only to compare against steps 2-4. A
   mismatch is a finding about the implementation, reported as such; it is
   never resolved in favour of the getter.

`scripts/reconcile.py` implements exactly this order (exit codes: 0
consistent, 1 chains diverge, 2 raw-vs-getter mismatch — 2 outranks 1), and
its storage arithmetic is pinned against the compiler by
`test/StorageParity.t.sol` and `scripts/test_reconcile.py` over a shared
committed fixture.

Across chains, compare **all four** of:

1. `updateNonce`;
2. the three `FactorSlot` entries via `getSlot`;
3. **the implementation pointer and its live code hash** — read the raw
   namespaced slot `keccak256("glaux.account.v1.implementation")` with
   `eth_getStorageAt`, NOT the ERC-1967 slot, which Glaux never writes and which
   on a migrated account may still hold a stale foreign value;
4. **the delegation target** (the account's code should be the EIP-7702
   indicator `0xef0100` followed by the router address).

Points 3 and 4 are not optional garnish. `SetImplementation` changes only
the implementation pointer while advancing the nonce like any other update,
so two chains can show an identical nonce and identical factors while
running entirely different logic. Comparing nonce and slots alone hides
exactly the divergence that matters most.

- A chain with a lower `updateNonce` is *usually* just behind — show it as
  "behind, pending relay" and offer to submit the outstanding updates. But
  confirm it is genuinely a prefix of the same history: if the chain ahead
  applied a *different* update at that nonce, this is equivocation, not lag,
  and replaying will fail or diverge further.
- A chain never touched at all has no Glaux state whatsoever: the address
  there is a plain, undelegated EOA. Represent this plainly — "not yet
  active on this chain" — rather than omitting the chain or implying the
  configuration is already live everywhere.
- Same nonce with different slots, different implementation pointers, or
  different code at the same pointer is the equivocation residual
  materializing. Surface it as a conflict, not a display bug.
- Never present one chain's configuration as a global synchronized truth.
  The protocol provides no global view; only the client's UI can, and only
  by querying every chain it claims to represent.

**Reconciling divergence is not a formality.** The contract accepts exactly
`updateNonce + 1`, so there is no "jump to a higher nonce and converge"
move: each branch must be advanced step by step. If the branches rotated
*different* slots, a single signature pair may not be valid on both — the
payloads must be identical but the signatures may have to be produced
per-branch by whichever quorum each branch still recognizes. If one branch
installed logic that broke `applyUpdate`, that branch cannot be recovered
at all. Plan for reconciliation to be a supervised operation, and prefer
never needing it.

## Execution nonce reads are not an RPC trust root

Both direct execution and ERC-4337 sign a sequential nonce obtained from chain
state. Treating one RPC response as authentic lets a hostile endpoint return the
next nonce, collect a signature that is invalid today, and replay it after one
legitimate execution advances the chain into that nonce. Direct submission
exposes the signed batch to the endpoint during simulation; a bundler or 4337
submission endpoint sees the signed UserOperation as part of its ordinary job.

The SDK applies three layers:

1. It pins the nonce getter and a raw-storage read to the same block and requires
   agreement: the Glaux header word for direct execution, and EntryPoint v0.7's
   `nonceSequenceNumber[account][0]` word for ERC-4337.
2. `signExecution`, `buildUserOp`, and `signUserOp` refuse by default when
   `validUntil` is more than one hour ahead of the client's local clock. A longer
   operation requires an explicit `maxValidityWindowSeconds` override at every
   signing/build boundary that enforces the policy.
3. Integrators that have a nonce from an independent trusted view can pass
   `expectedNonce`; disagreement fails before factor signatures are requested.

Layer 1 is only a consistency check. A fully hostile endpoint can forge the
getter and raw word consistently. Layer 2 bounds the exposure but leaves the
operation replayable inside the accepted hour (or the integrator's explicit
override). To authenticate the nonce, obtain `expectedNonce` from a genuinely
independent trust path — for example a local node or a separately administered
provider — and do not mistake two URLs operated by the same backend for
independence. Local nonce bookkeeping is usable only if it accounts for failed
transactions and reorgs. If no independent view exists, keep the default ceiling
and present the residual plainly; never raise it merely to avoid refreshing an
expired request.

The same independence rule applies one step earlier, at **birth**. `submitBirth`
broadcasts, takes its receipt, and reads the account's code and storage back
through the client it was handed, so its postconditions confirm what that one
endpoint says — not what the chain holds. Before funding a newly born address, or
showing it to a user as live, confirm it against a second independently operated
endpoint: the account's designator, its implementation pointer, and its three
factor slots. `reconcile` is the tool for this; point it at two providers rather
than two URLs of the same backend.

## Signing a message is authorizing an action

With ERC-1271 live, the account can sign for protocols that move funds on a
signature alone — a Permit2 witness IS a transfer authorization, a Seaport
order IS a listing. None of that advances `execNonce` or leaves any on-chain
trace before a third party consumes the signature (threat model, residual 16).
So a client must present a message-signing request exactly as it would present
a transaction: show what the hash commits to, from which protocol, with which
deadline — and never as a harmless "sign this to continue". The deadline is
the signers' only bound on the exposure: for an order meant to stay open for
months, set `validUntil` months out, knowingly; for everything else keep it
short.

## Wire formats

These trip integrations more than anything else in this document.

- **secp256k1 signature**: exactly **65 bytes**, `r || s || v`, with `v` in
  `{27, 28}` and `s` in the lower half of the curve order. High-`s`
  signatures are rejected (`SignatureVerify._verifySecp256k1`), so
  normalize before submitting: if `s > n/2`, replace `s` with `n - s` and
  flip `v`.
- **secp256k1 slot data**: `abi.encode(address)` — exactly 32 bytes, the
  address right-aligned with a clean zero prefix. Dirty upper bits are
  rejected.
- **P-256 signature**: exactly **64 bytes**, `abi.encode(uint256 r,
  uint256 s)` — two zero-padded 32-byte words. Not DER, not 65 bytes, no
  recovery byte.
- **P-256 slot data**: exactly **64 bytes**, `abi.encode(uint256 qx,
  uint256 qy)` — the raw affine coordinates, not a SEC1 `04||X||Y` prefixed
  encoding and not a compressed point.
- **Execution deadline**: a `uint48` unix timestamp, passed as the second
  argument of `executeWithSigs(calls, validUntil, sigs)` *and* bound into the
  digest the factors sign. Signing one value and submitting another fails as a
  bad signature, which is the point. `0` is always an expired operation, never an
  unbounded one — for a long-lived operation pass an explicit far-future
  timestamp so the signers can see what they are agreeing to.
- **ERC-4337 signature blob**: `abi.encode(uint48 validUntil, SlotSig[2] sigs)`,
  bounded at 576 bytes. Note the deadline comes *first*, ahead of the array.
- **ERC-1271 signature blob**: the same shape and the same 576-byte bound,
  `abi.encode(uint48 validUntil, SlotSig[2] sigs)`. The factors do NOT sign the
  hash the consumer presents; they sign
  `eip191(account, keccak256(abi.encode(MSG_DOMAIN, block.chainid, account,
  hash, validUntil)))` with
  `MSG_DOMAIN = keccak256("GLAUX_MSG_V1")`. This is the only Glaux digest that
  binds the chain id — the account and Permit2 hold the same address on every
  chain, so an unbound message signature would authorize the identical action
  everywhere at once. `validUntil == 0` is rejected; an expired, malformed or
  under-quorum blob answers with the `0xffffffff` sentinel rather than a
  revert. On an account not yet born the ROUTER reverts `NotInitialized`
  before implementation code runs — consumers that treat a revert as invalid
  handle this correctly.

Hardware and WebAuthn APIs typically return **DER-encoded** ECDSA
signatures and SEC1 or COSE-encoded public keys. Converting them is the
client's job, and it must be explicit: parse the DER `SEQUENCE { INTEGER r,
INTEGER s }`, strip any sign-padding byte, left-pad each value to 32 bytes,
and drop the `04` prefix from an uncompressed public key before encoding
the coordinates.

Malformed input is rejected by returning `false`, never by reverting, so a
badly encoded signature is indistinguishable from a wrong one at the
contract level. Verify locally before submitting.

## Gas

The account never needs a native balance for someone else to relay a signed
operation — `executeWithSigs` and `applyUpdate` are callable by anyone
holding a validly-signed payload, and the caller pays the gas, not the
account. Authorization is separated from submission, which is what makes a
single funded relayer a cross-chain gas account.

Under an ERC-4337 paymaster an account can execute a user operation while
holding zero native currency.
`test/EntryPoint4337.t.sol::test_userOp_sponsoredExecutionWithZeroBalanceAccount`
proves it: it records every state transition of the `handleOps` call and
asserts the account's balance, the value sent to it, and its EntryPoint
deposit are zero at *every* step — not merely before and after — while
asserting the paymaster's own deposit was debited by exactly the
`actualGasCost` reported in the `UserOperationEvent`. Signatures authorize;
the relayer or paymaster pays.

The 4337 path carries the same deadline the direct path does, but it travels in
the signature rather than in the operation: `op.signature` is
`abi.encode(uint48 validUntil, SlotSig[2] sigs)`, and the factors sign
`eip191(account, keccak256(abi.encode(USEROP_DOMAIN, userOpHash, validUntil)))`
rather than the bare `userOpHash`. Sign the deadline you actually mean — the
account returns it to the EntryPoint as `validationData`, and the EntryPoint
refuses the operation with `AA22 expired or not due` once it passes. A blob whose
`validUntil` was edited after signing fails validation with `AA24 signature
error`, so the window cannot be widened in flight. `validUntil == 0` is refused
outright: the EntryPoint would read it as "no expiry".

A P-256 factor is compatible with the 4337 path: **ERC-7562 rule OP-062**
explicitly permits the `P256VERIFY` precompile of EIP-7951 during validation,
alongside the core precompiles. That holds only on networks that actually have
the precompile, and an individual bundler may still lag the specification, so
test against the bundlers you intend to use. The direct `executeWithSigs` path
needs no bundler at all and is unaffected either way.

### Decide what the operation may cost before the quorum signs it

`signUserOp` requires `maxCostWei`, the largest prefund the operation can
authorize: `(verificationGasLimit + callGasLimit + preVerificationGas + the
paymaster's two gas limits) * maxFeePerGas`, which is what the signature authorizes the
EntryPoint to collect — not what the operation is expected to use. With no
paymaster that prefund comes from the account; with one, from the paymaster's
deposit. Cap it either way: sponsorship can be withdrawn between signing and
inclusion, and a well-formed paymaster field naming the zero address puts the
whole amount back on the account.
Choose it per operation from what the action is worth. There is no default and
there will not be one: a default would be a number nobody chose, standing in
for the only decision that bounds this exposure.

`maxFeePerGas` is separately measured against a fee baseline. Supply
`feeBaseline`, read from a **second, independently operated endpoint**, whenever
the value at stake justifies it — the same rule birth confirmation follows, for
the same reason: an endpoint that both proposes a fee and vouches for it has
been asked nothing. Omitting it reads the baseline from the same client, which
catches a broken or greedy quote but not a coordinated lie.

Do not defeat the guard to make an operation go through. Raising `maxCostWei`
until the refusal stops is the same as not having a cap; a
`FeeExceedsBaselineError` on a chain whose base fee is negligible next to real
tips calls for a baseline you supply, not a larger multiple applied blindly.

## WebAuthn as a future verifier type

The `(verifierType, data)` shape of `FactorSlot` is designed to accommodate
new signature schemes without moving funds or changing the account's
address: a new `verifierType` value, a new branch in
`SignatureVerify.verify` and `isValidKey`, and an `applyUpdate` rotating
the slot to the new type and key material. The address, the other two
factors, and the held funds are untouched.

**Standard WebAuthn is not usable as F1 today, and this is not a
preference.** A WebAuthn authenticator does not sign an arbitrary digest:
it signs `authenticatorData || SHA-256(clientDataJSON)`, and the contract
digest can only travel inside the challenge field of that envelope. A raw
P-256 verification of the Glaux digest therefore cannot succeed against a
standard WebAuthn assertion. Supporting it means a **new verifier type**
that reconstructs and verifies the envelope on chain — additive, scoped,
and not implemented in Phase 1.

F1 today uses a platform-generated P-256 key that signs the raw digest
directly through a native crypto API. To be precise about what "extracted"
means: the **public key** is exported from the platform keystore, while the
**private key remains non-extractable** inside secure hardware and is used
only through the platform's signing API. Nothing about F1 requires — or
permits — exporting private key material.

## The TypeScript SDK

[`sdk/`](../sdk/README.md) is the executable counterpart of this document:
birth, direct execution, self-funded ERC-4337, ERC-7677 gas sponsorship,
`checkChain` (the eligibility gate the "prove eligibility before you
display an address" rule above depends on), and cross-chain reconciliation.
Its README restates the frozen-funds and signer-compatibility rules above in
integrator-facing form, plus an ERC-4337 bundler limitation (Alto 0.0.20)
discovered while building it. Read it before wiring any of this into a
client.
