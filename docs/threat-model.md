# Glaux — Threat Model

This document analyzes the security properties of the Glaux account as
implemented in `src/GlauxDelegate.sol`, `src/GlauxAccount.sol`,
`src/GlauxStorage.sol`, and `src/lib/SignatureVerify.sol`. It is written for
an auditor or an integrator who needs to know exactly what the contract
protects, against whom, and where that protection deliberately ends. Every
claim below is checkable against the cited function.

## Assets

The account protects five things. **Funds** held at one address, replicated
on every EVM chain by the same EIP-7702 delegation and reachable through
`executeWithSigs` (`GlauxAccount.sol`) or, once relayed through an
ERC-4337 bundler, through `executeFromEntryPoint`. **The three factor keys**
themselves — F2 the paper key at slot 0, F1 the device key at slot 1, F3 the
cloud co-signer at slot 2 — whose compromise, singly or in combination,
determines what an adversary can do. **The birth key**, the ephemeral EOA
private key that signs the one EIP-7702 authorization tuple and the
initialization blob; it exists only until the account is born and its
compromise before destruction is unrecoverable (see residuals below). **The
update nonce and the configuration it defines** — `updateNonce` in
`GlauxStorage.Layout` and the three `FactorSlot` entries it gates — since
whoever can produce two valid signatures over the next nonce controls the
account's future signers, verifier types, and implementation. **The ERC-1967
implementation pointer** at the canonical slot
(`GlauxStorage.ERC1967_IMPL_SLOT`), which is written once by
`GlauxDelegate.initialize` and thereafter only by `applyUpdate` under
`ACTION_SET_IMPLEMENTATION` — it decides which logic contract every
delegatecall from the immutable `GlauxDelegate` fallback executes.

## Adversaries

**A remote attacker with no factors.** Can read all on-chain state, can
submit any calldata to the account, but cannot produce a valid signature
from any of the three slots. `_checkTwoSigs` requires two signatures from two
distinct slot indices (`sigs[0].slotIndex != sigs[1].slotIndex`) each
verified against the stored key material via `SignatureVerify.verify`; there
is no path that accepts fewer than two independently-verified signatures.
Guarantee: total denial of state-changing operations. Non-guarantee: none —
this is the baseline case the whole design exists to hold.

**A compromised cloud provider, holding F3.** Gains one of three signatures.
Alone it can neither execute transactions nor apply updates, because every
state-changing entry point (`applyUpdate`, `executeWithSigs`,
`validateUserOp`'s two-signature check) requires 2-of-3. Guarantee: F3 alone
is worth exactly one factor, never more. Non-guarantee: if the same breach
also yields F1 or F2 (for instance because both are stored on the same
compromised backend), the threshold is met — the contract has no way to
know that "F1" and "F3" are not actually independent in a given deployment;
independence is a client-integration property, not a contract-enforced one.

**A device thief, device locked.** Without unlocking hardware-backed
storage, the thief has physical possession but no signing capability; F1's
key material never leaves the secure element/enclave in a compliant client.
Guarantee: possession without unlock yields nothing. This guarantee is
entirely a client/platform property (see `docs/client-guidance.md`) — the
contract has no visibility into device state.

**A device thief, device unlocked.** Can produce F1 signatures on demand.
Combined with F3 (routinely co-signing on the same device for daily UX per
spec §6) this reaches the 2-of-3 threshold and grants full control:
arbitrary `executeWithSigs` calls, and — critically — `applyUpdate` calls
that can rotate F1 and F3 themselves, replacing the paper key's co-signers
entirely and locking the legitimate owner out unless they still hold F2 and
act first. Non-guarantee: Glaux does not defend against this; it is the
first declared residual below (mirrors spec §7.1).

**Runtime malware on an unlocked device.** Equivalent to the unlocked-device
thief for anything the malware can get the device to sign — it can request
F1 signatures through the OS's biometric/secure-enclave APIs and, if F3 also
signs transparently on the same device, assemble a valid 2-of-3. No
on-chain check distinguishes a user-initiated signature from a
malware-triggered one; this is inherent to any signature-based scheme and is
declared, not mitigated, by the contract.

**A malicious or censoring relayer or bundler.** Can refuse to submit a
signed payload, delay it, or reorder independent payloads relative to each
other, but cannot forge a signature, cannot alter `u.payload` or
`calls` without invalidating the digest the signatures cover
(`keccak256(abi.encode(GlauxStorage.UPDATE_DOMAIN, address(this), u.nonce, u.action, keccak256(u.payload)))`
for updates, the analogous `EXEC_DOMAIN` digest including `block.chainid`
for direct execution), and cannot replay an already-applied update or
execution past its nonce check (`BadUpdateNonce`, and the monotonic
`execNonce`/EntryPoint per-account nonce for execution). Guarantee:
integrity and ordering-past-the-nonce are enforced regardless of relayer
behavior. Non-guarantee: liveness — a censoring relayer can delay
indefinitely; the mitigation is that relaying is permissionless (anyone can
submit a validly-signed payload), so censorship by one relayer is defeated by
switching to another, not by a contract-level guarantee of inclusion.

**A paymaster.** Under ERC-4337, `validateUserOp` decides validity
independently of the paymaster (`msg.sender != ENTRYPOINT` gate plus the
two-signature check); a paymaster can decline to sponsor a userOp or apply
its own acceptance policy, but it cannot alter `calls`, forge signatures, or
bypass the account's own validation — `PackedUserOperation` fields the
paymaster does not control are hashed into `userOpHash`, and the account's
signature check is over that hash. Guarantee: paymaster misbehavior can at
worst deny sponsorship, never authorize an unsigned operation.

**A compromised birth environment.** If the process generating the ephemeral
EOA is compromised before the birth key is destroyed, the attacker holds the
one key capable of producing a valid `InvalidBirthSignature`-passing
signature over `keccak256(abi.encode(GlauxStorage.INIT_DOMAIN, implementation, keccak256(initData)))`,
and can therefore author their own `initData` (their own three factor
slots) and call `GlauxDelegate.initialize` before the legitimate owner does.
This is the second declared residual below: no on-chain check distinguishes
the legitimate initializer from an attacker holding the same key, because
by construction they are indistinguishable — the birth key IS the address's
EIP-7702 authority.

**An attacker who already holds two factors.** Meets the 2-of-3 threshold
for every operation the contract exposes, without qualification: execution,
slot rotation, verifier-type change, and implementation upgrade (subject to
the code-hash and compatibility-marker checks in `ACTION_SET_IMPLEMENTATION`,
which bind bytecode identity and interface conformance, not signer
legitimacy). This is not a partial compromise — it is the definition of
control under the design's 2-of-3 threshold model, stated as the third
declared residual below.

## Guarantees, summarized

Two independent signatures from two of the three factor slots are necessary
and sufficient to change account configuration or move funds; no single
factor, and no non-factor actor (relayer, bundler, paymaster), can do either
alone. Execution digests bind `block.chainid`, so a signed execution
authorized for one chain cannot be replayed on another. Update digests
deliberately carry no chain-id, so one signed configuration change reaches
every chain the account is deployed on without re-signing — this is a
feature, not an oversight, and its consequence is declared explicitly below.
Implementation upgrades require the new contract's runtime code hash to
match a hash chosen by the signers (`newImplementation.codehash ==
expectedCodeHash` in `applyUpdate`) and require the new contract to answer
`glauxCompatibilityId()` with `GlauxStorage.COMPAT_ID`
(`keccak256("GLAUX_ACCOUNT_V1")`) before it is installed — both checked
inside `applyUpdate`'s `ACTION_SET_IMPLEMENTATION` branch, not left to
convention. The three factor slots must be pairwise distinct in both
verifier type and key data — `_isDuplicateSlot` is checked pairwise in
`initializeAccount` and again against the other two slots on any single-slot
update in `applyUpdate`, reverting with `DuplicateSlot()` — so the threshold
can never be silently collapsed to a 1-of-1 by installing the same key
twice. Birth requires the target implementation to have deployed code
(`implementation.code.length == 0` reverts with `InvalidImplementation` in
`GlauxDelegate.initialize`) and requires the implementation's own
initializer to leave `GlauxStorage.layout().initialized == true` before the
ERC-1967 slot is written, so a delegatecall into an implementation that
silently no-ops cannot produce a live-looking but unconfigured account.

## Declared residuals

These are not omissions found during review; they are properties of the
design that the project states openly rather than implies away.

**Birth-environment compromise.** If the birth key leaks before it is
destroyed, the attacker can sign their own `initData` and call `initialize`
with their own choice of three factor slots, taking the account before its
intended owner does. There is no on-chain mitigation: the digest the
contract checks
(`keccak256(abi.encode(GlauxStorage.INIT_DOMAIN, implementation, keccak256(initData)))`)
is verified against `address(this)` as the signer precisely because the
birth key and the account address are the same EIP-7702 authority — the
contract cannot distinguish "the real owner's key" from "a copy of the real
owner's key" because no such distinction exists at the cryptographic level.
The entire security of the account before initialization rests on the birth
key never leaving the process that generated it, and on prompt destruction
after signing. This is a process guarantee, not a contract guarantee.

**Two compromised factors is full control, by design.** An attacker holding
any two of the three factor keys can execute arbitrary calls, rotate all
three slots, change verifier types, and upgrade the implementation
(constrained only by the code-hash and compatibility checks, which bind what
bytecode can be installed, not who may install it). There is no defense
against this inside the contract, and none is claimed. The fixed 2-of-3
threshold means security depends entirely on keeping any two factors from
falling to the same adversary — this is the design's central assumption,
stated without hedging.

**Same-nonce cross-chain equivocation.** Because update digests carry no
chain-id, two different `Update` payloads signed by the same 2-of-3 quorum
for the *same* `u.nonce` value are each independently valid and each will be
accepted by `applyUpdate` on whichever chain sees them first — the contract
only checks `u.nonce != l.updateNonce + 1`, which cannot detect that a
different payload already consumed that nonce on a different chain, because
each chain's storage is independent. The result is a genuine fork: chain A
ends up with configuration X at `updateNonce = N`, chain B ends up with
configuration Y at the same `updateNonce = N`, and both have advanced past
that nonce, so neither one can simply "retry" the other's update. Per-chain
nonces cannot prevent this by construction — the entire point of the
chain-agnostic update channel (spec §5, "sign once, replay many") is that
one signature reaches every chain, which requires the nonce space to be
shared, not per-chain. The mitigation is therefore entirely signer-side:
the quorum must never sign two distinct updates for one nonce value,
full stop — an update should be treated as consumed the moment it is signed,
not the moment it is observed on-chain. If divergence happens anyway,
clients detect it by reading `updateNonce` and each slot's content on every
chain the account has touched and comparing them: identical `updateNonce`
with differing slot contents is definitive proof of equivocation. Recovery
requires the surviving 2-of-3 quorum to sign a fresh update, at a nonce
higher than the diverged one, that the client applies uniformly to bring
every chain back to one configuration — there is no way to "undo" a
divergence, only to converge past it, and any chain not yet reconciled
remains authoritatively on its own diverged branch until that new update
reaches it.

**Code-hash binding guarantees identical bytecode, not identical behaviour.**
`applyUpdate`'s `ACTION_SET_IMPLEMENTATION` branch checks
`newImplementation.codehash == expectedCodeHash`, which proves the runtime
bytecode at that address is byte-for-byte what the signers intended. It
proves nothing about what that bytecode does once running, because
Solidity contracts commonly read mutable state — storage slots, or
addresses of other contracts they call — that is not part of the code hash.
An implementation with matching code hash on two different chains can
still behave differently there if, for example, it is itself a proxy
pointing at different logic on each chain, or if it calls out to
chain-specific external contracts (a different DEX router, a different
oracle) baked into constructor-set or storage-set addresses rather than
into the bytecode. Signers verifying `expectedCodeHash` are verifying
"this exact bytecode," not "this exact behaviour" — the two coincide only
for implementations without such external mutable dependencies, and clients
should say so rather than implying a code-hash match is a behavioural
guarantee.

**The compatibility marker is self-attestation.** `applyUpdate` requires the
candidate implementation to answer a `staticcall` to
`glauxCompatibilityId()` with exactly `GlauxStorage.COMPAT_ID`
(`keccak256("GLAUX_ACCOUNT_V1")`) before installing it. This stops accidents
— installing an implementation that was never meant to be a Glaux logic
contract, or an incompatible future version that changed the marker on
purpose to signal a breaking change — and it stops casual misconfiguration.
It does not stop a deliberate attacker: anyone who already controls a valid
2-of-3 quorum (the same attacker described in the residual above) can
trivially deploy a contract that returns the correct marker while doing
anything else it wants, because the marker is a self-reported four-byte
function selector's return value, not a proof of any actual interface
conformance beyond that one function. The check filters mistakes; it does
not filter malice from a quorum that has already reached the threshold that
matters.

**Key-shape validation cannot prove key possession.** `_validateSlot` calls
`SignatureVerify.isValidKey`, which for `VERIFIER_SECP256K1` checks that the
32-byte payload decodes to a nonzero value that fits in 160 bits (a
structurally valid address). Both of these checks — well-formedness of the
value, not evidence that anyone controls the corresponding private key. An
authorized 2-of-3 quorum can, entirely within the rules the contract
enforces, install a factor slot containing an address or a public key that
nobody holds the private key for — for instance by mistyping a value, or by
copying the wrong key from a backup. If that slot becomes one of the two
needed for the next quorum change, the account is permanently bricked
(2-of-3 is no longer reachable) with no on-chain recovery path, because the
contract's validation is necessarily limited to shape, never possession.

**P-256 signature malleability is deliberately not normalised on-chain.**
`SignatureVerify._verifySecp256k1` explicitly rejects the high-s form
(`if (uint256(s) > SECP256K1_N_DIV_2) return false;`), but
`_verifyP256` performs no equivalent check — it forwards `(r, s)` directly
to the RIP-7212/EIP-7951 precompile at `P256_VERIFIER` without constraining
`s` to the lower half of the curve order. This means a valid P-256
signature `(r, s)` and its malleable counterpart `(r, n-s)` are both
accepted by the verifier for the same message and key. This is safe in this
design specifically because replay protection here is nonce-based, not
signature-based: `applyUpdate` and `executeWithSigs` both check a
monotonically increasing nonce stored in `GlauxStorage.Layout`
(`updateNonce`, `execNonce`) before accepting an operation, and neither
signature value nor any hash of it is ever used as an identifier, an
idempotency key, or a uniqueness constraint anywhere in the contract.
Malleability only matters where a system infers state ("has this signature
been seen before?") from the signature bytes themselves; Glaux never does
that, so a second, differently-encoded signature over an already-consumed
nonce is simply rejected by the nonce check, exactly as a non-malleable
duplicate would be.

**Permissionless relay.** Anyone may submit a validly-signed `Update` or
`Call[]` payload, or a validly-signed `PackedUserOperation`; neither
`applyUpdate`, `executeWithSigs`, nor `validateUserOp`/
`executeFromEntryPoint` check `msg.sender` against any allowlist for the
signer side of the operation (`validateUserOp` and `executeFromEntryPoint`
do check `msg.sender == ENTRYPOINT`, but that restricts which contract may
invoke the 4337 path, not who may have produced the underlying userOp
signature). A relayer or bundler operating in this permissionless model can
therefore refuse to include a payload it dislikes, or delay it arbitrarily,
achieving censorship or denial of timely service. It can never forge a
signature it does not hold, never reorder an already-signed payload past
its own nonce check (a delayed update or execution is still checked against
the current `updateNonce`/`execNonce` at the moment it lands, so delay
cannot be converted into acceptance out of order), and never alter the
signed payload without invalidating the digest under the signatures it is
carrying. The mitigation for censorship is structural, not cryptographic:
because relaying requires no special authorization, a censored payload can
always be submitted through a different relayer.

**Chains never touched.** Until an EIP-7702 authorization and an
`initialize` call (or a later `applyUpdate`) actually land on a given chain,
that chain's state for this address is whatever the account's nonce and
storage happen to be there — which, before first touch, means the address
is a plain, undelegated EOA with no Glaux logic installed at all, and after
some updates but before others, means a configuration that lags behind
chains that have received more recent updates. There is no global registry
or oracle the contract consults to know what "the latest configuration" is
across chains; each chain's view is exactly what has been submitted to it,
nothing more. A client that queries only one chain and presents its
configuration as if it were universal misleads the user. Client UIs must
query every chain of interest independently and represent divergence or
staleness — including "this chain has never been touched, so the account is
not yet live here" — honestly, rather than assuming or implying a synced
global view that the protocol does not provide.

**Upgrade is irreversible in one direction.** `GlauxDelegate.initialize`
reverts with `AlreadyInitialized()` the moment the ERC-1967 implementation
slot is non-zero, and there is no function anywhere in `GlauxDelegate` or
`GlauxAccount` that clears that slot back to zero. Once an account is born,
the only way to change its logic is `applyUpdate`'s
`ACTION_SET_IMPLEMENTATION` branch, which itself depends on the update
channel — the same 2-of-3 signature path — still functioning correctly
against whatever implementation is currently installed. If a quorum
installs a broken implementation (one that passes the code-hash and
compatibility checks but has, say, a bug that makes `applyUpdate` itself
unreachable or always-reverting), the account cannot be returned to
`initialize`-time state; the only repair path is another `applyUpdate` call
routed through whatever entry points the broken implementation still
exposes, and if none do, the account is stuck on that implementation
permanently. This is the direct consequence of birth being a strictly
one-time, one-directional event: it buys the guarantee that a live account
can never be re-initialized out from under its owners, at the cost of no
safety net if an upgrade itself breaks the upgrade path.
