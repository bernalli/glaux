# Internal red-team — 2026-08-05 (pre-publication)

Adversarial pass run before flipping the repository public. Unlike the earlier
review rounds, the two reviewers were briefed as attackers: the sole objective
was a concrete way to **steal funds, permanently brick an account, forge a
birth, bypass the 2-of-3 threshold, or make an SDK-following integrator lose
funds**. Unexploitable style or robustness observations were explicitly out of
scope; the required deliverable for every candidate was either an exploit path
(preconditions, actor, gain) or a reasoned proof of non-exploitability.

- **Scope**: `src/**` (the contracts that hold funds), `sdk/src/**`,
  `scripts/*.py` operational tooling, and `docs/**` + `README.md` treated as a
  deception surface (could a documented claim, if trusted, cost an integrator
  funds?).
- **Method**: two independent reviewers (A and B), blind to each other —
  divergence between them would itself be a signal. Each was told to spend its
  budget on the single deepest exploitable path rather than an exhaustive sweep.
- **Reproduction discipline**: any positive exploit claim was to be reproduced
  before being treated as real, as done for H-1/H-2 in the 2026-08-03 audit.

## Verdict

**No exploitable path found by either reviewer.** The two blind passes converged:
the on-chain threshold, birth, signature and storage logic hold against the
strongest attacks mounted, and the documentation's deception surface is clean —
no claim is false in the fund-losing direction. There were no positive exploit
claims to reproduce. The residual fund-loss exposure is entirely **client-side**
and already disclosed in `threat-model.md` / `client-guidance.md`.

Because there were no positive claims, verification took the form of the
orchestrator independently re-reading the load-bearing surfaces and confirming
the reviewers' reasoning against the code: all five contracts, the ERC-4337 fee
ceiling (`sdk/src/gas/feeGuard.ts`), the pinned canonical addresses
(`sdk/src/core/constants.ts`) and the deployment record. Every anchor checked out.

## The hardest attacks attempted, and why they hold

### 1. Forge a birth to hijack a funded account, or install attacker factors at a chosen address
The account address is *recovered*, not chosen: the router recomputes
`r = keccak256(abi.encode(digest, salt))`, where `digest` commits to
`(implementation, expectedCodeHash, keccak256(initData))`, and reverts unless the
recovery equals `address(this)` (`src/GlauxDelegate.sol:121-136`). `AUTH_MSG_HASH`
bakes in the router's own address (`src/GlauxDelegate.sol:56,65`) and `v` is fixed
at 27 (`:47`), so the recovered address is a pseudo-random function of the full
configuration. Landing on a chosen 160-bit address, colliding two configurations
on one address, or re-delegating an existing account to a hostile router are each
a ~2^160 search. Re-birth is blocked by `IMPL_SLOT != 0 → AlreadyInitialized`
(`:114-119`). The 13-byte rootless tag is confirmed *not* load-bearing here — the
`r`-recomputation is — so a tag weakness would not help.

### 2. Reach the 2-of-3 quorum with a single factor
`_checkTwoSigs` requires two distinct slot indices, rejects identical `(r,s)`
across the two signatures, and verifies each against the live stored key
(`src/GlauxAccount.sol:392-415`). The "pick a signature, derive the key it
recovers to" forge is closed at registration by `_requirePossession`, whose
challenge digest commits to `keccak256(keyData)` — the key itself
(`src/GlauxAccount.sol:148-154`). Registering a second credential therefore
requires a signature valid under a key that a digest committing to that same key
recovers to: a hash-preimage search, not a curve computation. Key material is
forced canonical (`_isValidSecp256k1Key`, `src/lib/SignatureVerify.sol:88-95`)
*before* the proof is checked, leaving no attacker-controllable entropy to grind
a fixed point. `ecrecover(...) == address(0)` is rejected
(`src/lib/SignatureVerify.sol:85`). The secp256k1 v-flip twin and the P-256
existential-forgery angle both terminate against the same possession commitment.

### 3. Drain the account/deposit on the ERC-4337 path via a hostile RPC + paymaster + bundler
`signUserOp` enforces a **mandatory absolute cost cap** and a fee-history baseline
check at the single signing choke point, on the final paymaster-decorated
operation, before any signature exists. `assertUserOpCost`
(`sdk/src/gas/feeGuard.ts:207-213`) prices the ERC-4337 v0.7 worst-case prefund
including the paymaster's own two gas limits (`computeUserOpMaxCost` /
`paymasterGas`, `:189-195, 165-170`), so a paymaster that inflates them or names
the zero address to shove the prefund back on the account stays bounded by
`maxCostWei`. The cap cannot be silently omitted: a non-bigint throws
(`:207-210`). The baseline reads `eth_feeHistory` with a strict shape check and
fails closed, never falling back to an endpoint-proposed value
(`fetchFeeBaseline`, `:66-114`). `userOpHash` binds `paymasterAndData`, so nothing
can be altered post-signing.

## Candidates investigated and rejected

Cross-domain / cross-chain digest replay (six domain constants + EIP-191 v0x00
validator binding; EXEC/MSG bind `chainid`, birth/update chain-agnostic by design
with nonce guards); transient-slot-0 collision (router uses the namespaced
`DELEGATE_BIRTH_GUARD_SLOT`, not slot 0); ERC-1967 slot poisoning on re-delegation
(Glaux never touches that slot); reentrancy landing an update or double-execute
mid-batch (`applyUpdate` and `_execute` converge on the same `executing` guard);
7702-designator or codeless implementation as logic (`ImplementationCheck` rejects
leading `0xEF`, requires exact codehash + compat marker in a bounded window);
`initializeAccount` outside a router birth (birth-guard `NotDuringBirth`);
factor-rotation leaving an old key valid (all channels read live slots through the
one `_checkTwoSigs`); P-256 `(r, n-s)` malleability (confined to one slot index,
never a second credential); probe-key install (refused); prefund paid on invalid
signature (EntryPoint reverts and unwinds the op); reconcile parity / empty-set
false "consistent" (empty set throws, canonical re-encode guard applied to both
`implementation()` and the load-bearing `getSlot` decode); eligibility probes at
canonical CREATE2 addresses ("has code" ≡ "has canonical code" on an honest chain;
moot on a hostile one); client accepting a router-rejected birth blob (both
submitters re-run the router's exact recovery check and refuse to broadcast on an
implausibly cheap authorization-aware gas estimate).

## Residual exposure (disclosed, client-side — not code defects)

The catastrophic-loss surface that remains is closed only by client-side rules the
contracts cannot enforce, each already normative in the docs:

- **Hostile single RPC** (residual 18): birth confirmation, nonce and fee baseline
  all flow through one endpoint that can lie consistently; only the absolute
  `maxCostWei` cap and the local-clock `validUntil` ceiling survive a fully hostile
  endpoint. Mitigation ("use a second independent endpoint") lives in guidance.
- **Blob retention with a random-nonce signer** (residuals 4/13): the production
  P-256 possession path signs with a random nonce, so a discarded blob names an
  address that can never be reborn — funds sent there are gone. "Craft once, keep
  the blob."
- **Deployment reproducibility**: `receive()` accepts value on any chain; funds at
  the address on a chain lacking the canonical router/impl/CREATE2 deployer are
  frozen.
- **Two-factor compromise** (residual 2) and **ERC-1271 statelessness** (residual
  16) are accepted definitional properties of the design.

## Deployment-state note (liveness, not a security defect)

Both reviewers independently flagged that `sdk/src/core/constants.ts` pins the new
rootless router `0x3ccF1cc0…` and implementation `0x21b5D576…`, while the public
testnets still carry the previous router `0xB8270e4B…` and the canonical redeploy
is pending a funded relayer key (`docs/deployments.md`). Until that redeploy lands,
an integrator building blobs against the pinned router targets a contract not yet
on-chain; the birth submitters' gas-floor guard refuses such a birth rather than
bricking, so this is a liveness state, not a loss — and there are no real funds at
this stage. Confirming the canonical router is deployed on every target chain is a
prerequisite for publication.
