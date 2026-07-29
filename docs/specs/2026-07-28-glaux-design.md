# Glaux — Design Specification

- **Version**: v0.3
- **Date**: 2026-07-28, revised 2026-07-29
- **Status**: v0.1 was ratified before implementation. v0.2 and v0.3 fold in the
  design changes that security review forced during Phase 1; each is marked in
  place and all are listed in §11.
- **Origin**: Minerva ADR-0003 (W3-R route) and research dossiers 11
  (cross-chain keystore state of the art) and 12 (post-quantum EVM state of
  the art). In the founding documents the project is referred to by its
  former name, MINA.

## 1. Vision and ambition

Glaux is a minimal, crypto-agile EIP-7702 smart account: self-custodial key
management with a fixed 2-of-3 threshold on the operational path and a
replaceable verification-slot design that makes signature schemes — including
future post-quantum ones — swappable without migrating funds or changing
address.

The long-term ambition is adoption beyond its first client: Glaux aims to
become a reference standard for EVM self-custody — wallets first, tokenized
traditional finance as it moves on-chain second; both need recoverable,
quantum-ready self-custody that survives device loss, vendor churn, and
algorithm turnover. Adoption is a first-class goal, pursued actively:
permissive licensing, a public specification, a standardization path (ERC
draft once the design is validated), ecosystem grants for audits, and
migration tooling for existing accounts (Safe first).

## 2. Scope boundary

The contract verifies signatures; it knows nothing about platforms, clouds,
or key storage. Everything platform-specific lives in client guidance, not in
the protocol.

Phase 1 artifacts:

1. this specification;
2. the reference delegate contract (Solidity);
3. the threat model document;
4. client reference guidance (factor storage requirements per platform).

Explicitly out of Phase 1: client SDKs, Safe migration adapters, post-quantum
and zk-email verifiers (only the interface that will host them), gas
abstraction UX (paymasters), commissioned audits.

## 3. Account architecture

- The account is an EOA delegated via EIP-7702 to the **Glaux delegate**, a
  single contract deployed at the same deterministic address on every EVM
  chain (CREATE2 through a canonical deployer; deploying on a new chain is
  permissionless).
- Account state holds **3 factor slots**, each a pair `(verifierType, data)`,
  with a **fixed 2-of-3 threshold**. No generic k-of-n: deliberate
  opinionation, minimal audit surface.
- *(revised v0.2)* **The three slots must hold pairwise-distinct credentials**,
  enforced at birth and on every rotation. Counting distinct slot *indices* is
  not enough: if the same key sits in two slots, one signature submitted twice
  under two indices satisfies the threshold, and 2-of-3 silently collapses to
  1-of-1. Two slots are duplicates when they share a verifier type and
  identical key data.
- *(revised v0.2)* **Every implementation must self-identify** by returning
  `keccak256("GLAUX_ACCOUNT_V1")` from `glauxCompatibilityId()`. Both the birth
  path and the upgrade path staticcall it and require exactly one word of
  return data equal to that constant. This is a guard against accident and
  incompatible logic — it is self-attestation, not proof against an adversary
  who already holds two factors and therefore owns the account by definition.
- *(revised v0.2)* **An implementation may never be an EIP-7702 delegation
  designator.** For a delegated EOA, `EXTCODEHASH` hashes the 23-byte designator
  while `DELEGATECALL` executes the delegation *target's* code — so a bound code
  hash would bind nothing, and one designator can resolve to different code on
  different chains. EIP-3541 forbids deploying code beginning with `0xEF`, so a
  leading `0xEF` byte identifies a designator exactly, and both the birth and the
  upgrade path reject it. Both also read the marker through a bounded 32-byte
  output window, so hostile returndata is a clean rejection rather than an
  out-of-gas failure.
- **Every state-changing operation** — execution, key rotation, slot type
  change, implementation upgrade — requires 2 valid signatures from 2
  distinct slots.
- **v1 verifiers**: secp256k1 (`ecrecover`) and P-256 (EIP-7951 precompile on
  L1, RIP-7212 on L2s).
- The **verifier interface is the crypto-agility point**: new verifier types
  (hash-based SLH-DSA post-quantum, zk-email DKIM proofs, …) are additive,
  audited upgrades. A factor can change *kind*, not just key, with no fund
  migration and no address change.
- The delegate exposes ERC-4337 `validateUserOp` (bundler compatibility,
  future gas UX) alongside a direct execution path.

## 4. Account birth and residual-key neutralization

- An ephemeral EOA is generated client-side. It signs **one** EIP-7702
  authorization tuple with `chain_id = 0` and nonce 0. The tuple (public) is
  retained; the birth private key is **destroyed**.
- The account never transacts as a plain EOA, so its EOA nonce stays 0 on
  every chain **until first touch there**: applying the tuple consumes it on
  that chain (EIP-7702 increments the authority nonce), and the same tuple
  remains valid on every chain not yet touched, present or future ("replay
  on first touch").
- *(revised v0.2)* The birth blob signs the **implementation identity**, not
  merely its address:

  ```
  digest = keccak256(abi.encode(INIT_DOMAIN, implementation,
                                expectedCodeHash, keccak256(initData)))
  ```

  Before the delegatecall, the immutable router requires non-empty runtime
  code, `implementation.codehash == expectedCodeHash`, and the compatibility
  marker. Only then does it delegatecall `initializeAccount`, assert the
  `initialized` postcondition, write the implementation pointer, and emit.
- *(revised v0.3)* **The authoritative implementation pointer lives in a
  Glaux-owned namespaced slot**, `keccak256("glaux.account.v1.implementation")`,
  and the ERC-1967 slot is written only as a mirror for explorer tooling. The
  ERC-1967 slot is an industry-wide standard and an EIP-7702 re-delegation does
  not clear storage, so an EOA arriving from any other proxy-pattern wallet
  would otherwise find it occupied — which would block birth permanently *and*
  let the router's fallback execute a stale foreign pointer. Glaux never reads a
  slot it does not own. Birth is additionally guarded against re-entry for the
  duration of the untrusted initializer.

  Rationale: the digest deliberately carries no chain id, so the blob replays
  everywhere — and the same *address* does not hold the same *code* on every
  chain. Without the code-hash binding, replaying the public blob on a chain
  where that address holds different code would initialize the account against
  foreign logic that then runs by delegatecall in the account's own storage and
  balance context, needing only to set `initialized` to satisfy the router. One
  signature must install byte-identical logic everywhere or fail cleanly.
- An implementation with no code on the target chain is rejected without
  writing any state, and **the same blob stays retryable** on that chain once
  the logic contract is deployed there. That is the ordinary case, not an
  error: a birth blob is expected to outrun deployment on chains the account
  has not reached yet.
- Consequences, declared openly:
  - the delegation pointer is fixed forever; upgrades happen *inside* the
    delegate through an implementation slot governed by the 2-of-3;
  - *(revised v0.2)* **a birth key that survives destruction is a permanent
    master key, not a front-running risk.** The birth key *is* the account's
    EOA key, and EIP-7702 lets a delegated EOA still originate ordinary
    transactions and sign further authorizations — so a surviving copy can
    spend directly and can replace the delegation itself, forever. No factor
    rotation revokes it, because the 2-of-3 governs the delegate's state, not
    the EOA's authority. Suspected birth-key compromise therefore means
    migrating assets to a new address, never rotating factors. EIP-7851, when
    live, will allow disabling residual ECDSA authority at the protocol level
    and is the only real remedy; Glaux's construction does not depend on it,
    but this is the residual that most deserves a client's attention.

## 5. Single update channel (sign once, replay many)

- **All** configuration changes — slot key rotation, slot verifier-type
  change, implementation upgrade — travel through one message type, signed
  without chain-id, carrying a monotonically increasing per-account update
  nonce.
- Two actions exist. `SetSlot` carries `(uint8 index, uint8 verifierType,
  bytes data)`. *(revised v0.2)* `SetImplementation` carries
  `(address implementation, bytes32 expectedCodeHash)` and enforces the same
  three checks as birth — code present, exact code hash, compatibility marker —
  for the same cross-chain reason: one address does not hold one bytecode
  everywhere, and an upgrade that installed foreign code would be delegatecalled
  into the account's own storage.
- *(revised v0.2)* **Same-nonce equivocation is a residual, not a defect.** Two
  different updates signed for the same nonce can each land first on different
  chains, leaving divergent configurations with both nonces advanced. Per-chain
  nonces cannot prevent it — it is inherent to a deliberately chain-agnostic
  channel. The rule is signer-side and absolute: *never sign two updates for one
  nonce*, including "the same upgrade with a per-chain code hash", which is
  exactly the forbidden case. Clients reconcile by comparing nonce, slots, **and
  the implementation pointer with its live code hash** — an upgrade advances the
  nonce while changing nothing else, so nonce-and-slots agreement alone can hide
  two chains running different logic.
- Updates are replayed **in order** on each chain at first touch ("silent
  submission"). No chain-specific configuration update exists: the Coinbase
  Smart Wallet audit lesson (issue #114 — mixing chain-specific and
  cross-chain updates desynchronizes owner state across chains) is a design
  invariant, not a guideline.
- Worst accepted failure is "retry later". Never fund loss, never an
  inconsistent intermediate state.
- A chain not yet touched holds the previous configuration until the replay
  lands; clients surface this honestly instead of masking it (ADR-0003
  invariant).

## 6. Reference factor deployment

- **F1 — device key**: hardware-backed P-256 on whatever device the user
  owns — Secure Enclave (iPhone/Mac), StrongBox/TEE (Android), TPM/Windows
  Hello (PC), WebAuthn passkey in the general case. P-256 is the primary
  algorithm because it is the only one every consumer secure-hardware speaks
  natively *and* the only one with live EVM precompiles. Never tied to a
  single vendor.
- **F2 — paper key**: printed secp256k1 key. Cold factor for recovery and
  rare privileged operations.
- **F3 — cloud co-signer**: software key synced through the user's cloud of
  choice. Backend is pluggable — iCloud Keychain, Google equivalents, or any
  E2E-encrypted storage — against declared conformance requirements:
  end-to-end encryption, authenticated access, revocability. Never
  Apple-only.
- Daily UX: F1+F3 co-sign transparently. Recovery: any 2 of 3. Factor
  evolution (e.g., adding an email-based recovery factor via a zk-email
  verifier) is a 2-of-3 update on the single channel.

## 7. Threat model — declared residuals

Summary only — `docs/threat-model.md` holds the full enumeration with the
guarantee/non-guarantee per adversary, and `docs/client-guidance.md` holds the
signer-side rules that follow from it.

1. **Two factors are full control.** The threshold is the whole security model:
   an adversary holding any two factors can rotate the third, upgrade the
   implementation and move funds. Every "guard" below stops accidents and
   incompatible code, never a two-factor adversary.
2. **Unlocked-device runtime compromise** controls F1+F3: the daily pair is
   defeated; full theft still requires F2. No mobile wallet covers this
   case; Glaux declares it instead of pretending otherwise.
3. *(revised v0.2)* **A retained birth key is a permanent master key** — see
   §4. This is the gravest residual and the only one whose remedy is migration
   rather than rotation.
4. **Never-touched chain**: previous configuration remains valid there until
   the update replay lands (declared in client UX).
5. **Same-nonce cross-chain equivocation** (§5): detectable by reconciliation,
   preventable only signer-side.
6. **Cloud breach**: worth exactly 1 factor of 3.
7. *(revised v0.2)* **A code hash binds bytecode, not behaviour.** Identical
   bytecode at the signed hash may still be a proxy pointing elsewhere, or may
   read storage a client did not review. The check makes cross-chain code
   identical; it does not make it correct.
8. *(revised v0.2)* **Upgrades are irreversible in one direction**: once the
   implementation pointer is non-zero the birth path can never re-run, so an
   upgrade to logic that cannot itself upgrade is terminal. Storage-layout and
   dependency review is a client obligation, not an on-chain check.
9. *(revised v0.2)* **Submission is permissionless by design** — anyone may
   relay a signed operation and pay for it, which is what makes a cross-chain
   gas account possible. A relayer chooses *whether* and *when*, never *what*.
10. *(resolved v0.2)* **No upgrade timelock in v1.** It was left open in v0.1;
    the decision is not to add one. Upgrade authority is exactly the authority
    that can already move the funds, so a timelock would delay an adversary who
    could simply drain instead, while adding a stuck-state failure mode to the
    permanent router.

## 8. License, stack, quality bar

- **License**: MIT (ecosystem norm — Coinbase Smart Wallet, Solady,
  OpenZeppelin; maximum adoptability for grants and third parties).
- **Stack**: Foundry, Solidity 0.8.x, CI on GitHub Actions.
- **Quality bar**: property-based + invariant tests from day 1; Slither in
  CI; Halmos/formal verification as a pre-audit milestone; audits sought
  through ecosystem grants (public track-record strategy).
- Repository private until the work is presentable; born-public discipline
  active from day 1 (no internal infrastructure references, no AI co-author
  trailers).

## 9. Standardization path

v1 ships a minimal bespoke verifier interface: smallest audit surface,
deliberate opinionation (fixed 2-of-3, no free-form module installation).
Once validated in production: publish the verifier interface and the update
channel as an **ERC draft**; evaluate an **ERC-7579 adapter** as future work,
so Glaux slots can host ecosystem modules without importing their surface
into the core.

## 10. Phase 1 acceptance

- This specification ratified.
- Delegate reference implementation: factor slots, fixed 2-of-3, single
  update channel, `validateUserOp`, deterministic deployment.
- Property/invariant test suite green in CI, plus a Slither gate.
- A test proving a paymaster can sponsor a user operation for an account
  holding zero native currency — the on-chain evidence for the cross-chain gas
  account of Phase 2.
- Testnet deployments: Sepolia + one L2 testnet with RIP-7212.
- Threat model document and client reference guidance.

### Bundler compatibility of the P-256 factor (resolved 2026-07-29)

ERC-4337 bundlers restrict what an account may do during validation, and a
P-256 factor makes validation staticcall the P256VERIFY precompile — so this
had to be checked rather than assumed. It is explicitly permitted:
**ERC-7562 rule OP-062** allows "the core precompiles `0x1`–`0x11`" and "the
`P256VERIFY` secp256r1 precompile defined in EIP-7951". EIP-7951 is Final and
assigns address `0x100`, taking 160 bytes `h ‖ r ‖ s ‖ qx ‖ qy` and returning
one word equal to 1 on success and empty on failure — which is exactly what
`SignatureVerify._verifyP256` sends and how it interprets the answer.

Two caveats remain, and they are the ordinary kind: OP-062 permits the
precompile *on networks that have it*, so a chain without it is out regardless
(residual 8 in the threat model), and any given bundler may lag the
specification. Neither is a design question. The direct `executeWithSigs` path
needs no bundler at all.

## 11. Revision history

- **v0.3 (2026-07-29)** — three defects from an independent review, two of them
  in the immutable router. **The implementation pointer is now a Glaux-owned
  namespaced slot**, not ERC-1967: that slot is an industry-wide standard and an
  EIP-7702 re-delegation does not clear storage, so an EOA migrating from any
  proxy-pattern wallet arrived with it occupied — which permanently blocked
  birth *and* let the router's fallback execute the stale foreign pointer.
  ERC-1967 is still written as a mirror for explorers, never read. **Birth is
  guarded against re-entry** for the duration of the untrusted initializer, so
  the router no longer depends on a convention that replaceable code could drop.
  **Two signatures sharing `(r, s)` are rejected**: one ECDSA signature verifies
  against more than one public key, so distinct slots were not yet distinct
  credentials and a single keypair could meet the 2-of-3 threshold. Also
  declared: a birth blob never expires and cannot be revoked (sign exactly one);
  two P-256 slots make an account inert on a chain without the precompile; the
  direct execution path has no deadline. **Open, must be decided before the
  router is deployed to a canonical address: whether to adopt EIP-712 typed
  data** — see the threat model.

- **v0.2 (2026-07-29)** — six changes forced by Phase 1 security review, all
  ratified before landing: factor slots must be pairwise distinct (§3);
  implementations must carry the `GLAUX_ACCOUNT_V1` marker (§3); the birth blob
  binds `expectedCodeHash` and the router validates code, hash and marker before
  the delegatecall, asserting the `initialized` postcondition before writing the
  ERC-1967 pointer (§4); `SetImplementation` carries `expectedCodeHash` (§5);
  same-nonce equivocation and implementation-pointer reconciliation declared
  (§5); the birth-key residual restated as a permanent master key rather than a
  front-running window (§4, §7). Also resolved: no upgrade timelock in v1 (§7).
- **v0.1 (2026-07-28)** — ratified before implementation.
