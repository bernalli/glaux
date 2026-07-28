# Glaux — Design Specification

- **Version**: v0.1 (draft for review)
- **Date**: 2026-07-28
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
  every chain: the single tuple remains valid on all present and future
  chains ("replay on first touch").
- Consequences, declared openly:
  - the delegation pointer is fixed forever; upgrades happen *inside* the
    delegate through an implementation slot governed by the 2-of-3;
  - the residual-key threat collapses to birth-time environment compromise
    (see threat model). EIP-7851, when live, will allow disabling residual
    ECDSA authority at the protocol level; Glaux's construction does not
    depend on it.

## 5. Single update channel (sign once, replay many)

- **All** configuration changes — slot key rotation, slot verifier-type
  change, implementation upgrade — travel through one message type, signed
  without chain-id, carrying a monotonically increasing per-account update
  nonce.
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

1. **Unlocked-device runtime compromise** controls F1+F3: the daily pair is
   defeated; full theft still requires F2. No mobile wallet covers this
   case; Glaux declares it instead of pretending otherwise.
2. **Birth-time environment compromise**: a compromised key-generation
   environment can exfiltrate the ephemeral key before destruction.
3. **Never-touched chain**: previous configuration remains valid there until
   the update replay lands (declared in client UX).
4. **Cloud breach**: worth exactly 1 factor of 3.
5. **Upgrade power**: the 2-of-3 controls implementation upgrades; a timelock
   on upgrades is evaluated during implementation.

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
- Property/invariant test suite green in CI.
- Testnet deployments: Sepolia + one L2 testnet with RIP-7212.
- Threat model document.
