# MINA

Minimal, crypto-agile EIP-7702 smart account — self-custodial key management
with threshold security on the operational path and a post-quantum-ready
verification slot.

> **Status: pre-alpha, design phase.** Nothing here is audited or
> production-ready. Do not use with real funds.

## Goals

- **One address, every EVM chain** — an EIP-7702 delegated EOA keeps the same
  address on every chain by construction: no factories, no counterfactual
  deploys.
- **Threshold security on the operational path** — the delegate enforces
  2-of-3 verification for operations; the EIP-7702 residual-key problem is
  addressed explicitly in the threat model (until EIP-7851 lands).
- **Sign-once, replay-many rotation** — one rotation signature valid on every
  chain, delivered per chain on first touch; a single update channel, always
  replayable, never mixed with chain-specific updates.
- **Crypto-agility, PQ-ready** — P-256/passkey as primary signer (live
  precompiles: EIP-7951 on L1, RIP-7212 on L2), a replaceable verification
  slot so signature schemes can rotate without migrating funds, an optional
  hash-based (SLH-DSA) post-quantum factor, and a lattice migration path once
  PQ precompiles ship.
- **Adoption tooling** — migration adapters for existing smart accounts
  (Safe first).

## Non-goals

- No backend, no custody: everything verifies on-chain or client-side.

## License

Permissive open-source license (exact license TBD before first release).
