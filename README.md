# Glaux

*Glaux (γλαύξ) — the little owl of Minerva, stamped on Athenian tetradrachms
to guard the coin.*

Minimal, crypto-agile EIP-7702 smart account — self-custodial key management
with threshold security on the operational path and a post-quantum-ready
verification slot.

> **Status: unaudited reference implementation.** Phase 1 is complete — the
> contracts, a property/invariant test suite, deterministic deployment and
> birth tooling all exist and are green — but nothing here has been audited.
> **Do not use with real funds.**

## Documentation

| Document | What it is |
|---|---|
| [`docs/specs/2026-07-28-glaux-design.md`](docs/specs/2026-07-28-glaux-design.md) | The design specification (v0.5), with a revision list |
| [`docs/threat-model.md`](docs/threat-model.md) | What is protected, against whom, and the residuals the project declares openly |
| [`docs/client-guidance.md`](docs/client-guidance.md) | Required reading before integrating: several residuals are closed **only** by a client-side rule |
| [`docs/static-analysis.md`](docs/static-analysis.md) | Slither triage — every finding fixed, suppressed with reasoning, or accounted for |
| [`docs/deployments.md`](docs/deployments.md) | Deterministic addresses and the end-to-end birth proof |

## Build and test

```bash
forge build
forge test
```

Dependencies are vendored under `lib/` (see `lib/VENDORED.md`) rather than
installed as submodules, so a fresh checkout builds offline with no fetch step.

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

MIT — see [`LICENSE`](LICENSE).
