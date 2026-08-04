# Glaux Phase 4 — Client SDK and cross-chain gas account: design

Status: approved 2026-08-03 (brainstorming session; model, language,
scope and design each ratified explicitly).
Base branch: `audit/phase3-internal` (contains the Phase 3 audit fixes; not yet
merged to `main`).

## 1. Goal and requirement trace

Phase 4 of the roadmap: complete the product before publishing. Two charter
items land here:

- **Cross-chain gas account** (requirement, 2026-07-29): the account holder
  funds gas once and operates on every supported chain.
- **Client SDK** (charter lever): the piece that makes the design usable by
  third parties.

This spec covers both, because the first collapsed into the second (§2).

## 2. Decision: the gas account is an SDK module, not infrastructure

Ratified 2026-08-03. The gas account is **not built as Glaux infrastructure**.
No paymaster contract, no on-chain deposit, no rebalancing service. Instead the
SDK implements the [ERC-7677](https://eips.ethereum.org/EIPS/eip-7677)
paymaster-web-service protocol, with the provider as configuration:

- **First provider: Pimlico.** One off-chain balance funds sponsorship on
  100+ chains; free on testnets; mainnet gas is billed +10%. This satisfies
  the "fund once, operate everywhere" requirement today, with deposit custody
  and rebalancing carried by the provider's own business.
- **Second provider (future): Circle Paymaster** — the opposite trust model
  (the user pays gas from their own on-chain USDC). Deferred: coverage today
  is Arbitrum and Base only, and its cross-chain single-balance mode is still
  in development. Under ERC-7677 adding it is a module, not a redesign.
- **Structural fallback: permissionless self-relay.** Submission is
  permissionless by design (threat model §10); anyone with native gas on a
  chain can relay a signed operation. The provider is a convenience layer,
  never a custodian and never an authorizer: a paymaster can at worst deny
  sponsorship, never authorize an unsigned operation (threat model, paymaster
  entry).

Rejected alternatives, for the record: a self-hosted paymaster + deposit +
rebalancer (audit surface, a hot operational key, and bridge risk, all without
differentiating value — gas is a commodity market); pinning the product to one
chain (a paymaster lives on the chain where the operation executes; the single
account lives in the provider's off-chain balance, not on a chain).

## 3. Funds safety on uncovered chains (settled during design)

Provider non-coverage is never a funds-safety problem:

1. **Inbound** transfers reach the address on any chain (and on chains where
   the account is born, `receive()` runs with `address(this)` = account).
2. **Outbound** works without any paymaster, twice over: the 4337 path is
   self-funding (`validateUserOp` pays `missingAccountFunds` from the
   account's own balance — `GlauxAccount.sol`), and the direct path is
   permissionless relay, where the batch itself may reimburse the relayer.

The **real** hazard is elsewhere and is owned by this SDK: the account address
is an EOA whose birth key is destroyed. On a chain where the account has not
been born, funds sent to the address arrive but are **frozen until a birth
happens there**. The birth blob does not expire (`chainId 0` authorization), so
on an *eligible* chain this is recoverable at any time; on an *ineligible*
chain (no EIP-7702, or no P256VERIFY for the canonical factor set) the funds
stay frozen until that chain upgrades. Nobody can steal them; nobody can move
them either. Hence §5: chain eligibility is a security feature, not
documentation.

## 4. Form and placement

- **Language**: TypeScript (strict), ESM, Node 20+ and browser targets.
  Ratified over Swift-first: npm is the integrator lingua franca; Minerva can
  consume it via bridge or bindings.
- **Placement**: a `sdk/` workspace **inside this repo**. The source of truth
  for digests and encodings is the Solidity; parity fixtures must live beside
  the contracts in the same CI or they drift.
- **Foundation**: viem 2.x (MIT; native EIP-7702 and ERC-4337 support).
  Checked against the npm registry at design time (2.55.10, MIT); the
  dependency-security gate (Sonatype) was not authenticated during design and
  MUST be re-run when dependencies are actually added.
- **npm publication is out of scope** for this phase (Phase 5, together with
  repo publication; the package name is chosen then).

## 5. Modules

Each module has one purpose, a typed public surface, and no reach into the
internals of the others.

- **`core`** — the account model: address, the three `FactorSlot`s, domains
  and digests (EIP-191 `0x00` everywhere; `MSG_DOMAIN`, `USEROP_DOMAIN`,
  update/birth domains), blob encodings. Pure functions, zero I/O. This is
  the layer that must be bit-identical to the Solidity, and the layer parity
  fixtures pin down.
- **`signers`** — a pluggable `Signer` interface: raw secp256k1 (paper factor,
  tests), raw P-256 (device factor), cloud co-signer. The SDK never holds a
  long-lived private key; whoever implements the interface signs. DER→raw
  normalization and low-s live here (client-guidance rules become code).
  **Compatibility note (corrected during planning)**: the contract verifies a
  *raw* P-256 signature over the digest, so the device factor must be a key
  that signs bare 32-byte digests — a native Secure Enclave key qualifies; a
  browser WebAuthn passkey does **not** (it signs the WebAuthn envelope, not
  the digest). Browser-passkey support would require an on-chain WebAuthn
  verifier type: out of scope, recorded as a future verifier candidate.
- **`birth`** — ephemeral birth key generation, birth-blob construction
  (authorization with `chainId 0`), the pre-birth preflight (port of
  `preflight_fresh_account` as hardened by audit finding H-2: IMPL_SLOT plus
  all namespaced words checked, and exactly `0xef0100‖router` admitted as
  pre-existing code), and submission through a relayer.
- **`execute`** — the two outbound paths: direct
  `executeWithSigs(calls, validUntil, sigs)`, and ERC-4337 (UserOp
  construction, signature blob `abi.encode(uint48 validUntil, SlotSig[2])`,
  self-funded or sponsored). `validUntil == 0` is rejected client-side as it
  is on-chain.
- **`gas`** — the ERC-7677 client (`pm_getPaymasterStubData`,
  `pm_getPaymasterData`); provider is configuration, Pimlico first. The
  fallback policy is **declarative and explicit**: sponsored → self-funded
  4337 → self-relay guidance; every degradation surfaces as an observable
  event, never a silent retry. Provider API keys come from the environment,
  never from the repo.
- **`eligibility`** — the chain eligibility matrix. Live, read-only probes:
  P256VERIFY at `0x100` (two-armed, as at birth), EIP-7702 support (probed
  read-only via `eth_estimateGas` with an authorization list, the mechanism
  verified live on both testnets on 2026-07-31), CREATE2 factory presence,
  EntryPoint v0.7 code, router/impl deployed at canonical addresses, account
  born. Result is a three-state verdict per chain:
  `born` / `eligible` (birth needed) / `ineligible` (frozen-funds hazard).
  **Gate rule**: an integrator asks this module before displaying a receive
  address on a chain; `ineligible` produces a hard warning. A verified-chains
  table (measured, not estimated) feeds the public docs.
- **`reconcile`** — TypeScript port of `reconcile.py` with the same normative
  raw-first ordering from client-guidance, same verdicts.

## 6. Data flow

Integrator builds an operation → `signers` sign digests produced by `core` →
`execute` submits (direct via relayer, or 4337 via bundler) → `gas` decorates
the UserOp with paymaster fields when a provider is configured and sponsorship
is granted → `reconcile`/`eligibility` read back cross-chain state.

## 7. Error handling

Typed, per-domain errors (`IneligibleChainError`, `BirthPreflightError`,
`PaymasterUnavailableError`, `OperationExpiredError`, …). The gas module's
fallback chain emits explicit events for every degradation. No silent
fallbacks anywhere: a sponsored path that quietly becomes self-paid is treated
as a bug.

## 8. Testing

Four layers, mirroring what already exists for Python:

1. **Parity fixtures Solidity↔TS**: generated by a forge script, committed,
   consumed by the TS suite, with sabotage checks proving the fixtures can
   fail.
2. **Two-chain e2e on anvil**: reuse the `two_chain_proof` harness — birth,
   replay, execute, reconcile driven from the SDK instead of the Python
   scripts.
3. **4337 e2e**: a local OSS bundler (Alto) against anvil; self-funded and
   sponsored paths.
4. **Gas module**: a mock ERC-7677 server in CI (contract-level tests of the
   client, including fallback events); a manual smoke test against Pimlico's
   testnet endpoint stays out of CI.

CI grows one Node job beside the existing four (test, python, slither,
aderyn). Pinned toolchain, as everywhere else in the repo.

## 9. Security posture

- Zero new on-chain Solidity surface: `src/` does not change, the canonical
  code hash does not move, and no blob is invalidated by this phase. (The
  fixture-generation forge script is test tooling, not contract surface.)
- The SDK is the surface of the **second internal audit pass** (already a
  roadmap item): new code does not inherit the trust of reviewed code.
- Client-guidance rules become executable: pre-birth preflight, ROUTER in the
  signing step, raw-first reconciliation ordering, signature normalization.
- No secrets in the repo; provider keys via environment, and the relayer key is
  never read from or written to the working tree.

## 10. Out of scope (v0)

Advanced rotation / the update-channel client, Safe migration adapter,
ERC-7579 adapter, Circle provider, npm publication, any mainnet operation.
These are recorded, not lost: they queue behind v0 in the roadmap.

## 11. Open items this spec depends on

- Merge of `audit/phase3-internal` to `main` — this branch is cut from
  it, so the SDK work lands after it.
- Testnet redeploy at impl `0x21b5D576…` (waits on a funded
  `GLAUX_RELAYER_KEY`) — the SDK e2e against public testnets needs it; the
  anvil layers do not wait for it.
