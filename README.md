# Glaux

*Glaux (γλαύξ) — the little owl the Athenians stamped on their silver
tetradrachms to guard the coin.*

Minimal, crypto-agile **EIP-7702 smart account**: one address on every EVM
chain by construction, 2-of-3 threshold security on the operational path, and
a replaceable verification slot, so the factors that authorize an operation
can adopt new signature schemes without migrating funds.

> ## ⚠️ Unaudited — do not use with real funds
>
> Glaux is a reference implementation. It has been through two internal
> adversarial review passes by independent reviewers working blind to each
> other ([2026-08-03](docs/internal-audit-2026-08-03.md),
> [2026-08-04](docs/internal-audit-2026-08-04-phase4.md) — findings, fixes and
> open residuals are all on record), but **no independent third-party security
> audit has been performed**. The threat model
> [declares its residuals openly](docs/threat-model.md).
> Every account born on the public testnets uses publicly known test keys and
> is controllable by anyone.

## Why it exists

Smart accounts today buy their security with an address problem. A
contract wallet lives where a factory deployed it: reaching the same address
on a new chain means a counterfactual deployment that someone must execute,
parameters that must never drift, and a factory that must exist there at all.
A plain EOA has the opposite trade — the same address everywhere, secured by
exactly one key, forever, with no way to rotate it.

EIP-7702 makes a third shape possible, and Glaux is a deliberately minimal
take on it: the account **is** an EOA — same address on every chain, no
factories, nothing counterfactual — delegated to an immutable router that
enforces 2-of-3 verification over three independent factors (device P-256 /
Secure Enclave via the native precompiles, plus two secp256k1 keys). One
**birth blob** replays on any chain, whenever that chain is first touched —
nothing signs it, because a rootless birth has no key to sign with; one signed
rotation replays the same way. Verification lives in a
replaceable slot, so the factor layer can adopt new signature schemes without
moving funds or changing address: today it verifies secp256k1 and P-256, and
the slot is the designed migration path for schemes that become verifiable
on-chain later, post-quantum ones included.

Birth is **rootless**: no key for the account is generated at any point. The
EIP-7702 authorization tuple is crafted so that its `r` is a hash commitment to
the account's own birth configuration, and the address is whoever `ecrecover`
returns for it. Forging that with a real key would mean inverting the discrete
log, so a born Glaux account is provably one whose private key nobody has ever
held — the property [EIP-8164](https://eips.ethereum.org/EIPS/eip-8164) names as
a goal for protocol-level rootless accounts, obtained here without waiting for
it. The price is that the delegation can never be revoked or repointed, by
anyone.

That agility stops at the factor layer, and the distinction matters. The
account *is* an EOA, so its EIP-7702 delegation stays under a secp256k1
authority no rotation can replace, and the account's public key is recoverable
from the authorization tuple of every birth. An adversary who breaks secp256k1
therefore bypasses the factors entirely, whatever they have been rotated to, and
rootlessness does not help: the key nobody holds is still computable by whoever
breaks the curve. Closing that requires a change at the protocol layer or moving
the assets to a new account. Residual 1 of the
[threat model](docs/threat-model.md) states this in full, alongside the residuals
the project has decided to accept rather than fix.

## The cross-chain proof

The claim the design rests on — one blob, every chain, same account — is
demonstrated on public networks, not argued. One birth blob was submitted
unmodified to two independent testnets. It produced **the same account, with the
same three factors, at the same address, for the same gas to the unit**:

| | Sepolia (11155111) | Base Sepolia (84532) |
|---|---|---|
| deploy tx | [`0xbdff134f…`](https://sepolia.etherscan.io/tx/0xbdff134f87d19f4a47ba048c581e527a5b0fb61a5684f3d2e1d99964c8af360c) | [`0x218f2543…`](https://sepolia.basescan.org/tx/0x218f254321d7df1c577daed581123038ea099d771f55ea668151379052d1b1e7) |
| deploy gas | 561,297 | 561,297 |
| birth tx (EIP-7702, type 4) | [`0x728a69d5…`](https://sepolia.etherscan.io/tx/0x728a69d5fa748d42a21afd9de5bc7a930dd4902bf868b08464b22a787eae2ebd) | [`0x2519eba9…`](https://sepolia.basescan.org/tx/0x2519eba9539c1dc26bd55404de09b41dad291c5865a9cacf137d71025bab98b5) |
| birth gas | 375,598 | 375,598 |
| born account | [`0xF6C08eCe…`](https://sepolia.etherscan.io/address/0xF6C08eCe382A0007c93748693b6E900a21a6258a) | [`0xF6C08eCe…`](https://sepolia.basescan.org/address/0xF6C08eCe382A0007c93748693b6E900a21a6258a) |

| Artifact of that run | Value (identical on both chains) |
|---|---|
| `GlauxAccount` (implementation) | `0x21b5D576AB4188Ee06DD866b6Fd4a23085A73f5d` |
| `GlauxDelegate` (router) | `0x3ccF1cc0F702C084B31e691e057d8742ADF35790` |
| implementation runtime code hash | `0xb32d638ed9bd6329b5b2f27e9dcaa3a9fc65f396315f67eef276cd6f89ac9106` |

The deploy line covers the router alone: the implementation was already on both
chains at that address, so the deterministic deploy script created only what was
missing.

The mechanism is a `chainId 0` authorization tuple: EIP-7702 burns the
authority's nonce only on the chain that applies it, so the same blob stays
valid on every chain not yet reached — nothing in it expires, and a third
chain can still be reached with it today. Read back afterwards, the two
chains are indistinguishable: same delegation indicator, same factor slots
byte for byte, and the raw-first reconciliation tool reports
`verdict: consistent` across both. The full run is in
[`docs/deployments.md`](docs/deployments.md), together with the two-chain proof
run locally at every bytecode change — which additionally exercises a live
refusal on a chain that cannot verify P-256, something no public testnet
offers, since both verify it.

**This account was born rootless, and no key was ever created for it.** There is
no birth key to hold or destroy: the authorization tuple is crafted rather than
signed — its `r` commits to the factor configuration — and the account is simply
the address that tuple recovers to. Nobody can birth it into a different
configuration, which is the property the earlier ephemeral birth key had to be
trusted to give up. An earlier generation of accounts, born under the previous
router `0xB8270e4B…` before that change, is still delegated to it and still
works; those runs are kept in
[`docs/deployments.md`](docs/deployments.md) rather than rewritten.

## What is here

- **`src/`** — the contracts: `GlauxDelegate`, the immutable router every
  account delegates to (frozen forever, kept minimal), and `GlauxAccount`,
  the upgradeable implementation behind it: threshold verification, the
  sign-once/replay-many update channel, direct execution with deadlines, and
  an ERC-4337 path. ERC-165/721/1155/1271 surface included.
- **`sdk/`** — a TypeScript SDK (strict, on viem): factor signers, birth,
  execution, ERC-7677 gas sponsorship, chain-eligibility checks, and a port
  of the reconciliation tool that must agree with the Python one verdict for
  verdict.
- **`scripts/`** — the Python tooling that signs what the contracts verify:
  birth blob generation, possession proofs, permissionless submission, and
  raw-first cross-chain reconciliation.
- **`test/`** — unit, property and invariant suites, plus parity fixtures
  that pin Solidity, Python and TypeScript to the same bytes.

CI gates every push: build, tests, `forge fmt`, Slither and Aderyn on the
contracts, lint + tests for the Python tooling, strict typecheck + tests for
the SDK. Dependencies are vendored under `lib/` (see `lib/VENDORED.md`), so a
fresh checkout needs no dependency fetching — Foundry still downloads the
pinned solc on the first build.

## Documentation

Read in this order:

| Document | What it is |
|---|---|
| [`docs/specs/2026-07-28-glaux-design.md`](docs/specs/2026-07-28-glaux-design.md) | The design specification (v0.9), with its full revision history |
| [`docs/threat-model.md`](docs/threat-model.md) | What is protected, against whom, the residuals the project declares openly, and the three it has [accepted rather than fixed](docs/threat-model.md#accepted-residuals) |
| [`docs/client-guidance.md`](docs/client-guidance.md) | **Required reading before integrating**: several residuals are closed only by a client-side rule |
| [`docs/internal-audit-2026-08-03.md`](docs/internal-audit-2026-08-03.md) | First internal audit (contracts): findings, reproductions, fixes |
| [`docs/internal-audit-2026-08-04-phase4.md`](docs/internal-audit-2026-08-04-phase4.md) | Second internal audit (client code): findings, fixes, open residuals |
| [`docs/static-analysis.md`](docs/static-analysis.md) | Slither/Aderyn triage — every finding fixed, suppressed with reasoning, or accounted for |
| [`docs/deployments.md`](docs/deployments.md) | Deterministic addresses, the end-to-end birth proofs, and the cross-chain replay |
| [`docs/development.md`](docs/development.md) | Commands, layout, CI, and the constraints that are not negotiable |

## Build and test

```bash
forge build
forge test
```

The Python tooling and the TypeScript SDK have their own commands and one
non-obvious prerequisite each — see
[`docs/development.md`](docs/development.md).

## Non-goals

No backend, no custody, no privileged relayer: everything verifies on-chain
or client-side, and every submission path is permissionless.

## Author

Samuele Martinalli ([@bernalli](https://github.com/bernalli)) — <bernalli@proton.me>

## License

MIT — see [`LICENSE`](LICENSE).
