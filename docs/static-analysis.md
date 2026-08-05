# Static analysis triage

Two analyzers run against this repository. Slither is the authoritative one and
gates CI; Aderyn is a second opinion with a different detector set, added
2026-07-30 after Semgrep was measured to catch one Solidity vulnerability class
in five. Slither's triage comes first, Aderyn's is the last section.

## Slither

Tool: Slither 0.11.6, configuration in `slither.config.json` (informational and
low findings are deliberately **not** excluded, so this document has to account
for every one of them). CI runs `crytic/slither-action` with `fail-on: high`.

Run it locally with:

```
slither src/ --config-file slither.config.json
```

Findings are triaged below. Nothing is suppressed without a reason written next
to the code it suppresses.

### Fixed

| Detector | Location | Resolution |
|---|---|---|
| `missing-zero-check` | `GlauxAccount` constructor | Fixed, not suppressed. Implementations are immutable and land at a deterministic CREATE2 address, so a zero EntryPoint would sit permanently at the canonical address with the entire ERC-4337 path dead. The constructor now reverts `ZeroEntryPoint()`; covered by `test_constructor_rejectsZeroEntryPoint`. |

### Suppressed in place, with justification

Each of these carries a `slither-disable-next-line` comment at the code, with the
reasoning inline. They are High-severity detectors firing on the patterns that
constitute the contract's purpose.

| Detector | Location | Why it is intentional |
|---|---|---|
| `arbitrary-send-eth` | `GlauxAccount._execute` | A smart account exists to send value where its owners direct. Every destination, value and calldata is bound into the digest that the 2-of-3 quorum signed; the contract never chooses a destination. |
| `calls-loop` | `GlauxAccount._execute` | Batching is a feature. A failing call reverts the whole batch (`CallFailed(index, revertData)`) rather than being silently skipped, so the loop cannot leave a partial batch applied. |
| `reentrancy-eth` | `GlauxAccount._execute` | The state written after the external calls *is* the reentrancy guard being released. `executing` is set before the loop and any re-entry reverts `ReentrantCall()`; the transient flag is the mitigation Slither is reporting as the bug. |
| `controlled-delegatecall` | `GlauxDelegate.initialize` | Delegatecall to a signed target is what a proxy is. The function id is a hardcoded literal, not input; the target is bound by the birth proof and by the code-hash and compatibility-marker checks performed immediately before. |

### Accepted, not suppressed

These remain visible in every run. They are below the CI gate and are recorded
here rather than silenced, so a future reviewer sees the same list we did.

- **`reentrancy-events`** (Low) — `Executed` and `Initialized` are emitted after
  external calls. The values they carry cannot change in between: the execution
  nonce is snapshotted before the calls on the direct path, and on the
  EntryPoint path re-entry into `_execute` reverts, so no nested batch can
  advance it. Event ordering, not state, is what the detector observes.
- **`assembly`** (Informational) — used for the namespaced storage and transient
  slots, the router's fallback, and revert-data bubbling. All are load-bearing and none can be expressed in high-level
  Solidity without changing semantics.
- **`low-level-calls`** (Informational) — the batch calls, the two
  `glauxCompatibilityId()` staticcalls, the birth delegatecall, and the ERC-4337
  prefund transfer. Each is deliberate and individually reviewed.
- **`naming-convention`** (Informational) — `ENTRYPOINT` is an immutable in
  upper case, which is the prevailing convention for immutables and constants.
- **`redundant-statements`** (Informational) — the discarded `ok` in
  `validateUserOp`. The prefund transfer's success is deliberately ignored
  because the EntryPoint verifies the resulting deposit itself and fails the
  operation there; reverting locally would be a worse failure mode.
- **`unindexed-event-address`** (Informational) — `Initialized(address)` is not
  indexed. Deliberate: cross-chain reconciliation reads the implementation
  pointer and its live code hash directly, which is authoritative, rather than
  filtering logs — so indexing would add bytecode to the permanent router without
  supporting any workflow the design actually relies on.

## Aderyn

Tool: Aderyn 0.6.8, pinned and gating in CI (see *CI wiring* below). Run it
locally with:

```
aderyn --src src --path-excludes lib,test,script -o report.json --highs-only
```

The first run against this repository (2026-07-30) produced **four High findings
and no Lows**. All four were triaged individually on 2026-07-31 against the code
they point at, and all four are false positives — three of them fire on the exact
constructs that make the design work, and the fourth describes a dust lock on a
contract that by construction never holds funds. None of them was archived as a
group; the reasoning for each is below, and each must be recorded at the code
with `// aderyn-fp-next-line` before the CI gate goes in, or the gate fails on day
one.

| Detector | Location | Verdict |
|---|---|---|
| `abi.encodePacked()` Hash Collision | `GlauxStorage.eip191`, `GlauxStorage.sol:84` | **False positive, and the suggested fix would be a breaking change.** Packed collisions need at least two *variable-length* operands; this call has none — `bytes1`, `bytes1`, `address`, `bytes32` are all fixed width and the result is always exactly 54 bytes, so no two distinct argument tuples can encode alike. The encoding is also not ours to choose: `0x19 ‖ 0x00 ‖ validator ‖ structHash` is the EIP-191 version `0x00` wire format. Moving to `abi.encode` would change every Glaux digest and invalidate every unspent birth and update blob. |
| Contract locks Ether without a withdraw function | `GlauxDelegate`, `GlauxDelegate.sol:17` | **False positive on the path that matters, accepted on the one that does not.** The router is reached by `delegatecall` through the account's EIP-7702 delegation, so `receive()` runs with `address(this)` set to the *account*: ETH sent to a Glaux account accrues to that account and is spendable through the 2-of-3 path. `receive()` is required for exactly that, and cannot be dropped — without it a plain transfer would fall into `fallback()` and delegatecall the implementation on a 2300-gas stipend. What remains true is that ETH sent *directly to the router's own deployed address* is stuck. Nothing in the design or the client tooling ever sends there, and the alternative is worse: a withdraw function on a contract documented «frozen forever: keep minimal» would add a permanent state-changing entry point that also exists on every delegated account. Accepted, not fixed. |
| Storage Array Edited with Memory | `GlauxAccount._applyUpdate`, `GlauxAccount.sol:206` | **False positive.** The detector fires on the shape — a storage reference handed to a `memory` parameter — without checking whether anything is written through it. `_isDuplicateSlot(FactorSlot memory, FactorSlot memory)` is `pure` and only compares; the copy it receives is meant to be a copy. The real write is the storage assignment two lines later, `l.slots[index] = s`, which does update state. The same shape appears on the birth path at line 75 and is read-only there too. |
| Yul block contains `return` | `GlauxDelegate.fallback`, `GlauxDelegate.sol:112` | **False positive: it is the mandatory proxy idiom.** Forwarding the delegatecall's raw returndata with `return(0, returndatasize())` — and halting there — is what a proxy fallback *is*; the detector's warning that nothing after it executes is the intended semantics, and there is nothing after it. The `revert(0, returndatasize())` on the failure branch is the same idiom for the mirror case. Expressing this in high-level Solidity is not possible without corrupting the returned data. |

### CI wiring — done (2026-07-31)

Aderyn **always exits 0**, verified in its own `driver.rs`: an exit-code gate would
be green forever, including on a run that found real bugs. So the gate is
`scripts/aderyn_gate.py`, which parses the report and fails on a non-empty
`high_issues.issues`.

It also fails **closed**. A missing, malformed, or unexpectedly shaped report exits
2, because an analysis that did not run is not the same as an analysis that found
nothing — and those two must never look alike to CI. That behaviour is covered by
`scripts/test_aderyn_gate.py`, which runs in the existing `python` job.

The four suppressions above landed first, each recorded at the code it describes
with `// aderyn-fp-next-line` and the reasoning beside it. Suppressing inside the
gate instead would have hidden them from anyone reading the source. Verified end to
end before the job was switched on: the pre-marker report (4 Highs) exits 1, the
current report exits 0, an absent report exits 2, and aderyn runs correctly against
a checkout with no `out/` — the state a fresh CI job is in.

The job pins aderyn to `aderyn-v0.6.8` by release URL and verifies the tarball
against `ffd6ca658962e211a3ac821c646f69c8e14bf1b1001cbfe091bcd4535a691e46`. The pin
is not ceremony: a floating version changes both the detector set and which of the
four suppressions still line up with a real finding, so a bump is a deliberate act
that re-runs this triage.

Slither stays the authoritative gate.

Note for a later pass: the `python` job installs `ruff` unpinned and the repository
carries no ruff configuration, so that lint gate is whatever the current release
defaults to on the day it runs. The code here is clean under a much broader
ruleset than those defaults, but the gate itself should be pinned and configured.

### What neither analyzer covers

«Owner without access control» has no dedicated detector in Slither or in Aderyn.
It stays manual review, which is consistent with what the security rules already
say about tracing the real call path before calling an unmodified function
vulnerable.
