# Static analysis — Slither triage

Tool: Slither 0.11.6, configuration in `slither.config.json` (informational and
low findings are deliberately **not** excluded, so this document has to account
for every one of them). CI runs `crytic/slither-action` with `fail-on: high`.

Run it locally with:

```
slither src/ --config-file slither.config.json
```

Findings are triaged below. Nothing is suppressed without a reason written next
to the code it suppresses.

## Fixed

| Detector | Location | Resolution |
|---|---|---|
| `missing-zero-check` | `GlauxAccount` constructor | Fixed, not suppressed. Implementations are immutable and land at a deterministic CREATE2 address, so a zero EntryPoint would sit permanently at the canonical address with the entire ERC-4337 path dead. The constructor now reverts `ZeroEntryPoint()`; covered by `test_constructor_rejectsZeroEntryPoint`. |

## Suppressed in place, with justification

Each of these carries a `slither-disable-next-line` comment at the code, with the
reasoning inline. They are High-severity detectors firing on the patterns that
constitute the contract's purpose.

| Detector | Location | Why it is intentional |
|---|---|---|
| `arbitrary-send-eth` | `GlauxAccount._execute` | A smart account exists to send value where its owners direct. Every destination, value and calldata is bound into the digest that the 2-of-3 quorum signed; the contract never chooses a destination. |
| `calls-loop` | `GlauxAccount._execute` | Batching is a feature. A failing call reverts the whole batch (`CallFailed(index, revertData)`) rather than being silently skipped, so the loop cannot leave a partial batch applied. |
| `reentrancy-eth` | `GlauxAccount._execute` | The state written after the external calls *is* the reentrancy guard being released. `executing` is set before the loop and any re-entry reverts `ReentrantCall()`; the transient flag is the mitigation Slither is reporting as the bug. |
| `controlled-delegatecall` | `GlauxDelegate.initialize` | Delegatecall to a signed target is what a proxy is. The function id is a hardcoded literal, not input; the target is bound by the birth signature and by the code-hash and compatibility-marker checks performed immediately before. |
| `reentrancy-no-eth` | `GlauxDelegate.initialize` | Same shape as the entry above: the state written after the delegatecall is the reentrancy guard being *released*. The flag is set before the untrusted initializer runs and any re-entry reverts `ReentrantCall()`. |

## Accepted, not suppressed

These remain visible in every run. They are below the CI gate and are recorded
here rather than silenced, so a future reviewer sees the same list we did.

- **`reentrancy-events`** (Low) — `Executed` and `Initialized` are emitted after
  external calls. The values they carry cannot change in between: the execution
  nonce is snapshotted before the calls on the direct path, and on the
  EntryPoint path re-entry into `_execute` reverts, so no nested batch can
  advance it. Event ordering, not state, is what the detector observes.
- **`assembly`** (Informational) — used for the namespaced storage pointer, the
  ERC-1967 slot reads and writes, the router's fallback, and revert-data
  bubbling. All are load-bearing and none can be expressed in high-level
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
  indexed. Deliberate: cross-chain reconciliation reads the ERC-1967 slot and
  its live code hash directly, which is authoritative, rather than filtering
  logs — so indexing would add bytecode to the permanent router without
  supporting any workflow the design actually relies on.
