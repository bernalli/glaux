# Glaux Phase 2 — account surface and reconciliation ordering

Status: approved 2026-07-29. Increment on top of `2026-07-28-glaux-design.md` (v0.5);
that document remains the protocol spec and this one only adds to it.

Two deliverables, independent in the code but shipped together because the second one
gets its first real exercise on the two-chain proof the first one forces us to redo:

1. the account surface a reference smart account is expected to have and Glaux does not
   have — ERC-721/ERC-1155 receiver hooks, ERC-165, ERC-1271;
2. the reconciliation **ordering**: raw storage first, getters only as a cross-check.

Both live entirely in the upgradeable implementation and in off-chain tooling. Not one
line changes in `GlauxDelegate`, and its runtime code hash is verified unchanged rather
than assumed.

## Part 1 — Account surface

### What is added

Five external functions on `GlauxAccount`, no fallback, no new state:

| Function | Returns |
|---|---|
| `onERC721Received(address,address,uint256,bytes)` | `0x150b7a02` |
| `onERC1155Received(address,address,uint256,uint256,bytes)` | `0xf23a6e61` |
| `onERC1155BatchReceived(address,address,uint256[],uint256[],bytes)` | `0xbc197c81` |
| `supportsInterface(bytes4)` | `true` for `0x01ffc9a7`, `0x150b7a02`, `0x4e2312e0`, `0x1626ba7e` |
| `isValidSignature(bytes32,bytes)` | `0x1626ba7e` on success, `0xffffffff` otherwise |

The three receiver hooks accept unconditionally and return their own selector. They read
no state, write none, and do not touch the reentrancy guard — deliberately, because the
common case is the account transferring a token and the token calling back into the
account while `_execute` is still on the stack. A hook that took the guard would make
`safeTransferFrom` from a Glaux account impossible, which is the opposite of the goal.

`supportsInterface` advertises ERC-1271 as well. ERC-165 discovery of ERC-1271 is not in
the standard, but some integrations probe for it and advertising it is free.

Interfaces are imported from the vendored OpenZeppelin tree (`@openzeppelin/contracts/`,
already remapped) so the selectors come from the canonical declarations rather than from
hand-written literals. Every value in the table above was confirmed with `cast sig`;
`0x4e2312e0` is `0xf23a6e61 ^ 0xbc197c81`.

### ERC-1271 digest

```
digest = eip191(address(this),
                keccak256(abi.encode(MSG_DOMAIN, block.chainid, address(this), hash, validUntil)))

MSG_DOMAIN = keccak256("GLAUX_MSG_V1")
           = 0x81b19556e5c48050cf054cad533961c2de5bc0bfcaa4f7cc36e73e4a9344c469
```

The `hash` argument is never verified directly. Three reasons, in order of weight.

**Cross-chain replay is a live hazard here, not a theoretical one.** A Glaux account has
the same address on every EVM chain by construction, and so do the protocols that consume
ERC-1271 signatures — Permit2 is at one address everywhere. Without `block.chainid` in the
digest, a message signature collected on one chain authorizes the identical action against
the identical address on every other chain the account has been born on. This is the point
where the sign-once/replay-many property must be broken on purpose: it belongs to birth and
update blobs, which must stay valid on chains not yet reached, and not to messages, which
are consumed once by a protocol that already exists on a specific chain. `EXEC_DOMAIN`
already binds `block.chainid` for the same reason.

**Cross-channel reuse.** A raw `hash` would make `isValidSignature` an oracle that reports
whether the quorum ever signed a given 32-byte value — including the digests of the exec,
update, userop and registration channels. Wrapping under a distinct domain constant means a
signature is valid on exactly the channel it was produced for, in both directions.

**Binding the validator.** The EIP-191 version `0x00` wrapper puts `address(this)` in front
of the struct hash, as on every other Glaux channel, so a digest computed for one account is
not a digest for another. It also keeps Glaux digests out of reach of raw-hash signing APIs.

### Deadline

```
signature = abi.encode(uint48 validUntil, SlotSig[2])
```

Identical in shape to the ERC-4337 signature blob, and validated the same way: bounded
length, then a `try/catch` decode, then `block.timestamp > validUntil` fails. `validUntil ==
0` is a deadline in the past like any other, consistent with the direct execution path.

The deadline is inside the digest, so a holder of the blob cannot widen the window they were
handed — changing the value invalidates both signatures.

This is a deliberate departure from the "flat" `SlotSig[2]` blob a reader might expect. The
blob is account-specific anyway (ERC-1271 leaves the format entirely to the account), so the
integration cost is one field, while the property bought is the one just closed on the other
two paths: no Glaux authorization is unbounded in time. It matters more here than anywhere
else, because a message signature can move funds without any on-chain Glaux operation — a
Permit2 witness is a transfer authorization.

The consequence to state plainly for integrators: an order meant to stay open for months
needs `validUntil` set months out. A Seaport listing signed with a short deadline stops
being fillable when the deadline passes, which is the intended behaviour and not a bug.

### Failure semantics

`isValidSignature` never reverts. Malformed blob, blob over the length bound, quorum not
met, repeated slot index, shared `(r,s)`, empty slots, deadline passed — all return
`0xffffffff`. A revert is handled by some consumers and not others; a sentinel is handled by
all of them. The decode goes through the existing external `decodeSlotSigs` helper under
`try/catch`, exactly as `validateUserOp` does, so attacker-supplied bytes cannot turn into a
revert. The length bound is the one the 4337 path already uses, renamed from
`MAX_USEROP_SIGNATURE_LENGTH` to `MAX_SIGNATURE_BLOB_LENGTH` and shared by both paths, since
the two blobs have the same shape; the value does not change.

One case is outside this function's reach and must be stated rather than glossed: an account
that has **not** been born has no implementation pointer, so the router's fallback reverts
`NotInitialized` before any implementation code runs. No return value is possible there. In
practice consumers that treat a reverting `isValidSignature` as invalid — the OpenZeppelin
signature checker among them — behave correctly; the guarantee Glaux gives is that once the
account exists, no input produces a revert.

The quorum check is the existing `_checkTwoSigs`, unchanged: distinct slot indices, distinct
`(r,s)`, `initialized` set, both signatures verified against the installed slots. ERC-1271
therefore inherits the possession-proof guarantee at no extra cost.

### New residual

**With ERC-1271 live, `execNonce` is no longer a complete record of authorized value
movement.** The quorum can authorize a Permit2 transfer, a Seaport fill, or any other
signature-consuming protocol without a single Glaux nonce advancing and without any on-chain
trace before the signature is consumed by someone else. The deadline bounds the window; it
does not restore the record. Clients must treat a request to sign a message as a request to
authorize an action, and must never present it as harmless.

This goes in the threat model, and the two "Not implemented in v1" entries come out of it.

### Deliberately not done

No signature aggregation, no session keys, no delegated signer, no ERC-7579 module surface,
no `isValidSignature` variant that accepts a single factor. The threshold is 2-of-3 on every
operation, including this one.

## Part 2 — Reconciliation ordering

### The problem

`docs/client-guidance.md` already tells a client to read the implementation pointer with
`eth_getStorageAt` rather than trusting the ERC-1967 slot. What it does not say is that the
same reasoning applies to *everything else*: `getSlot`, `updateNonce`, `execNonce` and
`implementation()` are all answered by the implementation whose identity is the thing under
verification. An implementation that is hostile, or merely an unexpected build, can report a
nonce and a slot set that do not exist in storage — and reconciliation, whose whole purpose
is detecting that two chains diverge, would compare two sets of claims instead of two sets of
facts.

The reason clients would trust the getters anyway is practical, not lazy: decoding
`FactorSlot[3]` out of namespaced storage by hand is fiddly, and nothing in the repo does it.
So the fix is a tool, not a paragraph.

### Normative order

1. `eth_getCode(account)` — expect exactly the EIP-7702 designator, `0xef0100 ‖ router`
   (23 bytes). Anything else, including empty code, means the account is not a Glaux account
   on this chain, and nothing below is meaningful.
2. `eth_getStorageAt(account, IMPL_SLOT)` — the authoritative implementation pointer.
   `IMPL_SLOT = keccak256("glaux.account.v1.implementation")` =
   `0xecc57c70703ae87295636d5bf51ab33d95ad479d00483a780fa66c4613e2f3b8`.
   The ERC-1967 slot is neither read nor compared: Glaux never writes it and on a migrated
   account it may still hold a stale foreign value.
3. `eth_getCode(implementation)` → `keccak256` — the live code hash of the logic actually
   installed. Two chains can agree on nonce, slots and pointer and still run different code.
4. Raw account state from the namespaced layout: the packed header word, then the three
   factor slots including their `bytes` payloads.
5. **Only now** the getters — `updateNonce()`, `execNonce()`, `getSlot(i)`,
   `implementation()`, `glauxCompatibilityId()` — and only to be compared against steps 2-4.
   A mismatch is a finding about the implementation, reported as such. It is never resolved
   in favour of the getter.

### Storage layout

`BASE = keccak256("glaux.account.v1.storage")` =
`0xc645ef19799bcce32b2c21e3256a200e9914fa1c588f704be7391b93be01ae7f`.

| Slot | Contents |
|---|---|
| `BASE + 0` | packed: `initialized` (byte 0), `updateNonce` (bytes 1-8), `execNonce` (bytes 9-16) |
| `BASE + 1 + 2i` | `slots[i].verifierType` |
| `BASE + 2 + 2i` | `slots[i].data` — `bytes` header |

`bytes` follows the standard Solidity encoding: length ≤ 31 stores the payload left-aligned
in the same word with `2 * length` in the lowest byte; length ≥ 32 stores `2 * length + 1`
in the word and the payload from `keccak256(dataSlot)` onward. Both shapes occur in
practice — a secp256k1 slot holds `abi.encode(address)`, 32 bytes, so it is already the long
form with one payload word; a P-256 slot holds `abi.encode(qx, qy)`, 64 bytes, two payload
words.

This table is a derivation, and a derivation is exactly what silently drifts from the
compiler's actual choices. It is therefore not the source of truth: the parity test below is,
and the table is corrected to match it if they disagree.

### Tool

`scripts/reconcile.py`:

```
python scripts/reconcile.py --account 0xACCT --rpc sepolia=$URL --rpc base-sepolia=$URL2
                            [--router 0xROUTER] [--json]
```

Per chain it performs steps 1-5 in that order and prints a row per chain: designator status
and observed router, implementation pointer, live code hash, `initialized`, `updateNonce`,
`execNonce`, the three decoded slots, and the raw-vs-getter verdict. With `--router` the
observed router is checked against the expected one; without it, the routers are compared
across chains. A chain where the account has no code is reported as "not yet active", which
is a state and not a conflict.

Exit codes: `0` all chains consistent, `1` divergence between chains, `2` raw storage and
getters disagree on at least one chain, `3` a chain could not be read at all. `2` outranks
`1`: an implementation that misreports its own state invalidates any comparison built on its
answers. `3` is outside that ordering entirely: an RPC transport failure never executed
on-chain, so it is unknown state rather than evidence about the implementation, and it is
never folded into a verdict.

### Parity vectors

The offsets above are implemented twice — once by the compiler, once by the Python decoder —
which is the failure class this repo is most exposed to. So a Foundry test drives an account
into a known state (both verifier types installed, a rotation applied so the nonce is
non-zero), reads back every slot with `vm.load`, and writes a committed fixture of
`(slot, value)` pairs plus the expected decoded values. A pytest reads the same fixture,
recomputes each slot from the constants, decodes each value with the production decoder, and
asserts equality. Either side changing alone turns the fixture red.

This requires a Python job in CI — `ruff` plus `pytest` over `scripts/` — which does not
exist today: the off-chain tooling has never been in CI at all, in a repo where the Python
side signs the blobs.

## Bytecode and deployment consequences

Adding functions changes `GlauxAccount`'s bytecode, therefore its canonical CREATE2 address
and the runtime code hash every birth blob signs. The two-chain local proof is regenerated
from scratch and the tables in `docs/deployments.md` are rewritten, as on every previous
contract change.

`GlauxDelegate` must not move. Its bytecode contains no reference to the new code, and
`bytecode_hash = "none"` means no metadata hash carries source-file changes into it, so the
expectation is a byte-identical router — verified by comparing its runtime code hash before
and after, not assumed. If the router's hash moves, that is a stop-and-investigate event:
it would mean an unspent birth blob pointing at the old router address is stranded.

`foundry.toml` is not touched. `bytecode_hash`, `evm_version` and `optimizer_runs` all
participate in the canonical address and are out of scope here.

## Testing

Every control gets the negative test that proves the control is what stops the attack, per
the project's red-then-green rule.

ERC-1271:

- an exec-channel signature pair, replayed as a message signature for the same inner hash,
  is rejected — and the reverse, a message signature offered to `executeWithSigs`;
- a message signature valid on one chain id is rejected under another (`vm.chainId`);
- expired deadline rejected; `validUntil == 0` rejected; a deadline in the future accepted;
- rewriting `validUntil` in the blob invalidates the signatures;
- garbage bytes, truncated blob, and an over-length blob all return `0xffffffff` and do not
  revert;
- repeated slot index rejected; shared `(r,s)` rejected; one valid signature alone rejected;
- a born account with empty slots returns `0xffffffff`; an account not yet born reverts
  `NotInitialized` at the router, and the test pins that boundary so it stays a known
  property rather than a surprise;
- both verifier types work as either signer, including a P-256 factor.

Receiver hooks:

- a real vendored OpenZeppelin ERC-721 `safeTransferFrom` into the account succeeds, and an
  ERC-1155 single and batch transfer succeed;
- the hooks are callable while `_execute` is on the stack: the account transfers a token out
  in a batch and the token calls back in, and the batch does not revert `ReentrantCall`;
- `supportsInterface` returns true for the four ids and false for `0xffffffff` and for an
  unrelated id.

Reconciliation:

- the parity fixture, from both sides;
- both `bytes` shapes decoded (32-byte secp256k1 payload, 64-byte P-256 payload);
- a chain with no code reported as "not yet active" and not as a conflict;
- exit code `2` when the getters are made to disagree with storage — driven by a mock
  implementation that lies about `updateNonce`, which is the scenario the ordering exists for.

The suite baseline is 180 passing, 2 skipped, and must not drop.

## Documents to update

- `threat-model.md` — the two scope entries removed, the `execNonce` residual added.
- `client-guidance.md` — the reconciliation ordering as normative steps, the ERC-1271 blob
  in the wire formats section, and the rule that signing a message is authorizing an action.
- `deployments.md` — regenerated addresses, code hash, and two-chain proof.
- `specs/2026-07-28-glaux-design.md` — a pointer to this document.
- `development.md` — the new Python CI job, once it exists.
