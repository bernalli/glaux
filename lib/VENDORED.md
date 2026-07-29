# Vendored dependencies

These directories are verbatim copies of upstream sources, installed with
`forge install --no-git` and committed to this repository rather than tracked as
git submodules.

| Path | Upstream | Ref | Commit | Used for |
|---|---|---|---|---|
| `lib/forge-std` | https://github.com/foundry-rs/forge-std | `v1.16.2` | `bf647bd6046f2f7da30d0c2bf435e5c76a780c1b` | test framework (test-only) |
| `lib/account-abstraction` | https://github.com/eth-infinitism/account-abstraction | `v0.7.0` | `7af70c8993a6f42973f520ae0752386a5032abe7` | ERC-4337 interfaces; `EntryPoint` in tests |
| `lib/p256-verifier` | https://github.com/daimo-eth/p256-verifier | `master` | `607d3ec8377a3f59d65eca60d87dee8485d2ebcc` | `P256Verifier` etched at the precompile address in tests |
| `lib/openzeppelin-contracts` | https://github.com/OpenZeppelin/openzeppelin-contracts | `v5.0.2` | — | transitive dependency of `account-abstraction` (test-only) |

`lib/openzeppelin-contracts` exists solely because `account-abstraction`'s `EntryPoint`
and `BasePaymaster` import it (`^5.0.0` in their `package.json`). Glaux's own `src/`
imports nothing from OpenZeppelin, and must not: `src/` uses only the
`account-abstraction` *interfaces*, which have no OpenZeppelin dependency. This tree is
here so the tests can exercise the REAL EntryPoint and a real paymaster instead of a
mock.

## Why vendored instead of submodules

The development environment denies writes to `.gitmodules` and to the shared
`.git/config`, which makes submodule-based dependencies impossible to create or
to check out into the isolated worktrees used during implementation. Vendoring
keeps the dependency tree byte-identical to upstream while making every checkout
self-contained: no `git submodule update`, no network, reproducible offline
builds, and CI checkout without `submodules: recursive`.

## Verifying a vendored copy against upstream

```bash
git clone --depth 1 --branch <ref> <upstream> /tmp/verify
diff -r --exclude=.git /tmp/verify lib/<name>
```

## Local modification

Three paths were removed from `lib/p256-verifier`, none of them Solidity:

- `lib/` — the dependency's own development dependencies
  (`openzeppelin-contracts`, `forge-std`, `erc4626-tests`, ~10 MB). Nothing under
  it is reachable from this project's imports: only
  `p256-verifier/P256Verifier.sol` and its local `./P256.sol` are compiled.
- `.gitmodules` and `.vscode/` — inert here (the submodules they describe are
  gone), and both are file types the development environment refuses to write,
  which would make every fresh checkout fail.

Every upstream file that this project compiles is unmodified. No vendored file
was edited, and nothing was added beyond this note.
