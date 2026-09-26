# Vendored dependencies

These directories are verbatim copies of upstream sources, installed with
`forge install --no-git` and committed to this repository rather than tracked as
git submodules.

| Path | Upstream | Ref | Commit | Used for |
|---|---|---|---|---|
| `lib/forge-std` | https://github.com/foundry-rs/forge-std | `v1.16.2` | `bf647bd6046f2f7da30d0c2bf435e5c76a780c1b` | test framework (test-only) |
| `lib/account-abstraction` | https://github.com/eth-infinitism/account-abstraction | `v0.7.0` | `7af70c8993a6f42973f520ae0752386a5032abe7` | ERC-4337 interfaces; `EntryPoint` in tests |
| `lib/p256-verifier` | https://github.com/daimo-eth/p256-verifier | `master` | `607d3ec8377a3f59d65eca60d87dee8485d2ebcc` | `P256Verifier` etched at the precompile address in tests |
| `lib/openzeppelin-contracts` | https://github.com/OpenZeppelin/openzeppelin-contracts | `v5.0.2` | — | ERC-165/721/1155/1271 interfaces imported by `src/`; transitive dependency of `account-abstraction` in tests |

`lib/openzeppelin-contracts` (MIT) serves two purposes. It provides the four interfaces
that Glaux's own `src/` imports through the `@openzeppelin/contracts/` remapping
(`IERC165`, `IERC721Receiver`, `IERC1155Receiver`, `IERC1271`), and it is imported by
`account-abstraction`'s `EntryPoint` and `BasePaymaster` in the tests (`^5.0.0` in their
`package.json`). `src/` uses nothing from `account-abstraction`: the ERC-4337
`PackedUserOperation` struct it needs is its own MIT copy in
`src/interfaces/PackedUserOperation.sol`. The `account-abstraction` tree is here so the
tests can exercise the REAL EntryPoint and a real paymaster instead of a mock.

## Why vendored instead of submodules

Vendoring keeps the dependency tree byte-identical to upstream while making every
checkout self-contained: no `git submodule update`, no network, reproducible
offline builds, and CI checkout without `submodules: recursive`. A submodule
graph would put each dependency's availability and history behind a second
fetch that a fresh clone has to get right before anything compiles.

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
- `.gitmodules` and `.vscode/` — inert here: the submodules the first describes
  are gone with the directory above, and the second is editor configuration for
  a different project.

Every upstream file that this project compiles is unmodified. No vendored file
was edited, and nothing was added beyond this note.

## Licensing of vendored code

- `lib/account-abstraction` is GPL-3.0 (some files LGPL-3.0) and is used only by tests
  and test tooling: nothing under `src/` imports it, it is never deployed and never
  shipped inside any application, and CI fails if `src/` imports it. `src/` defines its
  own MIT copy of the ERC-4337 `PackedUserOperation` struct in
  `src/interfaces/PackedUserOperation.sol`.
- `lib/forge-std` (MIT/Apache-2.0) and `lib/p256-verifier` (MIT) are test-only.
- `lib/openzeppelin-contracts` is MIT.
