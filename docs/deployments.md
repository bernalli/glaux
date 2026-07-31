# Deployments

## Local two-chain end-to-end (verified)

Date: 2026-07-30. Contracts: the Phase 2 account surface (ERC-721/1155 receiver hooks,
ERC-165, ERC-1271) on top of the verifier probe and execution deadlines. The whole run
below is repeated from scratch each time the contracts change: changing them changes
their bytecode, and therefore every deterministic address and code hash recorded here.

`GlauxDelegate` keeps the same address across these re-runs while `GlauxAccount` moves,
which is the expected signal rather than a coincidence: the router is the immutable half
and Phase 2 has not touched it. Every change so far has landed in the implementation.
Before this run the router's build was checked directly:
`cast keccak "$(forge inspect src/GlauxDelegate.sol:GlauxDelegate deployedBytecode)"`
gives `0x6f90a8ec1d718d787bb3a3cdf0887caf750f65958a2b6e9cfef3cf103da8335c`, and the
CREATE2 address below matching every previous run is the on-chain form of the same
proof — same salt + same initcode is the only way to land on the same address.

Two local `anvil` instances with EIP-7702 (Prague) support, on different chain ids:

```
anvil --port 8545 --chain-id 31337 --hardfork prague
anvil --port 8546 --chain-id 31338 --hardfork prague
```

### 1. Deterministic deployment (CREATE2, salt `keccak256("glaux.v1")`)

`forge script script/Deploy.s.sol:Deploy --broadcast` against both RPCs, funded with anvil's
default account 0 (`0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266`).

| Chain id | GlauxAccount (impl)                          | GlauxDelegate (router)                       |
|----------|-----------------------------------------------|-----------------------------------------------|
| 31337    | `0x927ed5700518a8A053367da1EaFDFBdE061E73F2`  | `0xB8270e4B9aaeA6933716409Bb648FB3Cda3CCbE9`  |
| 31338    | `0x927ed5700518a8A053367da1EaFDFBdE061E73F2`  | `0xB8270e4B9aaeA6933716409Bb648FB3Cda3CCbE9`  |

**Addresses are identical on both chains** — the CREATE2 determinism claim, confirmed by
running the same salted-bytecode deployment through the canonical CREATE2 deployer
(`0x4e59b44847b379578588920cA78FbF26c0B4956C`) on two independent chains. The router's
address is unchanged from every previous run (immutability check passed); the
implementation moved from `0x6E7210C5…57ae3`, as adding the account surface must make it.

Implementation runtime code hash (`address(impl).codehash`, printed by `Deploy.s.sol`):

```
0x2c271f5a9e823360ad27431f2245570417fc1dc687b144eda63f8bf875b97c4c
```

### 2. Birth blob (one blob, generated once)

Each factor first produced a **possession proof** with `scripts/prove_possession.py`,
run separately per key — the contract refuses to install a key that has not signed the
registration challenge. Both anvil instances were given a P-256 verifier at `0x100`
(`anvil_setCode` with the vendored daimo implementation, code hash
`0x861fcab33b8882c3e9d109fdeaf29d2c8b62a06079561b1c0b106c1ce04575f4`), because both the
device factor's proof and the installation probe need it; a chain without a working
verifier cannot host a P-256 factor at all, and birth there is refused rather than
producing an unusable one — demonstrated live in §5.

Generated with `scripts/birth.py` using throwaway factor keys: the paper and cloud secp256k1
factors are anvil's well-known default accounts 1 and 2
(`0x7099...79C8`, `0x3C44...93BC`), and the device P-256 factor is the anchored test vector
from `test/P256Fixture.sol`. These are public test keys with no value — never reuse this
configuration for a real account. The ephemeral birth key existed only in the Python process
memory and was discarded on exit; it was never written to disk or logged.

Born account address (recovered from the EIP-7702 authorization signed by the birth key):

```
0x5b4c472093C0fa61158b68C6f378cb02b500c405
```

### 3. Submission — the SAME blob to BOTH chains

`scripts/submit_birth.py` submitted the identical JSON blob to each chain, relayed by anvil's
default account 0 acting as an ordinary, unprivileged relayer (`GLAUX_RELAYER_KEY`):

| Chain id | Tx hash                                                              | Status | Gas used |
|----------|-----------------------------------------------------------------------|--------|----------|
| 31337    | `0x10cdc0044223ef2caa91635521f22b723beac3a512ba2111040cebc707eeb66e`  | 1      | 1345155  |
| 31338    | `0xe7454f799267f6a003778c80ea136e9746c2b5f6014ebad793580f69cbb16449`  | 1      | 1345155  |

Both transactions succeeded (status 1) with identical gas usage.

Birth cost 687,651 gas before the probe and ~1.35M after, but almost none of that
difference is the probe's price on a real chain. These anvil instances answer P-256 with
the vendored **Solidity** verifier, which costs on the order of 330k gas per
verification, and the probe makes two calls; where `0x100` is the actual precompile the
same two calls cost what that chain charges for `P256VERIFY` — thousands of gas, not
hundreds of thousands. The figure above is the pessimistic end of the range, and it is
paid once, at birth or at rotation, never on the signing path.

Submitting this blob also exposed a latent bug in `scripts/submit_birth.py`, now fixed:
it estimated gas for a call to the account *without* the authorization list, and the
delegation and the call ride in the same transaction — so on a chain where the account
was not already delegated the node priced a plain EOA call (~47k), the script sent a
transaction with a limit near 171k, and birth ran out of gas mid-flight. The estimate now
carries the authorization list, and an implausibly cheap answer is treated as a node that
ignored it rather than as a cheap birth.

### 4. Post-birth verification — identical on BOTH chains

```
cast code 0x5b4c472093C0fa61158b68C6f378cb02b500c405 --rpc-url <rpc>
  -> 0xef0100b8270e4b9aaea6933716409bb648fb3cda3ccbe9   (EIP-7702 delegation indicator to the router)

cast call <account> "updateNonce()(uint64)" --rpc-url <rpc>
  -> 0

cast call <account> "getSlot(uint8)(uint8,bytes)" 0 --rpc-url <rpc>
  -> 1, 0x...70997970c51812dc3a010c7d01b50e0d17dc79c8   (secp256k1 paper factor)

cast call <account> "getSlot(uint8)(uint8,bytes)" 1 --rpc-url <rpc>
  -> 2, 0xc9b91be2...b7de6f                                (P-256 device factor, qx||qy)

cast call <account> "getSlot(uint8)(uint8,bytes)" 2 --rpc-url <rpc>
  -> 1, 0x...3c44cdddb6a900fa2b585dd299e03d12fa4293bc   (secp256k1 cloud factor)

# The pointer lives in Glaux's own namespaced slot. The shared ERC-1967 slot is
# left untouched, so nothing is exported to whatever wallet the account is
# re-delegated to next.
cast call <account> "implementation()(address)" --rpc-url <rpc>
  -> 0x927ed5700518a8A053367da1EaFDFBdE061E73F2
cast storage <account> 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc --rpc-url <rpc>
  -> 0x0000...0000   (ERC-1967: never written by Glaux)
```

Every one of these checks returned byte-for-byte identical output on chain id 31337 and chain
id 31338: one authorization tuple, one init blob, two different chain ids, same account
address, same configuration. That is the specification's chain-agnostic replay claim,
demonstrated live rather than assumed.

### 4b. The Phase 2 surface, exercised on the born account

ERC-165 answers on both chains: `supportsInterface` is `true` for `0x1626ba7e`
(ERC-1271) and `0x150b7a02` (ERC-721 receiver), `false` for `0xffffffff` as the
standard requires.

ERC-1271, with a real 2-of-3 blob (paper + cloud factors signing the wrapped digest
for chain id 31337):

```
cast call <account> "isValidSignature(bytes32,bytes)(bytes4)" <hash> <blob> --rpc-url http://127.0.0.1:8545
  -> 0x1626ba7e   (the chain the signature was produced for)

cast call <account> "isValidSignature(bytes32,bytes)(bytes4)" <hash> <blob> --rpc-url http://127.0.0.1:8546
  -> 0xffffffff   (the SAME signature on the other chain: rejected)
```

The second line is the chain binding doing its job on a live chain, not in a unit
test: same account address, same blob, different `block.chainid`, sentinel.

`scripts/reconcile.py` — its first real multi-chain run — read both chains raw-first
(designator, `IMPL_SLOT`, live code hash at the pointer, packed header, three factor
slots, then the getters as cross-check) and reported both consistent, exit 0, with
the raw side and the getters agreeing on every field.

### 5. Refusal on a chain that cannot verify P-256

The same run, with the verifier removed from chain 31338 only
(`anvil_setCode 0x0000000000000000000000000000000000000100 0x`) and a fresh birth blob
carrying the same three factors — one of them the P-256 device key:

```
python3 scripts/submit_birth.py --rpc http://127.0.0.1:8546 --blob blob.json
  -> status 0, gas used 72699   (candidate account 0x3CAb8361F4b3dCcD474A62935488BF16c2762936)

cast call <candidate> "getSlot(uint8)(uint8,bytes)" 0
  -> execution reverted: custom error 0x87138d5c   (NotInitialized — nothing was installed)
```

`scripts/reconcile.py` pointed at the half-born candidate shows why the raw-first
order exists: the raw side reads the truth directly — pointer zero, `initialized`
false, empty slots — while every getter reverts (`NotInitialized` through the router
fallback), and the tool reports the disagreement and exits 2. An account state that
the getters cannot describe at all is still fully legible from storage.

The account is not configured on that chain: no slots, implementation pointer still
zero (`cast storage <candidate> $(cast keccak 'glaux.account.v1.implementation')` reads
`0x0…0`), 72k gas spent instead of a stranded 2-of-3 that can never reach its own
threshold. What *did* land is the delegation itself — `cast code` reads
`0xef0100b8270e…`, and the account nonce moved to 1 — because an EIP-7702 authorization
is applied before the call it accompanies and survives the call reverting. That spends
the tuple, not the birth: the router is already installed, so if the chain later gains a
working verifier the same init blob completes the birth through a plain `initialize`
call, with no new authorization to sign. Chain 31337, which kept its verifier, was
unaffected — the same blob, the same factors, two different answers, each correct for
its chain.

## Public testnet: preconditions verified, broadcast NOT DONE

Date: 2026-07-29. No transaction has been broadcast to Sepolia or Base Sepolia. The
local two-chain run above remains the only end-to-end evidence. What follows is
everything about those two networks that could be checked *without* spending anything —
all of it read-only — so that the one remaining blocker is isolated and the first real
deployment has no open questions left in front of it.

### The P-256 precompile is live on both, and this was the open question

Birth carrying a P-256 device factor probes `0x100` and reverts `P256VerifierUnavailable`
rather than producing an account that can never reach its own threshold. Until now that
probe had only ever met the vendored Solidity verifier etched onto anvil, never a real
precompile, so whether the target chains could host the device factor at all was unknown.
They can. Both arms of `p256VerifierAvailable()` answer correctly on both networks:

| Chain (id)              | valid signature | same signature, `digest ^ 1` | probe verdict |
|-------------------------|-----------------|------------------------------|---------------|
| Sepolia (11155111)      | `0x…01`         | `0x` (empty)                 | installable   |
| Base Sepolia (84532)    | `0x…01`         | `0x` (empty)                 | installable   |

Sepolia has it via **EIP-7951**, which shipped in Fusaka and activated there on
2025-10-14; Base Sepolia via **RIP-7212**, added in Fjord. The two price it differently:
6900 gas per verification under EIP-7951, 3450 under RIP-7212, against the ~330k the
Solidity stand-in charges on anvil. The probe makes two such calls, so on a real chain
it costs roughly 14k on Sepolia and 7k on Base Sepolia plus the surrounding call and
memory gas — not a figure to quote precisely until a real birth is measured, but three
orders of magnitude away from the anvil run either way. The 1,356,339-gas birth recorded
above is therefore the pessimistic end of the range and is not what these networks will
bill. The probe runs once per P-256 slot installation — at birth and at rotation — never
on the signing path.

Verified two independent ways. First, `eth_call` to `0x100` executed by the nodes
themselves, agreeing across three unrelated providers (`ethereum-sepolia-rpc.publicnode.com`,
`1rpc.io/sepolia`, `sepolia.base.org` / `base-sepolia-rpc.publicnode.com`) — so the answer
is not one endpoint's quirk. Second, `test/P256ForkProbe.t.sol`, which forks each chain
and runs the shipped `SignatureVerify.p256VerifierAvailable()` against it, unchanged. That
test is skipped unless `GLAUX_RPC_*` is set and **must** be run with `--evm-version osaka`:
a fork supplies the chain's state while calls still execute in the local EVM at the
configured spec, and this repo builds for `prague`, which predates EIP-7951 — under it
`0x100` is not a precompile and every chain looks broken. Without the flag the test fails
against healthy chains, which is how this was found.

The flag does not reach the compiler, and that is precisely why it is safe. `foundry.toml`
pins `src`/`script` to solc 0.8.28, which has no `osaka` target, so Foundry clamps the
compiler input to `prague` and raises only the executor spec — read directly out of the
solc standard-json, which records `evmVersion=prague` under both invocations. Build info
is off by default, so reproducing that evidence takes
`forge build --evm-version osaka --build-info --force` and then reading
`input.settings.evmVersion` in `out/build-info/*.json`. Both contract addresses and the
implementation code hash are consequently
byte-identical with and without the flag, and nothing a birth blob signs moves. That
guarantee is tied to the pinned compiler: moving `src` to solc >= 0.8.29 would let `osaka`
reach the compiler for real, and the test would then need its own compilation profile
instead of a global flag.

One related trap, checked and not applicable: RIP-7212 on OP-stack chains has been
reported returning empty data when reached by a plain `CALL` from a state-changing
context. Every P-256 call in Glaux goes through `SignatureVerify._p256Verify`, which is
`staticcall` inside a `view` function, on both the probe and the signing path.

### The rest of the preconditions

Read-only checks against both networks, all passing:

- The canonical CREATE2 deployer `0x4e59b44847b379578588920cA78FbF26c0B4956C` is present
  on both, so the deterministic deployment has its factory.
- Neither `0x927ed5700518a8A053367da1EaFDFBdE061E73F2` (impl, Phase 2) nor
  `0xB8270e4B9aaeA6933716409Bb648FB3Cda3CCbE9` (router) is occupied on either chain —
  `eth_getCode` still returns `0x` for both on both, re-checked 2026-07-31.
- ERC-4337 EntryPoint v0.7 `0x0000000071727De22E5E9d8BAf0edAc6f37da032` is deployed on
  both, so the 4337 path has a real EntryPoint to meet.
- `forge script Deploy.s.sol` simulated against live state on both chains reproduces
  exactly the addresses of the local Phase 2 run — impl
  `0x927ed5700518a8A053367da1EaFDFBdE061E73F2`, router unchanged — and a CREATE2
  address commits to the initcode, so the runtime code hash the birth blobs sign
  (`0x2c271f5a9e823360ad27431f2245570417fc1dc687b144eda63f8bf875b97c4c`) is pinned by
  the same match. The determinism claim holds against the real chains, not only
  between two anvils. Estimated deployment cost 5,164,364 gas — up from 4,937,011
  pre-surface, the implementation grew — ~0.0106 ETH on Sepolia at 2.04 gwei,
  ~0.000057 ETH on Base Sepolia at 0.011 gwei, at the moment of measurement.
- This whole pre-flight was first run 2026-07-29 against the pre-surface build and
  re-run 2026-07-30 after Phase 2 moved the implementation: the fork probe passed
  unchanged on both networks (`GLAUX_REQUIRE_FORK_CHECKS=1 forge test
  --match-contract P256ForkProbe --evm-version osaka`), and every value above is
  from the re-run.

### Transaction type 4, which birth depends on

Birth rides an EIP-7702 authorization, so the networks must accept type-4 transactions.
Sepolia demonstrably does: `eth_sendRawTransaction` with a truncated `0x04` payload is
answered `rlp: too few elements for types.SetCodeTx` — the node recognises the type and
tries to decode it — while unknown types `0x05` and `0x63` are refused outright as
`transaction type not supported`. Base Sepolia returns the same generic decode error for
all three, so that probe does not discriminate there; what stands in for it is the
EIP-2935 history contract at `0x0000F90827F1C53a10cb7A02335B175320002935`, present with
83 bytes of code on both chains. On L1 that shipped with Pectra and on OP-stack with
Isthmus, in each case the same fork that brought EIP-7702. Base Sepolia's type-4 support
is therefore inferred rather than directly observed — no type-4 transaction appeared in a
scan of its last 300 blocks (2,734 transactions), which says they are rare there, not that
they are rejected. The first birth is what settles it.

### The one remaining blocker

`GLAUX_RELAYER_KEY` — a private key funded with testnet ETH on both networks. Only the
repository owner can obtain it, from the faucets.

The other two variables are no longer blockers *for the read-only work*, and that is a
weaker claim than it may look. The public keyless endpoints above answered every check in
this section, and they expose all the methods `submit_birth.py` needs — `eth_chainId`,
`eth_getBlockByNumber`, `eth_maxPriorityFeePerGas`, `eth_getTransactionCount`,
`eth_estimateGas`, `eth_sendRawTransaction`, `eth_getTransactionReceipt`, with no archive
or `debug`/`trace` namespace required. Two of the three broadcast-path doubts this section
used to leave open were closed on 2026-07-31, still without spending anything. Both nodes
parse and *account for* an authorization list in `eth_estimateGas`: the same call costs
`0x52e9` (21,225 gas) bare and `0xb56a` (46,442 gas) with one authorization attached, an
identical +25,217 on each chain, which is the per-authorization charge and not a field
they quietly ignore. Both also apply EIP-7702 semantics rather than merely tolerating the
key — an empty list is rejected on its own terms (Sepolia: *EIP-7702 transaction with
empty auth list*; Base Sepolia: *authorization list has invalid fields*). And
`eth_sendRawTransaction` is exposed on both and reaches the typed-transaction decoder,
which is where a type-4 payload has to land: fed a deliberately undecodable body it
answers *typed transaction too short* (Sepolia) and *failed to decode signed transaction*
(Base Sepolia), never *method not found*. What still cannot be settled without the key is
the last step — whether a well-formed, signed type-4 transaction is accepted for
propagation — and whether the rate limits hold up under a real deploy. Treat the
endpoints as usable at the time of this check, with a private endpoint as the fallback
the moment a broadcast misbehaves. `--verify` additionally needs an
`ETHERSCAN_API_KEY`; drop the flag to deploy without source verification.

Once the key exists, run (from the repository root):

```bash
# The endpoints every check in the section above was run against. Substitute a
# private one if rate limits bite.
export GLAUX_RPC_SEPOLIA=https://ethereum-sepolia-rpc.publicnode.com
export GLAUX_RPC_BASE_SEPOLIA=https://base-sepolia-rpc.publicnode.com
export GLAUX_RELAYER_KEY=<funded testnet key>

# Pre-flight: re-confirm both chains still verify P-256 before spending anything.
# GLAUX_REQUIRE_FORK_CHECKS makes a missing endpoint fail rather than skip — without
# it this command is green when it has checked nothing.
GLAUX_REQUIRE_FORK_CHECKS=1 forge test --match-contract P256ForkProbe --evm-version osaka -vv

# Deploy deterministically on both testnets. Drop --verify without an ETHERSCAN_API_KEY.
forge script script/Deploy.s.sol:Deploy --rpc-url "$GLAUX_RPC_SEPOLIA" --private-key "$GLAUX_RELAYER_KEY" --broadcast --verify
forge script script/Deploy.s.sol:Deploy --rpc-url "$GLAUX_RPC_BASE_SEPOLIA" --private-key "$GLAUX_RELAYER_KEY" --broadcast --verify

# Confirm both deployments produced the same GlauxAccount/GlauxDelegate addresses
# (the console2.log output of the two runs above should match).

# Generate one birth blob (throwaway or real factor keys, birth key is ephemeral and never persisted).
python3 scripts/birth.py \
  --router <GlauxDelegate address> --impl <GlauxAccount address> \
  --expected-code-hash <address(impl).codehash printed above> \
  --paper <paper factor address> --device-qx <0x...> --device-qy <0x...> \
  --cloud <cloud factor address> > blob.json

# Submit the SAME blob to both testnets.
GLAUX_RELAYER_KEY="$GLAUX_RELAYER_KEY" python3 scripts/submit_birth.py --rpc "$GLAUX_RPC_SEPOLIA" --blob blob.json
GLAUX_RELAYER_KEY="$GLAUX_RELAYER_KEY" python3 scripts/submit_birth.py --rpc "$GLAUX_RPC_BASE_SEPOLIA" --blob blob.json

# Verify on both networks: code is 0xef0100<router>, updateNonce() == 0, getSlot(0..2) match.
cast code <account> --rpc-url "$GLAUX_RPC_SEPOLIA"
cast code <account> --rpc-url "$GLAUX_RPC_BASE_SEPOLIA"
```

## Public testnet — Base Sepolia (2026-07-31)

Base Sepolia (chain id 84532) was the first public chain to carry the canonical
pair, at exactly the addresses the two anvils and the simulation predicted. The
Sepolia half, and the cross-chain replay it completes, are in the next section.

| Contract | Address |
|---|---|
| `GlauxAccount` (impl) | `0x927ed5700518a8A053367da1EaFDFBdE061E73F2` |
| `GlauxDelegate` (router) | `0xB8270e4B9aaeA6933716409Bb648FB3Cda3CCbE9` |

`keccak256` of the deployed implementation's runtime code, read back from the
chain, is `0x2c271f5a9e823360ad27431f2245570417fc1dc687b144eda63f8bf875b97c4c` —
the same hash the local proof produced and the same one every birth blob signs.
Determinism now holds against a real chain and not only between two local nodes.
The deployment cost **3,738,908 gas** across its two transactions (3,078,079 for
the implementation, 660,829 for the router), well under the 5,164,364 the
pre-flight estimated; Foundry's estimate is conservative by roughly a third.
Sepolia later reproduced all three figures exactly.

### The first birth on a public chain

One blob, submitted once, produced account
`0x3c8D09d23E2d854E670A3C7ba6D59858E3BEFE93` in transaction
`0x094f06e015056e37d370ebec7bcdbf7a3daee27ad360f5cc963e51190bca26be` at block
44842376, status 1, **376,557 gas**.

The transaction is a genuine **type `0x4`** — `eth_getTransactionByHash` reports
`"type": "0x4"` and carries the authorization tuple with `chainId: 0x0` and
`address` set to the router, which is the chain-agnostic form the whole design
rests on. The relayer that paid was not the account and never held the birth key.
Read back from the chain afterwards:

- `eth_getCode` on the account returns `0xef0100b8270e4b9aaea6933716409bb648fb3cda3ccbe9`,
  the EIP-7702 delegation indicator pointing at the router.
- `updateNonce()` and `execNonce()` are both `0`.
- Slot 0 holds verifier type 1 with the paper address, slot 1 type 2 with the
  P-256 `qx‖qy`, slot 2 type 1 with the cloud address — the configuration the
  blob committed to, installed intact.

The factor keys used here are the **publicly known anvil keys** carried over from
the local proof, so this account is controllable by anyone and must never hold
anything. It exists to prove the birth path on a public chain, nothing else.

## Public testnet — Sepolia, and the cross-chain replay (2026-07-31)

**One blob, submitted unmodified to two public chains, produced the same
account with the same configuration on both.** This is the claim the design
rests on, and it is now demonstrated rather than argued.

### The pair on Sepolia

Sepolia (chain id 11155111) was deployed from the same source tree, and
reproduced both canonical addresses exactly:

| Contract | Address | Sepolia codehash | Base Sepolia codehash |
|---|---|---|---|
| `GlauxAccount` (impl) | `0x927ed5700518a8A053367da1EaFDFBdE061E73F2` | `0x2c271f5a…b97c4c` | `0x2c271f5a…b97c4c` |
| `GlauxDelegate` (router) | `0xB8270e4B9aaeA6933716409Bb648FB3Cda3CCbE9` | `0x3c8374c2…d679c0` | `0x3c8374c2…d679c0` |

The implementation codehash is the same `0x2c271f5a9e823360ad27431f2245570417fc1dc687b144eda63f8bf875b97c4c`
every birth blob signs. Deployment cost **3,738,908 gas** — 3,078,079 for the
implementation and 660,829 for the router, *the same figures to the unit* as
Base Sepolia. Determinism holds across two independent public chains, not just
between two local nodes.

### The replay

The blob generated for this purpose was submitted to Base Sepolia first, then
to Sepolia, byte-for-byte identical — `sha256
fded42f5c70bc48805311422cdd65b56ca2faf2dc1041f666276288e7da64ae8` before and
after both submissions. It lives at
`~/.local/state/glaux-birth-blob-2026-07-31.json`, outside the repository.
Before either submission the account address was empty on both chains
(`eth_getCode` `0x`, nonce `0`).

| | Base Sepolia (84532) | Sepolia (11155111) |
|---|---|---|
| Account | `0xB17d55188e3c982df12c99e466a8971872746822` | *the same* |
| Tx | `0xddbc25f16bb07fefe2b73425497b4b9716e168fd4f8e6a9aa3ce65635042517a` | `0xf746e3516936a9d62e2f6bbd1254b5817edccd8359defe61f2f91030dfc90200` |
| Block | 44859249 | 11388429 |
| Status / gas | 1 / **376,569** | 1 / **376,569** |
| Type | `0x4` | `0x4` |
| Authorization | `chainId 0x0`, `nonce 0x0`, → router | *identical tuple* |

Both births burned the same 376,569 gas. Read back afterwards, the two chains
are indistinguishable: code `0xef0100b8270e4b9aaea6933716409bb648fb3cda3ccbe9`
(the delegation indicator pointing at the router), `updateNonce()` and
`execNonce()` both `0`, slot 0 type 1 with the paper address, slot 1 type 2
with the P-256 `qx‖qy`, slot 2 type 1 with the cloud address. `scripts/reconcile.py`
run against both endpoints returns **`verdict: consistent (exit 0)`**.

The mechanism is the `chainId 0` authorization tuple: EIP-7702 increments the
authority's nonce only on the chain that applied it, so a `nonce 0`
authorization stays valid on every chain that has not yet seen it. Nothing in a
birth blob expires — there is no deadline field — so the two submissions did
not have to be close in time, and a third chain can still be reached with this
same blob today. The relayer that paid on both chains is neither the account
nor a holder of the birth key: submission is permissionless, and only the gas
came from it.

The factor keys here are the **publicly known anvil keys**, as in the local
proof and the first public birth. This account is controllable by anyone and
must never hold anything; it exists to prove the birth and replay paths on
public chains.

### Housekeeping

`cache/Deploy.s.sol/11155111/run-latest.json` was deleted immediately after the
deploy — Foundry writes the private key into it in the clear, exactly as it did
for chain 84532. A grep for the key across the working tree comes back empty;
what remains under `cache/` holds RPC URLs only.
