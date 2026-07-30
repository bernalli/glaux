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

## Public testnet deployment: NOT DONE

Sepolia and Base Sepolia broadcast has **not** been performed. It is blocked on three
environment variables that only the repository owner can supply:

- `GLAUX_RPC_SEPOLIA` — a funded Sepolia RPC endpoint
- `GLAUX_RPC_BASE_SEPOLIA` — a funded Base Sepolia RPC endpoint
- `GLAUX_RELAYER_KEY` — a relayer private key funded with testnet ETH on both networks

No claim is made here that this happened; the local two-chain proof above is the only
end-to-end evidence currently available in this environment.

Once those variables exist, run (from the repository root):

```bash
# Deploy deterministically on both testnets.
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
