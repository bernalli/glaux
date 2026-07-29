# Deployments

## Local two-chain end-to-end (verified)

Date: 2026-07-29. Commit: `d1104a5ae8f76e34b222409bcfbff777ac2d2f99` (contracts unchanged by
this commit is the final Phase 1 state; the run below was repeated against it after the
implementation checks changed, because changing the contracts changes their bytecode and
therefore every deterministic address recorded here).

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
| 31337    | `0xF7d66d0D47286632C5cd48dA44fC68f19d6A827E`  | `0xcCc62DE32d7F2B4366d7b8312A2217dA53Ecd4eC`  |
| 31338    | `0xF7d66d0D47286632C5cd48dA44fC68f19d6A827E`  | `0xcCc62DE32d7F2B4366d7b8312A2217dA53Ecd4eC`  |

**Addresses are identical on both chains** — the CREATE2 determinism claim, confirmed by
running the same salted-bytecode deployment through the canonical CREATE2 deployer
(`0x4e59b44847b379578588920cA78FbF26c0B4956C`) on two independent chains.

Implementation runtime code hash (`address(impl).codehash`, printed by `Deploy.s.sol`):

```
0xdfef5dfe4d79637286859b7164e6114b88b4a0df3f477a99849bb9e8e32672b8
```

### 2. Birth blob (one blob, generated once)

Generated with `scripts/birth.py` using throwaway factor keys: the paper and cloud secp256k1
factors are anvil's well-known default accounts 1 and 2
(`0x7099...79C8`, `0x3C44...93BC`), and the device P-256 factor is the anchored test vector
from `test/P256Fixture.sol`. These are public test keys with no value — never reuse this
configuration for a real account. The ephemeral birth key existed only in the Python process
memory and was discarded on exit; it was never written to disk or logged.

Born account address (recovered from the EIP-7702 authorization signed by the birth key):

```
0x985872F49e73c34Ad343C568DA2831Cba1E94159
```

### 3. Submission — the SAME blob to BOTH chains

`scripts/submit_birth.py` submitted the identical JSON blob to each chain, relayed by anvil's
default account 0 acting as an ordinary, unprivileged relayer (`GLAUX_RELAYER_KEY`):

| Chain id | Tx hash                                                              | Status | Gas used |
|----------|-----------------------------------------------------------------------|--------|----------|
| 31337    | `0xcff656565b8abf3abab6cecf41f1585b354908ea4e319ba6cf392915448ce981`  | 1      | 324265   |
| 31338    | `0xb6fee16bcdf904f1f3dc206c7e5adc55fd6a66c62675b16c1c6e38d51c8a987e`  | 1      | 324265   |

Both transactions succeeded (status 1) with identical gas usage.

### 4. Post-birth verification — identical on BOTH chains

```
cast code 0x985872F49e73c34Ad343C568DA2831Cba1E94159 --rpc-url <rpc>
  -> 0xef0100ccc62de32d7f2b4366d7b8312a2217da53ecd4ec   (EIP-7702 delegation indicator to the router)

cast call <account> "updateNonce()(uint64)" --rpc-url <rpc>
  -> 0

cast call <account> "getSlot(uint8)(uint8,bytes)" 0 --rpc-url <rpc>
  -> 1, 0x...70997970c51812dc3a010c7d01b50e0d17dc79c8   (secp256k1 paper factor)

cast call <account> "getSlot(uint8)(uint8,bytes)" 1 --rpc-url <rpc>
  -> 2, 0xc9b91be2...b7de6f                                (P-256 device factor, qx||qy)

cast call <account> "getSlot(uint8)(uint8,bytes)" 2 --rpc-url <rpc>
  -> 1, 0x...3c44cdddb6a900fa2b585dd299e03d12fa4293bc   (secp256k1 cloud factor)
```

Every one of these checks returned byte-for-byte identical output on chain id 31337 and chain
id 31338: one authorization tuple, one init blob, two different chain ids, same account
address, same configuration. That is the specification's chain-agnostic replay claim,
demonstrated live rather than assumed.

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
