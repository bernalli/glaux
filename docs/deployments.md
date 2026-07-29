# Deployments

## Local two-chain end-to-end (verified)

Date: 2026-07-29. Commit: `80ceff6d9d9a5a00eb2fae4810272ba1a9eda63b`, the final Phase 1
state. The whole run below was repeated from scratch each time the contracts changed:
changing them changes their bytecode, and therefore every deterministic address and code
hash recorded here.

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
| 31337    | `0x55cbf6f799670E574BAb0C328F60eB0031238068`  | `0xf23eBaBa7aF8fa6fdB9618489FDf881d3b0EF89D`  |
| 31338    | `0x55cbf6f799670E574BAb0C328F60eB0031238068`  | `0xf23eBaBa7aF8fa6fdB9618489FDf881d3b0EF89D`  |

**Addresses are identical on both chains** — the CREATE2 determinism claim, confirmed by
running the same salted-bytecode deployment through the canonical CREATE2 deployer
(`0x4e59b44847b379578588920cA78FbF26c0B4956C`) on two independent chains.

Implementation runtime code hash (`address(impl).codehash`, printed by `Deploy.s.sol`):

```
0x1f10c7af471b8d7e21e1130f1fea8312f78cf5498eb50e9f1deeef5fbf39c882
```

### 2. Birth blob (one blob, generated once)

Each factor first produced a **possession proof** with `scripts/prove_possession.py`,
run separately per key — the contract refuses to install a key that has not signed the
registration challenge. Both anvil instances were given the P256VERIFY precompile at
`0x100` (`anvil_setCode` with the vendored verifier), because verifying the device
factor's proof needs it; a chain without that precompile cannot host a P-256 factor at
all, and birth there fails cleanly rather than installing an unusable one.

Generated with `scripts/birth.py` using throwaway factor keys: the paper and cloud secp256k1
factors are anvil's well-known default accounts 1 and 2
(`0x7099...79C8`, `0x3C44...93BC`), and the device P-256 factor is the anchored test vector
from `test/P256Fixture.sol`. These are public test keys with no value — never reuse this
configuration for a real account. The ephemeral birth key existed only in the Python process
memory and was discarded on exit; it was never written to disk or logged.

Born account address (recovered from the EIP-7702 authorization signed by the birth key):

```
0x4498aAE82C7684E1AA6F001A71986362b91851ED
```

### 3. Submission — the SAME blob to BOTH chains

`scripts/submit_birth.py` submitted the identical JSON blob to each chain, relayed by anvil's
default account 0 acting as an ordinary, unprivileged relayer (`GLAUX_RELAYER_KEY`):

| Chain id | Tx hash                                                              | Status | Gas used |
|----------|-----------------------------------------------------------------------|--------|----------|
| 31337    | `0xcfcfd9a4427cebb223e9d7f47a6465cf09666717bec6753bc2369dc34ce69eb4`  | 1      | 687651   |
| 31338    | `0x9b35373d8536b30523d3d917e253b7f4472526552502a30681b76505f3d03a10`  | 1      | 687651   |

Both transactions succeeded (status 1) with identical gas usage.

### 4. Post-birth verification — identical on BOTH chains

```
cast code 0x4498aAE82C7684E1AA6F001A71986362b91851ED --rpc-url <rpc>
  -> 0xef01002b7b0fa0aaa192a1e4168f9249dba4df80843248   (EIP-7702 delegation indicator to the router)

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
  -> 0x55cbf6f799670E574BAb0C328F60eB0031238068
cast storage <account> 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc --rpc-url <rpc>
  -> 0x0000...0000   (ERC-1967: never written by Glaux)
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
