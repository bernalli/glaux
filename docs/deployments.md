# Deployments

## Local two-chain end-to-end (verified)

Date: 2026-07-29. Commit: `a139b2d169a4a7e6fddc2c1b15d4f118d23a6245` (contracts unchanged by
this deployment tooling; `forge build`/`forge test` were re-run against this commit before and
after the proof below).

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
| 31337    | `0x14cadB3D9c7D0BcFF9eCD32c926a0E203eaEC823`  | `0xc8f1588dbCd2367aF76ba57E549388Dc8D11509a`  |
| 31338    | `0x14cadB3D9c7D0BcFF9eCD32c926a0E203eaEC823`  | `0xc8f1588dbCd2367aF76ba57E549388Dc8D11509a`  |

**Addresses are identical on both chains** — the CREATE2 determinism claim, confirmed by
running the same salted-bytecode deployment through the canonical CREATE2 deployer
(`0x4e59b44847b379578588920cA78FbF26c0B4956C`) on two independent chains.

Implementation runtime code hash (`address(impl).codehash`, printed by `Deploy.s.sol`):

```
0x7774493ff879ebb52c4e0afd243243ea25fff1ebc67f93d0b2ac5d820de1e85a
```

### 2. Birth blob (one blob, generated once)

Generated with `scripts/birth.py` using throwaway factor keys (paper/cloud secp256k1 EOAs
freshly created for this run; device P-256 key is the anchored test vector from
`test/P256Fixture.sol`). The ephemeral birth key existed only in the Python process memory
and was discarded on exit; it was never written to disk or logged.

Born account address (recovered from the EIP-7702 authorization signed by the birth key):

```
0x4D22Ae6e725813c5B846f66a6056b31e6bc7B9CD
```

### 3. Submission — the SAME blob to BOTH chains

`scripts/submit_birth.py` submitted the identical JSON blob to each chain, relayed by anvil's
default account 0 acting as an ordinary, unprivileged relayer (`GLAUX_RELAYER_KEY`):

| Chain id | Tx hash                                                              | Status | Gas used |
|----------|-----------------------------------------------------------------------|--------|----------|
| 31337    | `0x8e9c02daeaff39536ba71a299afbaa811fef8b7b54f15fc868f63badb6ee398a`  | 1      | 324522   |
| 31338    | `0x0935805206bba60fb8fd2ddc291b4df338de56cee69d64b7e664346f2f26fb1b`  | 1      | 324522   |

Both transactions succeeded (status 1) with identical gas usage.

### 4. Post-birth verification — identical on BOTH chains

```
cast code 0x4D22Ae6e725813c5B846f66a6056b31e6bc7B9CD --rpc-url <rpc>
  -> 0xef0100c8f1588dbcd2367af76ba57e549388dc8d11509a   (EIP-7702 delegation indicator to the router)

cast call <account> "updateNonce()(uint64)" --rpc-url <rpc>
  -> 0

cast call <account> "getSlot(uint8)(uint8,bytes)" 0 --rpc-url <rpc>
  -> 1, 0x...0044f4e7c18b902d58e5b64bcbb2b39e70b4ab69d3   (secp256k1 paper factor)

cast call <account> "getSlot(uint8)(uint8,bytes)" 1 --rpc-url <rpc>
  -> 2, 0xc9b91be2...b7de6f                                (P-256 device factor, qx||qy)

cast call <account> "getSlot(uint8)(uint8,bytes)" 2 --rpc-url <rpc>
  -> 1, 0x...000cf86db889cb20309b7c299061062563b3a6d7e5   (secp256k1 cloud factor)
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
