#!/usr/bin/env bash
# Two-chain end-to-end proof for Glaux (docs/deployments.md §1-5, automated).
#
# Boots two anvil chains, deploys deterministically on both, births ONE account
# from ONE blob on both chains, exercises the account surface (ERC-165, ERC-1271
# chain binding), runs reconcile.py, and re-proves the refusal on a chain whose
# P-256 verifier is removed. Prints every value the deployments.md tables need.
#
# MUST run without a restrictive sandbox: anvil, forge and cast need network
# access and an unrestricted filesystem. Test keys only — anvil defaults + the
# public P-256 fixture vector. Never reuse this configuration for a real account.
#
# Exit: 0 = every check passed; non-zero = the first failed check, with a
# message naming it. The ROUTER MOVING is a hard stop: it means the immutable
# half changed, which is a design violation, not a table to update.

set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"

CANONICAL_ROUTER="0x3ccF1cc0F702C084B31e691e057d8742ADF35790"
RPC_A="http://127.0.0.1:8545"
RPC_B="http://127.0.0.1:8546"
DEPLOYER_PK="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" # anvil 0
PAPER_PK="0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"    # anvil 1
CLOUD_PK="0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a"    # anvil 2
PAPER_ADDR="0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
CLOUD_ADDR="0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"
# test/P256Fixture.sol — public test vector, refused as probe key material is different
P256_PK="0x7459e13afd9158a379ee75ca9e80a328916dba1473c863f800f51ee5f46eb3ab"
QX="0xc9b91be23306ebbd29f0f1718a1db88a151200eb10c6aad04aa24f8006704de6"
QY="0x0accddfa8e09bddc03677b1f83a1d4aced4155d44ca7c1fd5226b8d312b7de6f"

PY="$REPO/.venv/bin/python"
[[ -x "$PY" ]] || PY="python3"
WORK="$(mktemp -d)"
ANVIL_PIDS=()

cleanup() {
  for pid in "${ANVIL_PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
  rm -rf "$WORK"
}
trap cleanup EXIT

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

step() { echo; echo "== $*"; }

step "0. router immobility (build-level)"
forge build --quiet
# Build-artifact hash, NOT the deployed code hash: `forge inspect` returns the
# artifact with the immutable SELF still unresolved, while deployment writes
# address(this) into the runtime code. Use this to compare builds; use
# EXTCODEHASH to compare what is deployed on two chains.
ROUTER_BUILD_HASH=$(cast keccak "$(forge inspect src/GlauxDelegate.sol:GlauxDelegate deployedBytecode)")
echo "router build-artifact hash: $ROUTER_BUILD_HASH"

step "1. boot two anvil chains (prague)"
anvil --port 8545 --chain-id 31337 --hardfork prague >"$WORK/anvil_a.log" 2>&1 &
ANVIL_PIDS+=($!)
anvil --port 8546 --chain-id 31338 --hardfork prague >"$WORK/anvil_b.log" 2>&1 &
ANVIL_PIDS+=($!)
for _ in $(seq 1 50); do
  cast chain-id --rpc-url "$RPC_A" >/dev/null 2>&1 && cast chain-id --rpc-url "$RPC_B" >/dev/null 2>&1 && break
  sleep 0.2
done
[[ "$(cast chain-id --rpc-url "$RPC_A")" == "31337" ]] || fail "anvil A not up"
[[ "$(cast chain-id --rpc-url "$RPC_B")" == "31338" ]] || fail "anvil B not up"

step "2. deterministic deploy on both"
declare -A IMPL ROUTER
for rpc in "$RPC_A" "$RPC_B"; do
  out=$(forge script script/Deploy.s.sol:Deploy --rpc-url "$rpc" --private-key "$DEPLOYER_PK" --broadcast 2>&1)
  IMPL[$rpc]=$(grep -oE 'GlauxAccount: (0x[0-9a-fA-F]{40})' <<<"$out" | awk '{print $2}')
  ROUTER[$rpc]=$(grep -oE 'GlauxDelegate: (0x[0-9a-fA-F]{40})' <<<"$out" | awk '{print $2}')
done
[[ "${IMPL[$RPC_A]}" == "${IMPL[$RPC_B]}" ]] || fail "impl addresses differ across chains"
[[ "${ROUTER[$RPC_A]}" == "${ROUTER[$RPC_B]}" ]] || fail "router addresses differ across chains"
[[ "${ROUTER[$RPC_A]}" == "$CANONICAL_ROUTER" ]] \
  || fail "ROUTER MOVED: ${ROUTER[$RPC_A]} != $CANONICAL_ROUTER — the immutable half changed. STOP."
IMPL_ADDR="${IMPL[$RPC_A]}"
IMPL_CODEHASH=$(cast keccak "$(cast code "$IMPL_ADDR" --rpc-url "$RPC_A")")
echo "impl:          $IMPL_ADDR"
echo "router:        $CANONICAL_ROUTER (unchanged)"
echo "impl codehash: $IMPL_CODEHASH"

step "3. etch the P-256 verifier at 0x100 on both"
VERIFIER_CODE=$($PY -c "import json;print(json.load(open('out/P256Verifier.sol/P256Verifier.json'))['deployedBytecode']['object'])")
for rpc in "$RPC_A" "$RPC_B"; do
  cast rpc anvil_setCode 0x0000000000000000000000000000000000000100 "$VERIFIER_CODE" --rpc-url "$rpc" >/dev/null
done
VHASH=$(cast keccak "$(cast code 0x0000000000000000000000000000000000000100 --rpc-url "$RPC_A")")
echo "verifier codehash: $VHASH"

step "4. possession proofs + birth blob (ONE blob)"
PAPER_PROOF=$(GLAUX_FACTOR_KEY="$PAPER_PK" $PY scripts/prove_possession.py --slot 0 --type 1)
DEVICE_PROOF=$(GLAUX_FACTOR_KEY="$P256_PK" $PY scripts/prove_possession.py --slot 1 --type 2 --qx "$QX" --qy "$QY")
CLOUD_PROOF=$(GLAUX_FACTOR_KEY="$CLOUD_PK" $PY scripts/prove_possession.py --slot 2 --type 1)
$PY scripts/birth.py \
  --router "$CANONICAL_ROUTER" --impl "$IMPL_ADDR" --expected-code-hash "$IMPL_CODEHASH" \
  --paper "$PAPER_ADDR" --device-qx "$QX" --device-qy "$QY" --cloud "$CLOUD_ADDR" \
  --paper-proof "$PAPER_PROOF" --device-proof "$DEVICE_PROOF" --cloud-proof "$CLOUD_PROOF" \
  >"$WORK/blob.json"
ACCT=$($PY -c "import json;print(json.load(open('$WORK/blob.json'))['account'])")
echo "born account: $ACCT"

step "5. submit the SAME blob to both"
export GLAUX_RELAYER_KEY="$DEPLOYER_PK"
for rpc in "$RPC_A" "$RPC_B"; do
  res=$($PY scripts/submit_birth.py --rpc "$rpc" --blob "$WORK/blob.json")
  echo "$res"
  [[ "$($PY -c "import json,sys;print(json.loads('''$res''')['status'])")" == "1" ]] || fail "birth failed on $rpc"
done

step "6. post-birth checks, identical on both"
for rpc in "$RPC_A" "$RPC_B"; do
  code=$(cast code "$ACCT" --rpc-url "$rpc")
  want="0xef0100$(tr '[:upper:]' '[:lower:]' <<<"${CANONICAL_ROUTER:2}")"
  [[ "$code" == "$want" ]] || fail "designator wrong on $rpc: $code"
  [[ "$(cast call "$ACCT" 'implementation()(address)' --rpc-url "$rpc")" == "$IMPL_ADDR" ]] || fail "impl pointer wrong on $rpc"
  [[ "$(cast storage "$ACCT" 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc --rpc-url "$rpc")" == "0x0000000000000000000000000000000000000000000000000000000000000000" ]] || fail "ERC-1967 slot written on $rpc"
  [[ "$(cast call "$ACCT" 'supportsInterface(bytes4)(bool)' 0x1626ba7e --rpc-url "$rpc")" == "true" ]] || fail "165(1271) false on $rpc"
  [[ "$(cast call "$ACCT" 'supportsInterface(bytes4)(bool)' 0xffffffff --rpc-url "$rpc")" == "false" ]] || fail "165(ffff) true on $rpc"
done
echo "designator, impl pointer, clean 1967 slot, ERC-165: OK on both"

step "7. ERC-1271 chain binding, live"
read -r SIG HASH <<<"$($PY - "$ACCT" <<'EOF'
import sys
from eth_abi import encode
from eth_account import Account
from eth_utils import keccak

acct = sys.argv[1]
MSG_DOMAIN = keccak(text="GLAUX_MSG_V1")
HASH = keccak(text="two-chain-proof message")
VALID_UNTIL = 2**31
struct = keccak(
    encode(
        ["bytes32", "uint256", "address", "bytes32", "uint48"],
        [MSG_DOMAIN, 31337, acct, HASH, VALID_UNTIL],
    )
)
digest = keccak(b"\x19\x00" + bytes.fromhex(acct[2:]) + struct)


def sig65(pk: str) -> bytes:
    s = Account.unsafe_sign_hash(digest, pk)
    return s.r.to_bytes(32, "big") + s.s.to_bytes(32, "big") + bytes([s.v])


paper = sig65("0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d")
cloud = sig65("0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a")
blob = encode(["uint48", "(uint8,bytes)[2]"], [VALID_UNTIL, [(0, paper), (2, cloud)]])
print("0x" + blob.hex(), "0x" + HASH.hex())
EOF
)"
R_A=$(cast call "$ACCT" "isValidSignature(bytes32,bytes)(bytes4)" "$HASH" "$SIG" --rpc-url "$RPC_A")
R_B=$(cast call "$ACCT" "isValidSignature(bytes32,bytes)(bytes4)" "$HASH" "$SIG" --rpc-url "$RPC_B")
[[ "$R_A" == "0x1626ba7e" ]] || fail "1271 rejected on its own chain: $R_A"
[[ "$R_B" == "0xffffffff" ]] || fail "1271 ACCEPTED cross-chain: $R_B — chain binding broken"
echo "signed-for chain: MAGIC; other chain: sentinel — chain binding holds"

step "8. reconcile.py across both (expect exit 0)"
$PY scripts/reconcile.py --account "$ACCT" --router "$CANONICAL_ROUTER" \
  --rpc chain-31337="$RPC_A" --rpc chain-31338="$RPC_B" || fail "reconcile verdict $? on healthy chains"

step "9. refusal where the verifier is gone (chain B), fresh blob"
cast rpc anvil_setCode 0x0000000000000000000000000000000000000100 0x --rpc-url "$RPC_B" >/dev/null
# A rootless account's address is derived from its birth digest, so a blob that
# repeats the same initData — same factors AND the same possession proofs, which
# is exactly what reusing the shell variables above would do — lands on the
# account already born in step 5. The submitter would then refuse it as
# pre-planted, and the refusal would say nothing about the missing verifier.
# Swapping the cloud factor for a different key changes initData, hence the
# digest, hence the address; the equality check below keeps that honest.
CLOUD2_PK="0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6" # anvil 3
CLOUD2_ADDR="0x90F79bf6EB2c4f870365E785982E1f101E93b906"
CLOUD2_PROOF=$(GLAUX_FACTOR_KEY="$CLOUD2_PK" $PY scripts/prove_possession.py --slot 2 --type 1)
$PY scripts/birth.py \
  --router "$CANONICAL_ROUTER" --impl "$IMPL_ADDR" --expected-code-hash "$IMPL_CODEHASH" \
  --paper "$PAPER_ADDR" --device-qx "$QX" --device-qy "$QY" --cloud "$CLOUD2_ADDR" \
  --paper-proof "$PAPER_PROOF" --device-proof "$DEVICE_PROOF" --cloud-proof "$CLOUD2_PROOF" \
  >"$WORK/blob2.json"
CAND=$($PY -c "import json;print(json.load(open('$WORK/blob2.json'))['account'])")
[[ "$CAND" != "$ACCT" ]] \
  || fail "refusal candidate equals the born account — the config was not changed, the check below would be vacuous"
# The submitter refuses outright — non-zero exit, reason on stderr, nothing on
# stdout — so the refusal is read from its exit code rather than from a result
# it deliberately no longer prints.
set +e
$PY scripts/submit_birth.py --rpc "$RPC_B" --blob "$WORK/blob2.json"
birth_rc=$?
set -e
[[ "$birth_rc" != "0" ]] || fail "birth SUCCEEDED without a verifier"
# The refusal now happens BEFORE broadcasting: the node cannot price a birth
# that would revert, and a guessed gas limit would send it anyway. That matters
# more than the exit code, because EIP-7702 applies the authorization even when
# `initialize` reverts — a broadcast here would leave this address delegated,
# unborn and, being rootless, unreachable forever. So assert the address was
# never touched at all.
[[ "$(cast code "$CAND" --rpc-url "$RPC_B")" == "0x" ]] \
  || fail "candidate $CAND was delegated on the verifier-less chain: the refusal came too late"
# And prove the refusal is about the missing verifier rather than about a blob
# this run happened to build wrong: the SAME blob must be born on chain A, where
# the verifier is present. Without this the check above passes for any reason at
# all, including a broken blob.
$PY scripts/submit_birth.py --rpc "$RPC_A" --blob "$WORK/blob2.json" >/dev/null \
  || fail "the refusal candidate could not be born on the healthy chain either — the blob is at fault, not the verifier"
[[ "$(cast code "$CAND" --rpc-url "$RPC_A")" != "0x" ]] || fail "candidate not delegated on chain A"
echo "refused before broadcast (submitter exit $birth_rc), address untouched on the verifier-less chain, same blob born on the healthy one"
# restore, for hygiene, in case the anvils outlive us
cast rpc anvil_setCode 0x0000000000000000000000000000000000000100 "$VERIFIER_CODE" --rpc-url "$RPC_B" >/dev/null

echo
echo "ALL CHECKS PASSED — values for docs/deployments.md:"
echo "  impl:              $IMPL_ADDR"
echo "  impl codehash:     $IMPL_CODEHASH"
echo "  router:            $CANONICAL_ROUTER (build-artifact hash $ROUTER_BUILD_HASH)"
echo "  verifier codehash: $VHASH"
echo "  born account:      $ACCT"
echo "  refusal candidate: $CAND"
echo "Update the doc tables by hand — the narrative around them is the point."
