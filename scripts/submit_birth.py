"""Submit a Glaux account-birth blob to one chain.

Reads a birth blob produced by `scripts/birth.py`, builds a single EIP-7702
type-4 (set-code) transaction that carries the signed authorization tuple
(delegating the born account's code to `GlauxDelegate`) and, in the same
transaction, calls `GlauxDelegate.initialize(implementation, expectedCodeHash,
initData, birthSig)` on the now-delegated account. Submission is
permissionless: the relayer only pays gas and never needs to hold the birth
key, so the same blob can be broadcast by anyone, on any chain, exactly once.

The relayer private key is read from the `GLAUX_RELAYER_KEY` environment
variable and is never accepted as a CLI flag or printed. Set the variable
without typing the key on a command line: an inline `GLAUX_RELAYER_KEY=0x...
python3 ...` assignment is written to the history file by every interactive
shell, which is the exposure a flag would have caused.

Usage:
    read -rs GLAUX_RELAYER_KEY && export GLAUX_RELAYER_KEY   # key never echoed
    python3 scripts/submit_birth.py \\
        --rpc http://127.0.0.1:8545 --blob /path/to/blob.json
    unset GLAUX_RELAYER_KEY
"""

import argparse
import json
import os
import sys
from typing import Any

from eth_abi import encode
from eth_account import Account
from eth_account.typed_transactions.set_code_transaction import Authorization
from eth_keys.datatypes import Signature
from eth_utils import keccak, to_bytes, to_checksum_address
from web3 import Web3

INITIALIZE_SELECTOR = keccak(text="initialize(address,bytes32,bytes,bytes)")[:4]

# The namespaced slots GlauxStorage owns (same derivation as reconcile.py's BASE_SLOT /
# IMPL_SLOT). A birth blob must only ever be broadcast to an address that has never been
# an EIP-7702 delegate: re-delegation does not clear storage, so a prior hostile delegate
# could have pre-planted these slots and made the account an attacker-owned Glaux account
# the instant it delegates to the router (threat-model residual 17). No on-chain check
# can catch this; this is the client-side gate. The layout is a header word at
# STORAGE_SLOT followed by three `FactorSlot` entries (verifierType, then the `bytes
# data` head) at STORAGE_SLOT+1..STORAGE_SLOT+6 — the preflight below checks IMPL_SLOT
# plus all seven of these words, not just the header.
STORAGE_SLOT = int.from_bytes(keccak(text="glaux.account.v1.storage"), "big")
IMPL_SLOT = int.from_bytes(keccak(text="glaux.account.v1.implementation"), "big")

# Any real birth runs three possession-proof verifications and, when a P-256 factor
# is present, the verifier probe on top. Nothing that does the job fits in this, so
# an estimate below it means the node priced a call to an account that is not
# delegated yet — the delegation and the call ride in the SAME transaction, so a node
# that ignores the authorization list sees a plain EOA and answers for a value
# transfer with calldata (~47k). Trusting that number sends a transaction that runs
# out of gas mid-birth.
MIN_PLAUSIBLE_BIRTH_GAS = 200_000
# Enough for the worst case observed: a chain that answers P-256 with a Solidity
# verifier at 0x100 rather than a precompile, where birth costs ~1.4M. Unused gas is
# refunded; only the relayer's balance has to cover the limit.
FALLBACK_BIRTH_GAS = 3_000_000


def load_blob(path: str) -> dict[str, Any]:
    """Read and parse a birth blob JSON file produced by `scripts/birth.py`."""
    with open(path, encoding="utf-8") as blob_file:
        return json.load(blob_file)


def build_authorization(blob: dict[str, Any]) -> dict[str, Any]:
    """Rebuild the EIP-7702 authorization dict web3/eth-account expect in `authorizationList`."""
    authorization = blob["authorization"]
    return {
        "chainId": authorization["chainId"],
        "address": to_checksum_address(authorization["address"]),
        "nonce": authorization["nonce"],
        "yParity": authorization["yParity"],
        "r": int(authorization["r"], 16),
        "s": int(authorization["s"], 16),
    }


def build_initialize_calldata(blob: dict[str, Any]) -> bytes:
    """ABI-encode the `initialize(address,bytes32,bytes,bytes)` call from the blob."""
    implementation = to_checksum_address(blob["implementation"])
    expected_code_hash = to_bytes(hexstr=blob["expectedCodeHash"])
    init_data = to_bytes(hexstr=blob["initData"])
    birth_sig = to_bytes(hexstr=blob["birthSig"])
    encoded_args = encode(
        ["address", "bytes32", "bytes", "bytes"],
        [implementation, expected_code_hash, init_data, birth_sig],
    )
    return INITIALIZE_SELECTOR + encoded_args


def assert_blob_authorization(blob: dict[str, Any]) -> None:
    """Bind an interchange blob's EIP-7702 authorization to its account.

    This is the Python counterpart of the SDK's ``assertCanonicalBlob``
    authorization checks. The pre-birth storage gate must inspect the EOA the
    tuple actually authorizes, not merely an unrelated ``blob["account"]``.
    ``chainId == 0`` is equally mandatory: otherwise the retained blob stops
    being replayable on every chain, which is Glaux birth's core invariant.
    ``nonce == 0`` for the same reason: EIP-7702 validates the tuple's nonce
    against the authority's CURRENT account nonce, and a birth key never sends
    a transaction of its own, so every chain sees it at 0 forever. A tuple
    signed for any other nonce applies, at best, on the single chain that
    happens to match -- and elsewhere the delegation is silently skipped.
    """
    authorization = blob["authorization"]
    account = to_checksum_address(blob["account"])
    router = to_checksum_address(blob["router"])
    target = to_checksum_address(authorization["address"])
    if target != router:
        sys.exit(
            "refusing to submit: birth blob authorization target differs from its router"
        )
    if authorization["chainId"] != 0:
        sys.exit(
            "refusing to submit: birth blob authorization chainId must be 0 for cross-chain replay"
        )
    if authorization["nonce"] != 0:
        sys.exit(
            "refusing to submit: birth blob authorization nonce must be 0 for cross-chain replay"
        )

    try:
        unsigned = Authorization(
            authorization["chainId"],
            to_bytes(hexstr=target),
            authorization["nonce"],
        )
        signature = Signature(
            vrs=(
                authorization["yParity"],
                int(authorization["r"], 16),
                int(authorization["s"], 16),
            )
        )
        signer = signature.recover_public_key_from_msg_hash(
            unsigned.hash()
        ).to_checksum_address()
    except Exception as exc:
        raise SystemExit(
            "refusing to submit: birth blob authorization signature is malformed"
        ) from exc
    if signer != account:
        sys.exit(
            "refusing to submit: birth blob authorization signer does not equal blob account"
        )


def preflight_fresh_account(
    w3: Web3, account_address: str, router_address: str
) -> None:
    """Abort before broadcasting if the target account is not a pristine EOA.

    An EIP-7702 re-delegation does not clear storage, so a birth blob must only be
    sent to an address whose code is either empty or the delegation designator this
    same blob would install (`0xef0100 ‖ router_address` — the retry of a birth whose
    initialize() call reverted, e.g. InvalidImplementation, which EIP-7702 still
    applies the authorization for), and whose Glaux namespaced words — IMPL_SLOT and
    the header plus all three FactorSlot entries at STORAGE_SLOT..STORAGE_SLOT+6 — are
    zero. See docs/client-guidance.md (Birth) and threat-model residual 17. Read-only;
    raises SystemExit on any violation.
    """
    expected_designator = bytes.fromhex("ef0100") + to_bytes(
        hexstr=to_checksum_address(router_address)
    )
    code = bytes(w3.eth.get_code(account_address))
    if len(code) != 0 and code != expected_designator:
        sys.exit(
            f"refusing to submit: {account_address} already has code "
            f"({len(code)} bytes) that is not the EIP-7702 designator for this blob's "
            f"router ({router_address}) — it must be a fresh EOA that was never an "
            "EIP-7702 delegate, or the retry of a birth that reverted while already "
            "delegated to this router (threat-model residual 17). Never migrate an "
            "EOA delegated to a different target."
        )
    impl = w3.eth.get_storage_at(account_address, IMPL_SLOT)
    if int.from_bytes(impl, "big") != 0:
        sys.exit(
            f"refusing to submit: {account_address} has a non-zero Glaux implementation "
            "slot — its storage was pre-planted (threat-model residual 17)."
        )
    for offset in range(7):
        slot = STORAGE_SLOT + offset
        word = w3.eth.get_storage_at(account_address, slot)
        if int.from_bytes(word, "big") != 0:
            kind = (
                "storage header word"
                if offset == 0
                else f"FactorSlot word (STORAGE_SLOT+{offset})"
            )
            sys.exit(
                f"refusing to submit: {account_address} has a non-zero Glaux {kind} "
                f"at slot {slot} — its storage was pre-planted (threat-model residual 17)."
            )


def submit_birth(w3: Web3, relayer_key: str, blob: dict[str, Any]) -> dict[str, Any]:
    """Build, sign, send, and wait for the type-4 birth transaction.

    Returns the transaction receipt as a plain dict (status, tx hash, gas used)
    only for a birth that actually succeeded. A receipt whose status is not 1
    exits non-zero instead: EIP-7702 applies the authorization even when the
    call riding in the same transaction reverts, so a reverted birth leaves the
    account delegated with none of its factor slots installed. Returning that
    receipt would let automation record a failed initialization as done.
    """
    assert_blob_authorization(blob)
    relayer = Account.from_key(relayer_key)
    account_address = to_checksum_address(blob["account"])
    preflight_fresh_account(w3, account_address, blob["authorization"]["address"])
    chain_id = w3.eth.chain_id
    latest_block = w3.eth.get_block("latest")
    base_fee = latest_block.get("baseFeePerGas", w3.eth.gas_price)
    priority_fee = w3.eth.max_priority_fee
    max_fee = base_fee * 2 + priority_fee

    transaction = {
        "type": 4,
        "chainId": chain_id,
        "nonce": w3.eth.get_transaction_count(relayer.address),
        "to": account_address,
        "value": 0,
        "gas": 0,  # replaced by the estimate below
        "maxFeePerGas": max_fee,
        "maxPriorityFeePerGas": priority_fee,
        "data": "0x" + build_initialize_calldata(blob).hex(),
        "accessList": (),
        "authorizationList": [build_authorization(blob)],
    }
    # Birth cost depends on the verifier types in the blob: each factor's possession
    # proof is verified on chain, a P-256 proof costs far more than a secp256k1 one,
    # and installing a P-256 slot also probes the verifier. Estimate rather than
    # hardcode — but an estimate for a type-4 transaction is only meaningful if the
    # node applies the authorization first, since the account has no code until it
    # does. Pass the authorization list, and treat an implausibly cheap answer as a
    # node that ignored it rather than as a cheap birth.
    try:
        estimate = w3.eth.estimate_gas(
            {
                "from": relayer.address,
                "to": account_address,
                "data": transaction["data"],
                "authorizationList": transaction["authorizationList"],
            }
        )
    except Exception:  # noqa: BLE001 - node may refuse to estimate pre-delegation
        estimate = 0
    if estimate >= MIN_PLAUSIBLE_BIRTH_GAS:
        transaction["gas"] = int(estimate * 3 // 2) + 100_000
    else:
        transaction["gas"] = FALLBACK_BIRTH_GAS

    signed = Account.sign_transaction(transaction, relayer.key)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    result = {
        "chainId": chain_id,
        "account": account_address,
        "txHash": receipt["transactionHash"].to_0x_hex(),
        "status": receipt["status"],
        "gasUsed": receipt["gasUsed"],
        "blockNumber": receipt["blockNumber"],
    }
    if receipt["status"] != 1:
        sys.exit(
            f"birth REVERTED: {account_address} was NOT initialized on chain "
            f"{chain_id}. Transaction {result['txHash']} was mined in block "
            f"{result['blockNumber']} with status {receipt['status']} "
            f"(gas used {result['gasUsed']}). The EIP-7702 authorization still "
            "applied, so the account is delegated with no factor slots "
            "installed: inspect it before retrying this blob."
        )
    return result


def main() -> None:
    """Parse CLI args, submit the birth blob to `--rpc`, and print the receipt as JSON."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--rpc", required=True, help="JSON-RPC endpoint of the target chain"
    )
    parser.add_argument("--blob", required=True, help="path to a birth blob JSON file")
    args = parser.parse_args()

    relayer_key = os.environ.get("GLAUX_RELAYER_KEY")
    if not relayer_key:
        sys.exit("GLAUX_RELAYER_KEY environment variable is not set")

    w3 = Web3(Web3.HTTPProvider(args.rpc))
    blob = load_blob(args.blob)
    result = submit_birth(w3, relayer_key, blob)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
