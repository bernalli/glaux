"""Submit a Glaux account-birth blob to one chain.

Reads a birth blob produced by `scripts/birth.py`, builds a single EIP-7702
type-4 (set-code) transaction that carries the signed authorization tuple
(delegating the born account's code to `GlauxDelegate`) and, in the same
transaction, calls `GlauxDelegate.initialize(implementation, expectedCodeHash,
initData, birthSig)` on the now-delegated account. Submission is
permissionless: the relayer only pays gas and never needs to hold the birth
key, so the same blob can be broadcast by anyone, on any chain, exactly once.

The relayer private key is read from the `GLAUX_RELAYER_KEY` environment
variable and is never accepted as a CLI flag or printed.

Usage:
    GLAUX_RELAYER_KEY=0x... python3 scripts/submit_birth.py \\
        --rpc http://127.0.0.1:8545 --blob /path/to/blob.json
"""

import argparse
import json
import os
import sys
from typing import Any

from eth_abi import encode
from eth_account import Account
from eth_utils import keccak, to_bytes, to_checksum_address
from web3 import Web3

INITIALIZE_SELECTOR = keccak(text="initialize(address,bytes32,bytes,bytes)")[:4]


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


def submit_birth(w3: Web3, relayer_key: str, blob: dict[str, Any]) -> dict[str, Any]:
    """Build, sign, send, and wait for the type-4 birth transaction.

    Returns the transaction receipt as a plain dict (status, tx hash, gas used).
    """
    relayer = Account.from_key(relayer_key)
    account_address = to_checksum_address(blob["account"])
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
        "gas": 500_000,
        "maxFeePerGas": max_fee,
        "maxPriorityFeePerGas": priority_fee,
        "data": "0x" + build_initialize_calldata(blob).hex(),
        "accessList": (),
        "authorizationList": [build_authorization(blob)],
    }
    signed = Account.sign_transaction(transaction, relayer.key)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    return {
        "chainId": chain_id,
        "account": account_address,
        "txHash": receipt["transactionHash"].to_0x_hex(),
        "status": receipt["status"],
        "gasUsed": receipt["gasUsed"],
        "blockNumber": receipt["blockNumber"],
    }


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
