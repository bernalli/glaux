"""Unit tests for `preflight_fresh_account` (audit finding H-2).

A re-delegation does not clear EIP-7702 storage, so a birth blob must only be
broadcast to an address that has never been a delegate (or is retrying a
birth that reverted while already delegated to this blob's own router) and
whose Glaux namespaced slots — IMPL_SLOT and the header plus all three
FactorSlot entries — are zero (threat-model residual 17). These tests stub
`w3` so nothing touches the network.
"""

from typing import Any

import pytest
from eth_account import Account
from hexbytes import HexBytes
from submit_birth import (
    IMPL_SLOT,
    STORAGE_SLOT,
    assert_blob_authorization,
    preflight_fresh_account,
    submit_birth,
)

ZERO_WORD = b"\x00" * 32
NON_ZERO_WORD = b"\x00" * 31 + b"\x01"
ACCOUNT = "0x000000000000000000000000000000000000AA"
ROUTER = "0x" + "00" * 19 + "B0"
ROUTER_DESIGNATOR = bytes.fromhex("ef0100") + bytes.fromhex(ROUTER[2:])
# Throwaway relayer key, never funded on any chain: `submit_birth` only reaches
# `Account.from_key` AFTER the authorization gate, so a rejected blob never uses it.
RELAYER_KEY = "0x" + "33" * 32


class _StubEth:
    """Minimal stand-in for `w3.eth`: returns fixed code / storage regardless of input."""

    def __init__(self, code: bytes, slots: dict[int, bytes]) -> None:
        self._code = code
        self._slots = slots

    def get_code(self, _address: str) -> bytes:
        return self._code

    def get_storage_at(self, _address: str, position: int) -> bytes:
        return self._slots.get(position, ZERO_WORD)


class _StubWeb3:
    def __init__(self, code: bytes, slots: dict[int, bytes]) -> None:
        self.eth = _StubEth(code, slots)


def test_pristine_account_passes_preflight() -> None:
    w3 = _StubWeb3(code=b"", slots={})
    preflight_fresh_account(w3, ACCOUNT, ROUTER)  # must not raise


def test_reverted_birth_retry_toward_same_router_passes_preflight() -> None:
    w3 = _StubWeb3(code=ROUTER_DESIGNATOR, slots={})
    preflight_fresh_account(w3, ACCOUNT, ROUTER)  # must not raise


def test_delegated_to_other_router_is_rejected() -> None:
    other_designator = bytes.fromhex("ef0100" + "11" * 20)
    w3 = _StubWeb3(code=other_designator, slots={})
    with pytest.raises(SystemExit):
        preflight_fresh_account(w3, ACCOUNT, ROUTER)


def test_delegated_account_is_rejected() -> None:
    designator = bytes.fromhex("ef0100" + "00" * 20)
    w3 = _StubWeb3(code=designator, slots={})
    with pytest.raises(SystemExit):
        preflight_fresh_account(w3, ACCOUNT, ROUTER)


def test_pre_planted_implementation_slot_is_rejected() -> None:
    w3 = _StubWeb3(code=b"", slots={IMPL_SLOT: NON_ZERO_WORD})
    with pytest.raises(SystemExit):
        preflight_fresh_account(w3, ACCOUNT, ROUTER)


def test_pre_planted_storage_header_is_rejected() -> None:
    w3 = _StubWeb3(code=b"", slots={STORAGE_SLOT: NON_ZERO_WORD})
    with pytest.raises(SystemExit):
        preflight_fresh_account(w3, ACCOUNT, ROUTER)


def test_pre_planted_factor_slot_data_head_length_is_rejected() -> None:
    """H-2 hole (1): a forged `bytes data` length at STORAGE_SLOT+2 (slot 0's data
    head) passed the old preflight, which only checked IMPL_SLOT and the header."""
    w3 = _StubWeb3(code=b"", slots={STORAGE_SLOT + 2: NON_ZERO_WORD})
    with pytest.raises(SystemExit):
        preflight_fresh_account(w3, ACCOUNT, ROUTER)


def test_pre_planted_factor_slot_verifier_type_is_rejected() -> None:
    w3 = _StubWeb3(code=b"", slots={STORAGE_SLOT + 1: NON_ZERO_WORD})
    with pytest.raises(SystemExit):
        preflight_fresh_account(w3, ACCOUNT, ROUTER)


def _authorization_blob(nonce: int = 0) -> dict:
    private_key = "0x" + "11" * 32
    account = Account.from_key(private_key).address
    authorization = Account.sign_authorization(
        {"chainId": 0, "address": ROUTER, "nonce": nonce}, private_key
    )
    return {
        "account": account,
        "router": ROUTER,
        "authorization": {
            "chainId": authorization.chain_id,
            "address": "0x" + authorization.address.hex(),
            "nonce": authorization.nonce,
            "yParity": authorization.y_parity,
            "r": hex(authorization.r),
            "s": hex(authorization.s),
        },
    }


def test_authorization_signer_and_zero_chain_id_are_accepted() -> None:
    assert_blob_authorization(_authorization_blob())


def test_authorization_for_a_different_eoa_is_rejected() -> None:
    blob = _authorization_blob()
    blob["account"] = "0x" + "22" * 20
    with pytest.raises(SystemExit, match="signer does not equal blob account"):
        assert_blob_authorization(blob)


def test_chain_specific_authorization_is_rejected() -> None:
    blob = _authorization_blob()
    blob["authorization"]["chainId"] = 1
    with pytest.raises(SystemExit, match="chainId must be 0"):
        assert_blob_authorization(blob)


def test_authorization_with_a_non_zero_nonce_is_rejected() -> None:
    """Only nonce 0 makes a retained blob replayable on every chain.

    EIP-7702 checks the tuple's nonce against the authority's CURRENT account
    nonce, and a birth key never sends a transaction of its own, so every chain
    sees it at 0 forever. This tuple is signed FOR nonce 5 by the blob's own
    account over the canonical router with chainId 0, so it recovers cleanly
    and every other gate in `assert_blob_authorization` passes it: the nonce is
    the only thing left to refuse it for.
    """
    blob = _authorization_blob(nonce=5)
    assert blob["authorization"]["nonce"] == 5
    with pytest.raises(SystemExit, match="nonce must be 0"):
        assert_blob_authorization(blob)


class _ExplodingEth:
    """Any RPC access at all is a test failure, not a stubbed answer."""

    def __getattr__(self, name: str) -> Any:
        raise AssertionError(
            f"submit_birth touched the chain (w3.eth.{name}) instead of refusing the blob"
        )


class _ExplodingWeb3:
    def __init__(self) -> None:
        self.eth = _ExplodingEth()


def test_submit_birth_refuses_an_authorization_signed_by_another_key() -> None:
    """The authorization gate must hold on the PUBLIC path, not only when called directly.

    `submit_birth` runs `assert_blob_authorization` ahead of the pre-birth
    storage preflight and of any transaction building, so a blob whose
    EIP-7702 tuple was signed by a key other than `blob["account"]` must be
    refused without a single RPC call: the `_ExplodingWeb3` stub turns any
    read — `get_code`, `get_storage_at`, `chain_id`, the gas estimate — into a
    failure, which is what makes "nothing downstream was reached" an assertion
    rather than an assumption.
    """
    blob = _authorization_blob()
    blob["account"] = "0x" + "22" * 20
    blob["implementation"] = "0x" + "33" * 20
    blob["expectedCodeHash"] = "0x" + "44" * 32
    blob["initData"] = "0x"
    blob["salt"] = "0x" + "00" * 32

    with pytest.raises(SystemExit, match="signer does not equal blob account"):
        submit_birth(_ExplodingWeb3(), RELAYER_KEY, blob)


def _submittable_blob() -> dict:
    """A blob that passes every gate, so only the receipt decides the outcome."""
    blob = _authorization_blob()
    blob["implementation"] = "0x" + "33" * 20
    blob["expectedCodeHash"] = "0x" + "44" * 32
    blob["initData"] = "0x"
    blob["salt"] = "0x" + "00" * 32
    return blob


class _MinedEth:
    """Every RPC the birth path needs, answering with a receipt of ``status``.

    The account is a pristine EOA (empty code, all-zero Glaux slots) and the
    gas estimate is plausible, so the transaction is built, signed and sent for
    real: the mined receipt is the only thing left that can decide the outcome.
    """

    chain_id = 31337
    max_priority_fee = 1_000_000_000
    # `latest_block.get("baseFeePerGas", w3.eth.gas_price)` evaluates its
    # default eagerly, so this is read on every call even on an EIP-1559 chain.
    gas_price = 1_000_000_000

    def __init__(self, status: int) -> None:
        self._status = status

    def get_code(self, _address: str) -> bytes:
        return b""

    def get_storage_at(self, _address: str, _position: int) -> bytes:
        return ZERO_WORD

    def get_block(self, _block: str) -> dict[str, Any]:
        return {"baseFeePerGas": 1_000_000_000}

    def get_transaction_count(self, _address: str) -> int:
        return 0

    def estimate_gas(self, _transaction: dict[str, Any]) -> int:
        return 500_000

    def send_raw_transaction(self, _raw: bytes) -> HexBytes:
        return HexBytes(b"\xab" * 32)

    def wait_for_transaction_receipt(self, tx_hash: HexBytes) -> dict[str, Any]:
        return {
            "transactionHash": tx_hash,
            "status": self._status,
            "gasUsed": 420_000,
            "blockNumber": 99,
        }


class _MinedWeb3:
    def __init__(self, status: int) -> None:
        self.eth = _MinedEth(status)


def test_reverted_birth_receipt_is_not_reported_as_success() -> None:
    """A mined-but-reverted birth left the account uninitialized.

    EIP-7702 still applies the authorization when the call in the same
    transaction reverts, so the account ends up delegated with none of its
    factor slots installed. Printing that receipt and exiting 0 would record a
    failed birth as done in whatever automation invoked this script.
    """
    with pytest.raises(SystemExit) as excinfo:
        submit_birth(_MinedWeb3(status=0), RELAYER_KEY, _submittable_blob())

    assert excinfo.value.code != 0
    assert "REVERTED" in str(excinfo.value.code)
    assert "0x" + "ab" * 32 in str(excinfo.value.code)


def test_successful_birth_receipt_is_returned() -> None:
    # The twin that keeps the check above honest: an ordinary status-1 receipt
    # must still come back as the printable result it always was.
    result = submit_birth(_MinedWeb3(status=1), RELAYER_KEY, _submittable_blob())

    assert result["status"] == 1
    assert result["txHash"] == "0x" + "ab" * 32
    assert result["chainId"] == 31337
