"""Unit tests for `preflight_fresh_account` (audit finding H-2).

A re-delegation does not clear EIP-7702 storage, so a birth blob must only be
broadcast to an address that has never been a delegate (or is retrying a
birth that reverted while already delegated to this blob's own router) and
whose Glaux namespaced slots — IMPL_SLOT and the header plus all three
FactorSlot entries — are zero (threat-model residual 17). These tests stub
`w3` so nothing touches the network.
"""

import pytest
from eth_account import Account
from submit_birth import (
    IMPL_SLOT,
    STORAGE_SLOT,
    assert_blob_authorization,
    preflight_fresh_account,
)

ZERO_WORD = b"\x00" * 32
NON_ZERO_WORD = b"\x00" * 31 + b"\x01"
ACCOUNT = "0x000000000000000000000000000000000000AA"
ROUTER = "0x" + "00" * 19 + "B0"
ROUTER_DESIGNATOR = bytes.fromhex("ef0100") + bytes.fromhex(ROUTER[2:])


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


def _authorization_blob() -> dict:
    private_key = "0x" + "11" * 32
    account = Account.from_key(private_key).address
    authorization = Account.sign_authorization(
        {"chainId": 0, "address": ROUTER, "nonce": 0}, private_key
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
