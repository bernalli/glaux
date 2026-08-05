"""Unit tests for `preflight_fresh_account` (audit finding H-2).

A re-delegation does not clear EIP-7702 storage, so a birth blob must only be
broadcast to an address that has never been a delegate (or is retrying a
birth that reverted while already delegated to this blob's own router) and
whose Glaux namespaced slots — IMPL_SLOT and the header plus all three
FactorSlot entries — are zero (threat-model residual 17). These tests stub
`w3` so nothing touches the network.
"""

import json
from pathlib import Path
from typing import Any

import birth
import pytest
import submit_birth as submitter
from eth_account.typed_transactions.set_code_transaction import Authorization
from eth_keys.datatypes import Signature
from eth_utils import to_bytes
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
CANONICAL_ROUTER = "0x3ccF1cc0F702C084B31e691e057d8742ADF35790"
CANONICAL_IMPLEMENTATION = "0x21b5D576AB4188Ee06DD866b6Fd4a23085A73f5d"
CANONICAL_IMPL_CODE_HASH = (
    "0xb32d638ed9bd6329b5b2f27e9dcaa3a9fc65f396315f67eef276cd6f89ac9106"
)


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


def _rootless_blob(
    *,
    router: str = CANONICAL_ROUTER,
    expected_code_hash: str = CANONICAL_IMPL_CODE_HASH,
) -> dict:
    init_data = b""
    digest = birth.build_init_digest(
        router,
        CANONICAL_IMPLEMENTATION,
        to_bytes(hexstr=expected_code_hash),
        init_data,
    )
    proof = birth.craft_rootless_authorization(digest, router)
    return {
        "account": proof.account,
        "router": router,
        "implementation": CANONICAL_IMPLEMENTATION,
        "expectedCodeHash": expected_code_hash,
        "initData": "0x",
        "salt": "0x" + proof.salt.hex(),
        "authorization": {
            "chainId": 0,
            "address": router,
            "nonce": 0,
            "yParity": proof.y_parity,
            "r": "0x" + proof.r.hex(),
            "s": hex(proof.s),
        },
    }


def test_authorization_signer_and_zero_chain_id_are_accepted() -> None:
    assert_blob_authorization(_rootless_blob())


def test_authorization_for_a_different_eoa_is_rejected() -> None:
    blob = _rootless_blob()
    blob["account"] = "0x" + "22" * 20
    with pytest.raises(SystemExit, match="does not recover to blob account"):
        assert_blob_authorization(blob)


def test_chain_specific_authorization_is_rejected() -> None:
    blob = _rootless_blob()
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
    blob = _rootless_blob()
    blob["authorization"]["nonce"] = 5
    assert blob["authorization"]["nonce"] == 5
    with pytest.raises(SystemExit, match="nonce must be 0"):
        assert_blob_authorization(blob)


def test_python_canonical_constants_match_shared_parity_fixture() -> None:
    fixture_path = (
        Path(__file__).resolve().parent.parent
        / "test"
        / "fixtures"
        / "sdk_parity.json"
    )
    canonical = json.loads(fixture_path.read_text(encoding="utf-8"))["canonical"]

    assert submitter.CANONICAL_ROUTER == canonical["router"]
    assert submitter.CANONICAL_IMPL_CODE_HASH == canonical["expectedCodeHash"]


def test_noncanonical_router_is_rejected_before_rpc() -> None:
    blob = _rootless_blob(router="0x" + "55" * 20)

    with pytest.raises(SystemExit, match="router is not canonical") as excinfo:
        submit_birth(_ExplodingWeb3(), RELAYER_KEY, blob)

    assert type(excinfo.value).__name__ == "InvalidBirthBlobError"


def test_noncanonical_expected_code_hash_is_rejected_before_rpc() -> None:
    blob = _rootless_blob(expected_code_hash="0x" + "66" * 32)

    with pytest.raises(SystemExit, match="expectedCodeHash is not canonical") as excinfo:
        submit_birth(_ExplodingWeb3(), RELAYER_KEY, blob)

    assert type(excinfo.value).__name__ == "InvalidBirthBlobError"


def test_authorization_r_not_bound_to_init_fields_is_rejected_before_rpc() -> None:
    """A COMPLETE proof, crafted for different init data, presented for this blob.

    It stays internally coherent — the tuple really does recover to the account
    it names — so every self-consistency check passes and only recomputing `r`
    from the blob's own configuration catches it. Swapping `initData` alone
    would not isolate this: the recovery check would fire first, and the `r`
    check could be deleted without a single test going red.
    """
    blob = _rootless_blob()
    foreign_digest = birth.build_init_digest(
        CANONICAL_ROUTER,
        CANONICAL_IMPLEMENTATION,
        to_bytes(hexstr=CANONICAL_IMPL_CODE_HASH),
        b"\x01",
    )
    foreign = birth.craft_rootless_authorization(foreign_digest, CANONICAL_ROUTER)
    # Only the TRANSMITTED r is foreign. Salt and s stay this blob's own, so the
    # recovery check still passes and this isolates the binding check alone.
    blob["authorization"]["r"] = "0x" + foreign.r.hex()

    with pytest.raises(SystemExit) as excinfo:
        submit_birth(_ExplodingWeb3(), RELAYER_KEY, blob)

    # Assert the FIELD, not the message: "authorization r" is a substring of
    # "authorization rootless proof", so a message match would stay green while
    # a different guard did the work.
    assert type(excinfo.value).__name__ == "InvalidBirthBlobError"
    assert excinfo.value.field == "authorization r"


def test_authorization_without_rootless_s_prefix_is_rejected_before_rpc() -> None:
    blob = _rootless_blob()
    authorization = blob["authorization"]
    untagged_s = 1
    unsigned = Authorization(
        authorization["chainId"],
        to_bytes(hexstr=authorization["address"]),
        authorization["nonce"],
    )
    signer = Signature(
        vrs=(authorization["yParity"], int(authorization["r"], 16), untagged_s)
    ).recover_public_key_from_msg_hash(unsigned.hash())
    blob["account"] = signer.to_checksum_address()
    authorization["s"] = hex(untagged_s)

    with pytest.raises(SystemExit, match="rootless proof") as excinfo:
        submit_birth(_ExplodingWeb3(), RELAYER_KEY, blob)

    assert type(excinfo.value).__name__ == "InvalidBirthBlobError"


def test_parity_one_authorization_is_rejected_before_rpc() -> None:
    blob = _rootless_blob()
    authorization = blob["authorization"]
    unsigned = Authorization(
        authorization["chainId"],
        to_bytes(hexstr=authorization["address"]),
        authorization["nonce"],
    )
    signer = Signature(
        vrs=(1, int(authorization["r"], 16), int(authorization["s"], 16))
    ).recover_public_key_from_msg_hash(unsigned.hash())
    blob["account"] = signer.to_checksum_address()
    authorization["yParity"] = 1

    with pytest.raises(SystemExit, match="yParity must be 0") as excinfo:
        submit_birth(_ExplodingWeb3(), RELAYER_KEY, blob)

    assert type(excinfo.value).__name__ == "InvalidBirthBlobError"


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
    blob = _rootless_blob()
    blob["account"] = "0x" + "22" * 20

    with pytest.raises(SystemExit, match="does not recover to blob account"):
        submit_birth(_ExplodingWeb3(), RELAYER_KEY, blob)


def _submittable_blob() -> dict:
    """A blob that passes every gate, so only the receipt decides the outcome."""
    return _rootless_blob()


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

    def __init__(self, status: int, installed_implementation: str | None = None) -> None:
        self._status = status
        self._installed_implementation = installed_implementation
        self._mined = False

    def get_code(self, _address: str) -> bytes:
        return b""

    def get_storage_at(self, _address: str, position: int) -> bytes:
        if (
            self._mined
            and position == IMPL_SLOT
            and self._installed_implementation is not None
        ):
            return bytes.fromhex("00" * 12 + self._installed_implementation[2:])
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
        self._mined = True
        return {
            "transactionHash": tx_hash,
            "status": self._status,
            "gasUsed": 420_000,
            "blockNumber": 99,
        }


class _MinedWeb3:
    def __init__(self, status: int, installed_implementation: str | None = None) -> None:
        self.eth = _MinedEth(status, installed_implementation)


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
    result = submit_birth(
        _MinedWeb3(
            status=1,
            installed_implementation=CANONICAL_IMPLEMENTATION,
        ),
        RELAYER_KEY,
        _submittable_blob(),
    )

    assert result["status"] == 1
    assert result["txHash"] == "0x" + "ab" * 32
    assert result["chainId"] == 31337


def test_status_one_without_installed_implementation_is_not_reported_as_success() -> None:
    blob = _submittable_blob()

    with pytest.raises(SystemExit) as excinfo:
        submit_birth(_MinedWeb3(status=1), RELAYER_KEY, blob)

    message = str(excinfo.value.code)
    assert type(excinfo.value).__name__ == "BirthPostconditionError"
    assert blob["account"] in message
    assert "0x" + "ab" * 32 in message
    assert "0x" + "00" * 32 in message
