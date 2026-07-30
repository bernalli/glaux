"""Parity tests: the storage arithmetic in reconcile.py against the committed
fixture that test/StorageParity.t.sol generated from the real compiler.

The fixture is asserted from both languages. The Solidity side proves the
derived slot formula finds the values the compiler actually wrote; this side
proves the Python re-implementation — key derivation AND decoding — lands on
the same bytes. Either side changing alone turns the fixture red.
"""

import json
from pathlib import Path

import pytest
from reconcile import (
    BASE_SLOT,
    IMPL_SLOT,
    data_slot,
    decode_bytes,
    decode_header,
    header_slot,
    type_slot,
)

FIXTURE = (
    Path(__file__).resolve().parent.parent / "test" / "fixtures" / "storage_parity.json"
)


@pytest.fixture(scope="module")
def fx() -> dict:
    return json.loads(FIXTURE.read_text())


@pytest.fixture(scope="module")
def storage(fx: dict):
    table = {int(e["slot"], 16): int(e["value"], 16) for e in fx["entries"]}

    def read(slot: int) -> int:
        return table.get(slot, 0)

    return read


def test_the_slot_constants_match_the_contract() -> None:
    # keccak256("glaux.account.v1.storage") / keccak256("glaux.account.v1.implementation"),
    # pinned as literals so a typo in the seed strings cannot pass unnoticed.
    assert (
        BASE_SLOT == 0xC645EF19799BCCE32B2C21E3256A200E9914FA1C588F704BE7391B93BE01AE7F
    )
    assert (
        IMPL_SLOT == 0xECC57C70703AE87295636D5BF51AB33D95AD479D00483A780FA66C4613E2F3B8
    )


def test_base_slot_matches_the_fixture(fx: dict) -> None:
    assert BASE_SLOT == int(fx["base"], 16)


def test_header_decodes_to_the_expected_state(fx: dict, storage) -> None:
    initialized, update_nonce, exec_nonce = decode_header(storage(header_slot()))
    assert initialized is fx["expected"]["initialized"]
    assert update_nonce == fx["expected"]["updateNonce"]
    assert exec_nonce == fx["expected"]["execNonce"]


@pytest.mark.parametrize("i", [0, 1, 2])
def test_factor_slots_decode_to_the_expected_state(fx: dict, storage, i: int) -> None:
    assert storage(type_slot(i)) == fx["expected"]["slots"][i]["verifierType"]
    data = decode_bytes(storage, data_slot(i))
    assert data == bytes.fromhex(fx["expected"]["slots"][i]["data"].removeprefix("0x"))


def test_short_form_bytes_decode_in_word() -> None:
    # No production payload is short-form (32 and 64 bytes are both long-form),
    # but the decoder must not silently misread one if a future layout adds it:
    # payload left-aligned in the word, 2*len in the low byte, even header.
    payload = b"hi"
    word = int.from_bytes(payload + b"\x00" * 29 + bytes([2 * len(payload)]), "big")
    assert decode_bytes(lambda _slot: word, 0x1234) == payload


def test_long_form_spanning_two_words_decodes(fx: dict, storage) -> None:
    # The P-256 slot (index 1) is 64 bytes: exactly the two-word long form.
    data = decode_bytes(storage, data_slot(1))
    assert len(data) == 64
