"""Parity tests: the storage arithmetic in reconcile.py against the committed
fixture that test/StorageParity.t.sol generated from the real compiler.

The fixture is asserted from both languages. The Solidity side proves the
derived slot formula finds the values the compiler actually wrote; this side
proves the Python re-implementation — key derivation AND decoding — lands on
the same bytes. Either side changing alone turns the fixture red.
"""

import json
from pathlib import Path
from typing import Any

import pytest
from eth_abi import decode as abi_decode
from eth_abi import encode as abi_encode
from eth_utils import to_checksum_address
from reconcile import (
    BASE_SLOT,
    IMPL_SLOT,
    MAX_FACTOR_DATA_LENGTH,
    SEL_EXEC_NONCE,
    SEL_GET_SLOT,
    SEL_IMPLEMENTATION,
    SEL_UPDATE_NONCE,
    ChainState,
    FactorDataDirtyPadding,
    FactorDataTooLong,
    compare,
    data_slot,
    decode_bytes,
    decode_header,
    header_slot,
    inspect_chain,
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


def test_empty_observation_set_is_refused() -> None:
    with pytest.raises(ValueError, match="at least one observed chain"):
        compare([], None)


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


# --- The factor data cap (audit finding I-3) ------------------------------
#
# The long-form length lives in a storage word an attacker can plant, and it
# decides how many further words the decoder reads. Uncapped, one planted word
# buys an unbounded number of RPC reads; the TypeScript port measured 5001
# reads before it was capped. These tests pin the Python side to the same
# behaviour: refuse past the cap, without reading the payload at all.


def test_planted_over_long_length_is_refused_before_any_payload_read() -> None:
    reads: list[int] = []

    def read(slot: int) -> int:
        reads.append(slot)
        return 2 * 160000 + 1  # long form claiming 160000 bytes = 5000 words

    with pytest.raises(FactorDataTooLong) as excinfo:
        decode_bytes(read, data_slot(0))
    assert excinfo.value.length == 160000
    # Exactly the header word: the refusal happens before the read loop, so a
    # planted length costs the caller one RPC round trip, not five thousand.
    assert reads == [data_slot(0)]


def test_the_cap_admits_sixty_four_bytes_and_refuses_sixty_five(
    fx: dict, storage
) -> None:
    # The committed fixture is ground truth from Solidity's real storage
    # layout. Do not replace it with a hand-written bytes encoder: that would
    # merely duplicate the decoder assumptions this boundary test must check.
    slot = data_slot(1)
    payload = bytes.fromhex(fx["expected"]["slots"][1]["data"].removeprefix("0x"))
    assert len(payload) == MAX_FACTOR_DATA_LENGTH == 64
    assert decode_bytes(storage, slot) == payload

    # The decoder must reject from this header alone. Indexing the one-entry
    # table makes any accidental payload read fail instead of returning zeros.
    over_cap = {slot: 2 * (MAX_FACTOR_DATA_LENGTH + 1) + 1}
    with pytest.raises(FactorDataTooLong) as excinfo:
        decode_bytes(lambda requested: over_cap[requested], slot)
    assert excinfo.value.length == MAX_FACTOR_DATA_LENGTH + 1


ACCOUNT = to_checksum_address("0x" + "aa" * 20)
ROUTER = to_checksum_address("0x" + "b0" * 20)
IMPL = to_checksum_address("0x" + "c0" * 20)
DESIGNATOR = bytes.fromhex("ef0100") + bytes.fromhex(ROUTER[2:])


class _FakeEth:
    """Duck-typed stand-in for ``w3.eth`` over a planted storage table.

    The poisoned slot's getter deliberately returns the account's real,
    non-empty factor data while raw decoding refuses its hostile length word.
    Returning empty data here would make the fake agree with the raw fallback,
    suppress the getter-comparison note, and turn the ordering proof vacuous.
    """

    def __init__(self, storage: dict[int, int], slots: dict[int, bytes]) -> None:
        self._storage = storage
        self._slots = slots

    def get_code(self, address: str) -> bytes:
        return DESIGNATOR if address == ACCOUNT else bytes.fromhex("6000")

    def get_storage_at(self, _address: str, position: int) -> bytes:
        return self._storage.get(position, 0).to_bytes(32, "big")

    def call(self, tx: dict[str, Any]) -> bytes:
        data = bytes(tx["data"])
        selector = data[:4]
        if selector == SEL_UPDATE_NONCE:
            return (7).to_bytes(32, "big")
        if selector == SEL_EXEC_NONCE:
            return (3).to_bytes(32, "big")
        if selector == SEL_IMPLEMENTATION:
            return abi_encode(["address"], [IMPL])
        if selector == SEL_GET_SLOT:
            i = abi_decode(["uint8"], data[4:])[0]
            verifier_type = self._storage.get(type_slot(i), 0)
            return abi_encode(["uint8", "bytes"], [verifier_type, self._slots[i]])
        raise AssertionError(f"unexpected getter call {selector.hex()}")


class _FakeWeb3:
    def __init__(self, storage: dict[int, int], slots: dict[int, bytes]) -> None:
        self.eth = _FakeEth(storage, slots)


class _DirtyImplementationEth(_FakeEth):
    def call(self, tx: dict[str, Any]) -> bytes:
        data = bytes(tx["data"])
        if data[:4] == SEL_IMPLEMENTATION:
            # Same low 20 bytes as IMPL, but a non-zero byte in the 12-byte
            # ABI padding prefix. `eth_abi` must reject this address word.
            return b"\x01" + b"\x00" * 11 + bytes.fromhex(IMPL[2:])
        return super().call(tx)


class _DirtyImplementationWeb3:
    def __init__(self, storage: dict[int, int], slots: dict[int, bytes]) -> None:
        self.eth = _DirtyImplementationEth(storage, slots)


# The identical bytes the sibling TypeScript test plants: canonical ABI for
# ``(uint8, bytes)`` except for one junk byte in the padding that follows the
# two-byte payload. ``eth_abi`` raises NonEmptyPaddingBytes here; viem masks the
# byte away and decodes it as if it were clean.
DIRTY_GET_SLOT_RETURN = (
    (1).to_bytes(32, "big")  # uint8 verifierType, matching the raw type slot
    + (0x40).to_bytes(32, "big")  # offset of the bytes payload
    + (2).to_bytes(32, "big")  # payload length
    + bytes.fromhex("aabb")
    + b"\x00" * 29
    + b"\x7f"  # junk parked in the payload's trailing padding
)


class _DirtyGetSlotEth(_FakeEth):
    """``getSlot(0)`` answers with the account's real state, encoded with one
    junk byte in the trailing padding of its ``bytes`` field."""

    def call(self, tx: dict[str, Any]) -> bytes:
        data = bytes(tx["data"])
        if data[:4] == SEL_GET_SLOT and abi_decode(["uint8"], data[4:])[0] == 0:
            return DIRTY_GET_SLOT_RETURN
        return super().call(tx)


class _DirtyGetSlotWeb3:
    def __init__(self, storage: dict[int, int], slots: dict[int, bytes]) -> None:
        self.eth = _DirtyGetSlotEth(storage, slots)


def test_inspect_chain_orders_raw_anomaly_before_getter_comparison(fx: dict) -> None:
    storage = {int(e["slot"], 16): int(e["value"], 16) for e in fx["entries"]}
    storage[IMPL_SLOT] = int(IMPL, 16)
    storage[header_slot()] = 1 | (7 << 8) | (3 << 72)
    storage[data_slot(1)] = 2 * 160000 + 1  # the planted length

    # These are the real compiler-fixture payloads. In particular, slot 1 must
    # stay non-empty and differ from the raw side's unreadable-data fallback;
    # otherwise this test stops exercising getter-note ordering.
    getter_slots = {
        i: bytes.fromhex(slot["data"].removeprefix("0x"))
        for i, slot in enumerate(fx["expected"]["slots"])
    }

    state: ChainState = inspect_chain(
        _FakeWeb3(storage, getter_slots), "sepolia", ACCOUNT
    )

    anomaly_note = (
        "slot 1: raw factor data length 160000 exceeds Glaux's "
        f"{MAX_FACTOR_DATA_LENGTH}-byte maximum"
    )
    getter_note = f"slot 1: raw {(2, '0x')} vs getter {(2, getter_slots[1].hex())}"
    assert anomaly_note in state.getter_mismatches
    assert getter_note in state.getter_mismatches
    assert state.getter_mismatches.index(anomaly_note) < state.getter_mismatches.index(
        getter_note
    )
    assert state.slots[0] == (
        1,
        fx["expected"]["slots"][0]["data"],
    )
    assert state.slots[1] == (2, "0x")
    assert state.slots[2] == (
        1,
        fx["expected"]["slots"][2]["data"],
    )
    assert compare([state], None) == 2


def test_dirty_implementation_address_padding_is_exit_two(fx: dict) -> None:
    storage = {int(e["slot"], 16): int(e["value"], 16) for e in fx["entries"]}
    storage[IMPL_SLOT] = int(IMPL, 16)
    storage[header_slot()] = 1 | (7 << 8) | (3 << 72)
    getter_slots = {
        i: bytes.fromhex(slot["data"].removeprefix("0x"))
        for i, slot in enumerate(fx["expected"]["slots"])
    }

    state = inspect_chain(
        _DirtyImplementationWeb3(storage, getter_slots),
        "dirty-implementation-padding",
        ACCOUNT,
    )

    assert compare([state], None) == 2
    assert len(state.getter_mismatches) == 1
    assert state.getter_mismatches[0].startswith("getter call failed:")


def test_dirty_get_slot_trailing_padding_is_exit_two(fx: dict) -> None:
    storage = {int(e["slot"], 16): int(e["value"], 16) for e in fx["entries"]}
    storage[IMPL_SLOT] = int(IMPL, 16)
    storage[header_slot()] = 1 | (7 << 8) | (3 << 72)
    # Raw slot 0 holds exactly the two bytes the dirty return decodes to once
    # its junk byte is masked away, so a lenient decoder would find getter and
    # raw in perfect agreement and reach exit 0: only strict decoding can move
    # this state to 2, which is what the assertion below is proving.
    storage[data_slot(0)] = int("aabb" + "00" * 29 + "04", 16)
    getter_slots = {
        i: bytes.fromhex(slot["data"].removeprefix("0x"))
        for i, slot in enumerate(fx["expected"]["slots"])
    }
    getter_slots[0] = bytes.fromhex("aabb")

    state = inspect_chain(
        _DirtyGetSlotWeb3(storage, getter_slots),
        "dirty-get-slot-padding",
        ACCOUNT,
    )

    # Parity invariant: this identical return vector is Python exit 2 here and
    # TypeScript `unreadable` in the sibling reconcile test.
    assert compare([state], None) == 2
    assert state.slots[0] == (1, "0xaabb")
    assert len(state.getter_mismatches) == 1
    assert state.getter_mismatches[0].startswith("getter call failed:")


def test_clean_get_slot_padding_is_exit_zero(fx: dict) -> None:
    # Twin of the test above, with the junk byte zeroed: the same state, encoded
    # the way the real account encodes it, must still reconcile cleanly. Without
    # it, a decoder that refused every getSlot return would satisfy the parity
    # assertion above.
    storage = {int(e["slot"], 16): int(e["value"], 16) for e in fx["entries"]}
    storage[IMPL_SLOT] = int(IMPL, 16)
    storage[header_slot()] = 1 | (7 << 8) | (3 << 72)
    storage[data_slot(0)] = int("aabb" + "00" * 29 + "04", 16)
    getter_slots = {
        i: bytes.fromhex(slot["data"].removeprefix("0x"))
        for i, slot in enumerate(fx["expected"]["slots"])
    }
    getter_slots[0] = bytes.fromhex("aabb")

    state = inspect_chain(_FakeWeb3(storage, getter_slots), "clean-padding", ACCOUNT)

    assert compare([state], None) == 0
    assert state.getter_mismatches == ()


@pytest.mark.parametrize(("marker", "length"), [(0x40, 32), (0xFE, 127)])
def test_impossible_short_form_lengths_are_refused(marker: int, length: int) -> None:
    # Solidity stores the even 2*len marker in the final byte, leaving only 31
    # bytes in the header word for a short-form payload.
    with pytest.raises(FactorDataTooLong) as excinfo:
        decode_bytes(lambda _slot: marker, data_slot(0))

    assert excinfo.value.length == length
    assert str(excinfo.value) == (
        f"raw factor data short-form length {length} exceeds Solidity's 31-byte maximum"
    )


def test_largest_legal_short_form_still_decodes_all_thirty_one_bytes() -> None:
    # This fixed word is 31 payload bytes followed by Solidity's 2*31 marker;
    # keeping the expected bytes independent avoids duplicating decoder logic.
    word = int(
        "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f3e",
        16,
    )
    expected = bytes.fromhex(
        "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    )

    assert decode_bytes(lambda _slot: word, data_slot(0)) == expected


def test_impossible_short_form_drives_python_parity_verdict_to_exit_two(
    fx: dict,
) -> None:
    storage = {
        int(entry["slot"], 16): int(entry["value"], 16) for entry in fx["entries"]
    }
    storage[IMPL_SLOT] = int(IMPL, 16)
    storage[header_slot()] = 1 | (7 << 8) | (3 << 72)
    storage[data_slot(0)] = 0x40  # even marker 2*32: impossible Solidity short form
    getter_slots = {
        i: bytes.fromhex(slot["data"].removeprefix("0x"))
        for i, slot in enumerate(fx["expected"]["slots"])
    }

    state = inspect_chain(_FakeWeb3(storage, getter_slots), "parity", ACCOUNT)

    # Parity invariant: planted header 0x40 is Python exit 2 here and
    # TypeScript `unreadable` in the sibling reconcile test.
    assert compare([state], None) == 2
    assert state.getter_mismatches[0] == (
        "slot 0: raw factor data short-form length 32 exceeds Solidity's "
        "31-byte maximum"
    )


def test_short_form_dirty_padding_is_refused_but_its_zeroed_twin_decodes() -> None:
    payload = bytes.fromhex("aabb")
    dirty_word = int.from_bytes(
        payload + b"\x7f" + b"\x00" * 28 + bytes([2 * len(payload)]), "big"
    )
    clean_word = int.from_bytes(
        payload + b"\x00" * 29 + bytes([2 * len(payload)]), "big"
    )

    # solc 0.8.28 zeroes short-form padding even on overwrites, so the junk
    # byte is impossible compiler-written state. Index 31 is the marker and is
    # excluded: only indices from the declared length through 30 are padding.
    with pytest.raises(FactorDataDirtyPadding) as excinfo:
        decode_bytes(lambda _slot: dirty_word, data_slot(0))

    assert excinfo.value.length == len(payload)
    assert str(excinfo.value) == (
        "raw factor data short-form padding is non-zero past the declared length 2"
    )
    assert decode_bytes(lambda _slot: clean_word, data_slot(0)) == payload


def test_empty_short_form_with_a_non_zero_high_byte_is_refused() -> None:
    dirty_empty_word = int.from_bytes(b"\xff" + b"\x00" * 31, "big")

    with pytest.raises(FactorDataDirtyPadding) as excinfo:
        decode_bytes(lambda _slot: dirty_empty_word, data_slot(0))

    assert excinfo.value.length == 0
    assert str(excinfo.value) == (
        "raw factor data short-form padding is non-zero past the declared length 0"
    )


def test_untouched_all_zero_word_still_decodes_to_empty() -> None:
    assert decode_bytes(lambda _slot: 0, data_slot(0)) == b""


def test_junk_in_the_last_padding_byte_is_refused() -> None:
    # Index 30 is the LAST padding byte, the one immediately before the marker.
    # Without this word, shrinking the check's window to ``word[length:30]``
    # would pass every other test on both sides: the other planted words carry
    # their junk right after the payload, so only junk parked here can tell the
    # two windows apart.
    payload = bytes.fromhex("aabb")
    word = int.from_bytes(
        payload + b"\x00" * 28 + b"\x7f" + bytes([2 * len(payload)]), "big"
    )

    with pytest.raises(FactorDataDirtyPadding) as excinfo:
        decode_bytes(lambda _slot: word, data_slot(0))

    assert excinfo.value.length == len(payload)


def test_dirty_short_form_padding_drives_python_parity_verdict_to_exit_two(
    fx: dict,
) -> None:
    storage = {
        int(entry["slot"], 16): int(entry["value"], 16) for entry in fx["entries"]
    }
    storage[IMPL_SLOT] = int(IMPL, 16)
    storage[header_slot()] = 1 | (7 << 8) | (3 << 72)
    storage[data_slot(0)] = int(
        "aabb7f0000000000000000000000000000000000000000000000000000000004", 16
    )
    getter_slots = {
        i: bytes.fromhex(slot["data"].removeprefix("0x"))
        for i, slot in enumerate(fx["expected"]["slots"])
    }

    state = inspect_chain(_FakeWeb3(storage, getter_slots), "dirty-padding", ACCOUNT)

    # Parity invariant: this identical planted word is Python exit 2 here and
    # TypeScript `unreadable` in the sibling reconcile test.
    assert compare([state], None) == 2
    assert state.getter_mismatches[0] == (
        "slot 0: raw factor data short-form padding is non-zero past the "
        "declared length 2"
    )
