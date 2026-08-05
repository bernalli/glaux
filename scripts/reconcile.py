"""Read-first reconciliation of a Glaux account across chains.

The account's getters -- ``getSlot``, ``updateNonce``, ``execNonce``,
``implementation()`` -- are answered by the implementation whose identity is
the thing reconciliation verifies, so this tool reads raw storage FIRST and
consults the getters only as a cross-check. A raw-vs-getter mismatch is itself
the finding (exit 2): an implementation that misreports its own state
invalidates every comparison built on its answers.

Order per chain (docs/client-guidance.md, normative):

1. ``eth_getCode(account)``       -> must be the EIP-7702 designator
   ``0xef0100 || router`` (23 bytes); anything else means the account is not a
   Glaux account on this chain and nothing below is meaningful.
2. ``eth_getStorageAt`` IMPL_SLOT -> the authoritative implementation pointer.
   The ERC-1967 slot is never read: Glaux does not write it and on a migrated
   account it may hold a stale foreign value.
3. ``eth_getCode(pointer)``       -> live code hash of the installed logic.
4. Raw namespaced state           -> packed header word + three factor slots.
5. The getters                    -> comparison only, never the source.

Exit codes: 0 all chains consistent; 1 chains diverge; 2 raw storage and
getters disagree on at least one chain (2 outranks 1).

Usage:
    python3 scripts/reconcile.py --account 0x... \\
        --rpc sepolia=$URL --rpc base-sepolia=$URL2 [--router 0x...] [--json]
"""

import argparse
import json
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from eth_abi import decode as abi_decode
from eth_abi import encode as abi_encode
from eth_utils import keccak, to_checksum_address

BASE_SLOT: int = int.from_bytes(keccak(text="glaux.account.v1.storage"), "big")
IMPL_SLOT: int = int.from_bytes(keccak(text="glaux.account.v1.implementation"), "big")
DESIGNATOR_PREFIX: bytes = bytes.fromhex("ef0100")
# ``SignatureVerify`` accepts only 32-byte secp256k1 key data or 64-byte
# P-256 coordinates, so a contract-born factor can never write more than 64.
MAX_FACTOR_DATA_LENGTH: int = 64
# Solidity's short ``bytes`` header keeps its low byte for ``2 * len``, so
# only the other 31 bytes can hold an in-word payload.
SHORT_BYTES_MAX_LENGTH: int = 31

SEL_UPDATE_NONCE: bytes = keccak(text="updateNonce()")[:4]
SEL_EXEC_NONCE: bytes = keccak(text="execNonce()")[:4]
SEL_IMPLEMENTATION: bytes = keccak(text="implementation()")[:4]
SEL_GET_SLOT: bytes = keccak(text="getSlot(uint8)")[:4]

Reader = Callable[[int], int]


def header_slot() -> int:
    """The packed header word: initialized, updateNonce, execNonce."""
    return BASE_SLOT


def type_slot(i: int) -> int:
    """The slot holding ``slots[i].verifierType``."""
    return BASE_SLOT + 1 + 2 * i


def data_slot(i: int) -> int:
    """The slot holding the ``bytes`` header of ``slots[i].data``."""
    return BASE_SLOT + 2 + 2 * i


def decode_header(word: int) -> tuple[bool, int, int]:
    """Unpack ``(initialized, updateNonce, execNonce)`` from the header word.

    Solidity packs the three fields from the low end: ``initialized`` at byte
    0, ``updateNonce`` at bytes 1-8, ``execNonce`` at bytes 9-16 -- proven by
    test/StorageParity.t.sol against the real compiler, not derived here.
    """
    return bool(word & 0xFF), (word >> 8) & (2**64 - 1), (word >> 72) & (2**64 - 1)


class MalformedFactorData(Exception):
    """A factor slot contains storage no Solidity ``bytes`` write can produce."""


class FactorDataTooLong(MalformedFactorData):
    """A factor slot's length word claims more data than its form can hold.

    Carries the offending ``length`` so the caller can report it verbatim: it
    is attacker-plantable evidence about the account, not a value to act on.
    """

    def __init__(self, length: int, *, short_form: bool = False) -> None:
        if short_form:
            message = (
                f"raw factor data short-form length {length} exceeds Solidity's "
                f"{SHORT_BYTES_MAX_LENGTH}-byte maximum"
            )
        else:
            message = (
                f"raw factor data length {length} exceeds Glaux's "
                f"{MAX_FACTOR_DATA_LENGTH}-byte maximum"
            )
        super().__init__(message)
        self.length: int = length


class FactorDataDirtyPadding(MalformedFactorData):
    """A short-form factor slot has non-zero bytes after its payload."""

    def __init__(self, length: int) -> None:
        super().__init__(
            "raw factor data short-form padding is non-zero past the declared "
            f"length {length}"
        )
        self.length: int = length


def decode_bytes(read: Reader, slot: int) -> bytes:
    """Decode a Solidity ``bytes`` value at ``slot``.

    Short form: payload left-aligned in the header word, ``2 * len`` in the
    low byte (even). Long form: ``2 * len + 1`` in the header word (odd),
    payload words starting at ``keccak256(slot)``.

    Raises ``FactorDataTooLong`` when a short-form marker exceeds Solidity's
    31-byte in-word limit or a long-form length exceeds
    ``MAX_FACTOR_DATA_LENGTH``, and ``FactorDataDirtyPadding`` when a
    short-form word carries non-zero bytes past its declared length. Both
    derive from ``MalformedFactorData``, which is what callers catch.
    """
    header = read(slot)
    if header & 1 == 0:
        length = (header & 0xFF) // 2
        # Solidity leaves one byte of this 32-byte word for the even length
        # marker, so a short-form payload can occupy at most the other 31.
        if length > SHORT_BYTES_MAX_LENGTH:
            raise FactorDataTooLong(length, short_form=True)
        word = header.to_bytes(32, "big")
        # solc 0.8.28 zeroes this padding on every short-form write, including
        # overwrites from long form, so non-zero bytes cannot be compiler-written.
        # Byte index 31 holds the marker and is excluded; only indices from the
        # declared length through index 30 are padding.
        if any(word[length:SHORT_BYTES_MAX_LENGTH]):
            raise FactorDataDirtyPadding(length)
        return word[:length]
    length = (header - 1) // 2
    # The length word is storage an attacker can plant, and it drives the read
    # loop below: bound it BEFORE deriving the payload base or issuing a single
    # payload read, or one planted word buys an unbounded number of RPC reads.
    if length > MAX_FACTOR_DATA_LENGTH:
        raise FactorDataTooLong(length)
    base = int.from_bytes(keccak(slot.to_bytes(32, "big")), "big")
    out = b""
    for j in range((length + 31) // 32):
        out += read(base + j).to_bytes(32, "big")
    return out[:length]


@dataclass(frozen=True)
class ChainState:
    """Everything reconciliation reads from one chain, raw side and getter side."""

    name: str
    active: bool
    # Non-empty code that is not this router's designator. Distinct from plain
    # inactivity: an account with NO code is simply not born on this chain yet,
    # which is legitimate, while an account delegated somewhere else is a
    # finding that must not be dropped from the comparison (see ``compare``).
    foreign_code: bool = False
    router: str | None = None
    impl_pointer: str | None = None
    impl_codehash: str | None = None
    initialized: bool | None = None
    update_nonce: int | None = None
    exec_nonce: int | None = None
    slots: tuple[tuple[int, str], ...] = ()
    getter_mismatches: tuple[str, ...] = field(default=())


def _call_getter(w3: Any, account: str, data: bytes) -> bytes:
    return bytes(w3.eth.call({"to": account, "data": data}))


def inspect_chain(w3: Any, name: str, account: str) -> ChainState:
    """Steps 1-5 for one chain: raw reads first, getters as cross-check only."""
    code = bytes(w3.eth.get_code(account))
    if code == b"":
        return ChainState(name=name, active=False)
    if len(code) != 23 or not code.startswith(DESIGNATOR_PREFIX):
        return ChainState(
            name=name,
            active=False,
            foreign_code=True,
            router=f"foreign code ({len(code)} bytes)",
        )
    router = to_checksum_address(code[3:])

    def read(slot: int) -> int:
        return int.from_bytes(bytes(w3.eth.get_storage_at(account, slot)), "big")

    impl_pointer = to_checksum_address(
        (read(IMPL_SLOT) & (2**160 - 1)).to_bytes(20, "big")
    )
    impl_code = bytes(w3.eth.get_code(impl_pointer))
    impl_codehash = (
        "0x" + keccak(impl_code).hex() if impl_code else "no code at pointer"
    )

    initialized, update_nonce, exec_nonce = decode_header(read(header_slot()))
    mismatches: list[str] = []
    raw_slots: list[tuple[int, str]] = []
    for i in range(3):
        verifier_type = read(type_slot(i))
        try:
            data = "0x" + decode_bytes(read, data_slot(i)).hex()
        except MalformedFactorData as exc:
            # One slot with a planted length must not blind the other two: the
            # anomaly is itself a finding (it makes the raw side unreadable and
            # so disagree with the getters), the remaining slots still read.
            data = "0x"
            mismatches.append(f"slot {i}: {exc}")
        raw_slots.append((verifier_type, data))
    slots = tuple(raw_slots)

    try:
        got = int.from_bytes(_call_getter(w3, account, SEL_UPDATE_NONCE), "big")
        if got != update_nonce:
            mismatches.append(f"updateNonce: raw {update_nonce} vs getter {got}")
        got = int.from_bytes(_call_getter(w3, account, SEL_EXEC_NONCE), "big")
        if got != exec_nonce:
            mismatches.append(f"execNonce: raw {exec_nonce} vs getter {got}")
        got_impl = to_checksum_address(
            abi_decode(["address"], _call_getter(w3, account, SEL_IMPLEMENTATION))[0]
        )
        if got_impl != impl_pointer:
            mismatches.append(
                f"implementation: raw {impl_pointer} vs getter {got_impl}"
            )
        for i in range(3):
            ret = _call_getter(w3, account, SEL_GET_SLOT + abi_encode(["uint8"], [i]))
            vt, data = abi_decode(["uint8", "bytes"], ret)
            if (vt, "0x" + bytes(data).hex()) != slots[i]:
                mismatches.append(
                    f"slot {i}: raw {slots[i]} vs getter {(vt, bytes(data).hex())}"
                )
    except Exception as exc:  # noqa: BLE001 -- a getter that reverts/errors is itself a finding
        mismatches.append(f"getter call failed: {exc}")

    return ChainState(
        name=name,
        active=True,
        router=router,
        impl_pointer=impl_pointer,
        impl_codehash=impl_codehash,
        initialized=initialized,
        update_nonce=update_nonce,
        exec_nonce=exec_nonce,
        slots=slots,
        getter_mismatches=tuple(mismatches),
    )


def compare(states: list[ChainState], expected_router: str | None) -> int:
    """Verdict across chains. ``execNonce`` is deliberately NOT compared
    cross-chain: executions are per-chain by design. What must agree is
    ``initialized``, ``updateNonce``, the factor slots, the implementation
    pointer and its live code hash, and the router.

    A chain with NO code at the account is excluded from the comparison: the
    account is simply not born there yet, which is legitimate. A chain whose
    account carries FOREIGN code is not excluded -- it has been delegated
    somewhere that is not this router, and dropping it would answer
    "consistent" for an account that is a Glaux account on one chain and
    something else entirely on another. Foreign code at the account address is
    a finding on its own terms, with nothing needed to contradict it: reaching
    that state at all means something re-delegated the account, and a lone
    observation of it is exactly the case an operator must not read as a clean
    bill of health."""
    if not states:
        raise ValueError("reconciliation requires at least one observed chain")
    exit_code = 0
    active = [s for s in states if s.active]
    foreign = [s for s in states if s.foreign_code]
    for s in active:
        if s.getter_mismatches:
            exit_code = 2
    if expected_router is not None:
        want = to_checksum_address(expected_router)
        if any(s.router != want for s in active) and exit_code < 2:
            exit_code = 1
    if foreign and exit_code < 2:
        exit_code = 1
    if len(active) >= 2:
        first = active[0]
        for s in active[1:]:
            diverges = (
                s.initialized != first.initialized
                or s.update_nonce != first.update_nonce
                or s.slots != first.slots
                or s.impl_pointer != first.impl_pointer
                or s.impl_codehash != first.impl_codehash
                or s.router != first.router
            )
            if diverges and exit_code < 2:
                exit_code = 1
    return exit_code


def _report(states: list[ChainState], verdict: int, as_json: bool) -> None:
    if as_json:
        print(
            json.dumps(
                {"verdict": verdict, "chains": [s.__dict__ for s in states]}, indent=2
            )
        )
        return
    for s in states:
        print(f"== {s.name}")
        if not s.active:
            note = s.router or "not yet active (no code at the account)"
            print(f"   {note}")
            continue
        print(f"   router:        {s.router}")
        print(f"   impl pointer:  {s.impl_pointer}")
        print(f"   impl codehash: {s.impl_codehash}")
        print(f"   initialized:   {s.initialized}")
        print(f"   updateNonce:   {s.update_nonce}   execNonce: {s.exec_nonce}")
        for i, (vt, data) in enumerate(s.slots):
            print(f"   slot {i}: type {vt}  data {data}")
        if s.getter_mismatches:
            print(
                "   RAW-VS-GETTER MISMATCH (the implementation misreports its state):"
            )
            for m in s.getter_mismatches:
                print(f"     - {m}")
    labels = {0: "consistent", 1: "CHAINS DIVERGE", 2: "RAW-VS-GETTER MISMATCH"}
    print(f"verdict: {labels[verdict]} (exit {verdict})")


def main() -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Read-first reconciliation of a Glaux account across chains."
    )
    parser.add_argument("--account", required=True, help="the Glaux account address")
    parser.add_argument(
        "--rpc",
        action="append",
        required=True,
        metavar="NAME=URL",
        help="chain to inspect, repeatable",
    )
    parser.add_argument(
        "--router", help="expected router address (else compared across chains)"
    )
    parser.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args()

    from web3 import Web3

    account = to_checksum_address(args.account)
    states: list[ChainState] = []
    for spec in args.rpc:
        name, _, url = spec.partition("=")
        if not url:
            parser.error(f"--rpc wants NAME=URL, got {spec!r}")
        w3 = Web3(Web3.HTTPProvider(url))
        states.append(inspect_chain(w3, name, account))

    verdict = compare(states, args.router)
    _report(states, verdict, args.as_json)
    return verdict


if __name__ == "__main__":
    sys.exit(main())
