"""Generate a Glaux account-birth blob.

Births are rootless: **no key is created here, and none is destroyed
afterwards, because none ever exists.** The chain-agnostic init digest binding
the three factor slots (paper/device/cloud) is computed first, and then an
EIP-7702 authorization tuple (``chainId=0``, ``nonce=0``, ``address=<router>``)
is CRAFTED rather than signed: ``r`` is derived from the digest, ``s`` carries
the ``ROOTLESS_S_PREFIX`` tag, and the account is whatever address that tuple
recovers to. Nobody holds a key for it, so nobody can birth it into a different
configuration — the property the ephemeral "birth key" of earlier versions had
to be trusted to destroy.

The resulting JSON blob (crafted authorization tuple + init data + salt) is
chain-agnostic by construction: it can be submitted, unmodified, to any chain
where the same ``GlauxDelegate``/``GlauxAccount`` bytecode was deployed
deterministically via CREATE2, producing the same account address with the
same configuration everywhere.

Usage (each proof is the output of scripts/prove_possession.py, run by that
factor's own holder):
    python3 scripts/birth.py \\
        --router 0x... --impl 0x... --expected-code-hash 0x... \\
        --paper 0x<address> --device-qx 0x... --device-qy 0x... --cloud 0x<address> \\
        --paper-proof 0x... --device-proof 0x... --cloud-proof 0x...
"""

import argparse
import json
from dataclasses import dataclass
from typing import Any

from eth_abi import encode
from eth_keys.datatypes import Signature
from eth_keys.exceptions import BadSignature, ValidationError
from eth_utils import keccak, to_bytes, to_checksum_address

INIT_DOMAIN = keccak(text="GLAUX_INIT_V1")
REG_DOMAIN = keccak(text="GLAUX_REG_V1")

VERIFIER_SECP256K1 = 1
VERIFIER_P256 = 2

SECP256K1_N_DIV_2 = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0


def _hex_to_int(value: str) -> int:
    """Parse a `0x`-prefixed (or bare decimal) string into an int."""
    return int(value, 0)


def _encode_slot(verifier_type: int, data: bytes) -> tuple[int, bytes]:
    """Build the `(uint8 verifierType, bytes data)` tuple for one factor slot."""
    return (verifier_type, data)


def build_slots(
    paper_address: str,
    device_qx: int,
    device_qy: int,
    cloud_address: str,
) -> list[tuple[int, bytes]]:
    """Build the three pairwise-distinct factor slots (paper, device, cloud).

    Slot 0 is the paper secp256k1 factor, slot 1 is the device P-256 factor,
    slot 2 is the cloud secp256k1 factor. The contract rejects the blob with
    `DuplicateSlot()` if any two slots are identical, so callers must supply
    distinct keys for the paper and cloud factors.
    """
    paper_data = encode(["address"], [to_checksum_address(paper_address)])
    device_data = encode(["uint256", "uint256"], [device_qx, device_qy])
    cloud_data = encode(["address"], [to_checksum_address(cloud_address)])
    return [
        _encode_slot(VERIFIER_SECP256K1, paper_data),
        _encode_slot(VERIFIER_P256, device_data),
        _encode_slot(VERIFIER_SECP256K1, cloud_data),
    ]


def build_init_data(slots: list[tuple[int, bytes]], proofs: list[bytes]) -> bytes:
    """ABI-encode the three factor slots and their possession proofs as `initData`.

    Matches `abi.decode(initData, (FactorSlot[3], bytes[3]))` in
    `GlauxAccount.initializeAccount`. Each proof is a signature by the slot's own
    key over the registration digest (see `registration_digest`); the contract
    refuses to install a key that has not signed one, because shape validation
    alone cannot tell a held key from an address derived from a chosen signature.
    """
    return encode(["(uint8,bytes)[3]", "bytes[3]"], [slots, proofs])


def registration_digest(index: int, verifier_type: int, key_data: bytes) -> bytes:
    """The digest a candidate key must sign to prove it exists.

    `keccak256(abi.encode(REG_DOMAIN, index, verifierType, keccak256(keyData)))`.
    It commits to the key material itself, which is what stops an attacker choosing
    a signature and deriving the address it is valid under. It binds neither chain
    nor account, so a factor can produce its proof offline before the account
    exists — the paper factor never comes back online — and the proof travels with
    the blob to every chain. A proof authorizes nothing, so its portability is
    harmless.
    """
    return keccak(
        encode(
            ["bytes32", "uint8", "uint8", "bytes32"],
            [REG_DOMAIN, index, verifier_type, keccak(key_data)],
        )
    )


def eip191_v0(validator: str, struct_hash: bytes) -> bytes:
    """Wrap a structured hash as EIP-191 version 0x00 signed data.

    `0x19 || 0x00 || validator || structHash`. Version 0x00 carries no chain id,
    so Glaux blobs keep replaying on every chain, while the prefix keeps a Glaux
    digest out of reach of raw-hash signing APIs.
    """
    return keccak(b"\x19\x00" + to_bytes(hexstr=to_checksum_address(validator)) + struct_hash)


def build_init_digest(
    router: str,
    implementation: str,
    expected_code_hash: bytes,
    init_data: bytes,
) -> bytes:
    """Compute the chain-agnostic init digest the authorization is crafted against.

    EIP-191 version 0x00 with the ROUTER as validator, over
    `keccak256(abi.encode(INIT_DOMAIN, implementation, expectedCodeHash,
    keccak256(initData)))`. The router has the same address on every chain, so
    binding it costs nothing in replayability.
    """
    struct_hash = keccak(
        encode(
            ["bytes32", "address", "bytes32", "bytes32"],
            [
                INIT_DOMAIN,
                to_checksum_address(implementation),
                expected_code_hash,
                keccak(init_data),
            ],
        )
    )
    return eip191_v0(router, struct_hash)


#: Tag every rootless `s` carries, mirroring `GlauxDelegate.ROOTLESS_S_PREFIX`.
ROOTLESS_S_PREFIX = 0x476C6175785F524F4F544C4553
#: Attempts before giving up. Each succeeds with probability about one half.
MAX_CRAFT_ATTEMPTS = 256


@dataclass(frozen=True, slots=True)
class RootlessProof:
    """The crafted EIP-7702 authorization of an account with no private key."""

    account: str
    salt: bytes
    r: bytes
    s: int
    y_parity: int


def authorization_message_hash(router: str) -> bytes:
    """`keccak256(0x05 || rlp([chainId 0, router, nonce 0]))`.

    The RLP of that tuple is `0xd7 0x80 0x94 || address || 0x80`: a list header
    for 23 bytes, the zero chain id, the 20-byte address, and the zero nonce.
    """
    return keccak(bytes.fromhex("05d78094") + to_bytes(hexstr=to_checksum_address(router)) + b"\x80")


def craft_rootless_authorization(digest: bytes, router: str) -> RootlessProof:
    """Build the authorization of an account whose private key never existed.

    Mirrors `GlauxDelegate.initialize` and the TypeScript SDK: `r` is fixed to
    a hash committing to this birth configuration, `s` carries the router's
    constant tag, and `ecrecover` then reveals which address that pair is valid
    for. That address becomes the account, and nobody holds its key — deriving
    one would mean solving for a nonce `k` with `x(kG) = r` for a chosen `r`.

    `y_parity` is always 0: where `r` is a valid curve x-coordinate, recovery
    id 27 succeeds, and where it is not, neither id does and the salt advances.
    """
    message_hash = authorization_message_hash(router)
    for attempt in range(MAX_CRAFT_ATTEMPTS):
        salt = keccak(encode(["bytes32", "uint256"], [digest, attempt]))
        r = keccak(encode(["bytes32", "bytes32"], [digest, salt]))
        tail = (
            int.from_bytes(
                keccak(encode(["bytes32", "bytes32", "uint8"], [digest, salt, 1])),
                "big",
            )
            >> 104
        )
        s = (ROOTLESS_S_PREFIX << 152) | tail
        account = _recover_address(r, s, message_hash)
        if account is not None:
            return RootlessProof(account=account, salt=salt, r=r, s=s, y_parity=0)
    raise ValueError(
        f"no rootless authorization found in {MAX_CRAFT_ATTEMPTS} attempts; "
        "this is unreachable unless keccak256 stopped behaving like a hash"
    )


def _recover_address(r: bytes, s: int, message_hash: bytes) -> str | None:
    """The address `(r, s)` recovers to, or `None` when `r` is off-curve.

    An off-curve `r` is not an error: it simply costs one more salt.
    """
    try:
        signature = Signature(vrs=(0, int.from_bytes(r, "big"), s))
        public_key = signature.recover_public_key_from_msg_hash(message_hash)
    except (BadSignature, ValidationError):
        # `BadSignature` is what an off-curve `r` produces; `ValidationError`
        # covers a component out of range. Deliberately narrow: any other
        # failure here means something unexpected about the curve library, and
        # swallowing it would turn a real problem into one more salt attempt.
        return None
    return to_checksum_address(public_key.to_address())


def recovers_to(digest: bytes, salt: bytes, s: int, expected: str, router: str) -> bool:
    """Re-run the router's whole authentication locally.

    Lets a client refuse a blob before a relayer spends gas on a birth the
    chain would reject, and — for a blob that arrived from elsewhere — before
    trusting that its `account` field means anything.
    """
    if (s >> 152) != ROOTLESS_S_PREFIX:
        return False
    r = keccak(encode(["bytes32", "bytes32"], [digest, salt]))
    recovered = _recover_address(r, s, authorization_message_hash(router))
    return recovered is not None and recovered == to_checksum_address(expected)


def build_birth_blob(
    router: str,
    implementation: str,
    expected_code_hash_hex: str,
    paper_address: str,
    device_qx: int,
    device_qy: int,
    cloud_address: str,
    proofs: list[bytes],
) -> dict[str, Any]:
    """Build the full chain-agnostic birth blob for a rootless account.

    No key is generated here and none is destroyed afterwards, because none
    ever exists: the account address falls out of the factor configuration.
    """
    expected_code_hash = to_bytes(hexstr=expected_code_hash_hex)
    if len(expected_code_hash) != 32:
        raise ValueError("--expected-code-hash must be a 32-byte hex value")

    slots = build_slots(paper_address, device_qx, device_qy, cloud_address)
    init_data = build_init_data(slots, proofs)
    digest = build_init_digest(router, implementation, expected_code_hash, init_data)
    proof = craft_rootless_authorization(digest, router)

    # Self-check over the blob's own fields: a blob whose parts disagree is
    # never handed to a caller.
    if not recovers_to(digest, proof.salt, proof.s, proof.account, router):
        raise ValueError("crafted authorization does not recover to its own account")

    return {
        "account": proof.account,
        "router": to_checksum_address(router),
        "implementation": to_checksum_address(implementation),
        "expectedCodeHash": "0x" + expected_code_hash.hex(),
        "authorization": {
            "chainId": 0,
            "address": to_checksum_address(router),
            "nonce": 0,
            "yParity": proof.y_parity,
            "r": hex(int.from_bytes(proof.r, "big")),
            "s": hex(proof.s),
        },
        "initData": "0x" + init_data.hex(),
        "salt": "0x" + proof.salt.hex(),
    }


def main() -> None:
    """Parse CLI args, build the birth blob, and print it as JSON on stdout."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--router", required=True, help="deployed GlauxDelegate address")
    parser.add_argument("--impl", required=True, help="deployed GlauxAccount implementation address")
    parser.add_argument(
        "--expected-code-hash",
        required=True,
        help="32-byte runtime code hash of --impl (printed by script/Deploy.s.sol)",
    )
    parser.add_argument("--paper", required=True, help="paper factor: secp256k1 address (slot 0)")
    parser.add_argument(
        "--device-qx",
        required=True,
        type=_hex_to_int,
        help="device factor: P-256 qx (slot 1)",
    )
    parser.add_argument(
        "--device-qy",
        required=True,
        type=_hex_to_int,
        help="device factor: P-256 qy (slot 1)",
    )
    parser.add_argument("--cloud", required=True, help="cloud factor: secp256k1 address (slot 2)")
    for flag, who, slot in (
        ("--paper-proof", "paper", 0),
        ("--device-proof", "device", 1),
        ("--cloud-proof", "cloud", 2),
    ):
        parser.add_argument(
            flag,
            required=True,
            help=(
                f"hex possession proof for the {who} factor (slot {slot}), produced "
                "by its holder with scripts/prove_possession.py"
            ),
        )
    args = parser.parse_args()

    blob = build_birth_blob(
        router=args.router,
        implementation=args.impl,
        expected_code_hash_hex=args.expected_code_hash,
        paper_address=args.paper,
        device_qx=args.device_qx,
        device_qy=args.device_qy,
        cloud_address=args.cloud,
        proofs=[
            to_bytes(hexstr=args.paper_proof),
            to_bytes(hexstr=args.device_proof),
            to_bytes(hexstr=args.cloud_proof),
        ],
    )
    print(json.dumps(blob, indent=2))


if __name__ == "__main__":
    main()
