"""Generate a Glaux account-birth blob.

Creates an ephemeral EOA (the "birth key"), signs the EIP-7702 authorization
tuple (``chainId=0``, ``nonce=0``, ``address=<router>``) that delegates the
EOA's code to the ``GlauxDelegate`` router, and signs the chain-agnostic init
digest that binds the three initial factor slots (paper/device/cloud) to the
account. The birth key exists only in process memory: it is generated,
used to sign, and discarded when the process exits. It is never written to
disk, logged, or printed.

The resulting JSON blob (authorization tuple + init data + birth signature)
is chain-agnostic by construction: it can be submitted, unmodified, to any
chain where the same ``GlauxDelegate``/``GlauxAccount`` bytecode was deployed
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
from typing import Any

from eth_abi import encode
from eth_account import Account
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
    return keccak(
        b"\x19\x00" + to_bytes(hexstr=to_checksum_address(validator)) + struct_hash
    )


def build_init_digest(
    router: str,
    implementation: str,
    expected_code_hash: bytes,
    init_data: bytes,
) -> bytes:
    """Compute the chain-agnostic init digest bound by the birth signature.

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


def sign_birth_digest(private_key: bytes, digest: bytes) -> bytes:
    """Sign `digest` with a raw (non-EIP-191) secp256k1 signature.

    Returns the 65-byte `r||s||v` signature the contract recovers with
    `ecrecover(digest, v, r, s)` directly against the signer's own address.
    `eth_account`/`eth_keys` always produce canonical low-s signatures, which
    is asserted here defensively since the contract rejects high-s values.
    """
    signed = Account.unsafe_sign_hash(digest, private_key)
    assert signed.v in (27, 28), f"unexpected v: {signed.v}"
    assert signed.s <= SECP256K1_N_DIV_2, (
        "signature s is not canonical (lower half of curve order)"
    )
    return to_bytes(hexstr=signed.signature.to_0x_hex())


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
    """Generate an ephemeral birth key and the full chain-agnostic birth blob.

    Returns a JSON-serializable dict with the EIP-7702 authorization tuple,
    the born account's address, the init data, and the raw birth signature.
    The birth private key is discarded as soon as this function returns.
    """
    birth_account = Account.create()
    expected_code_hash = to_bytes(hexstr=expected_code_hash_hex)
    if len(expected_code_hash) != 32:
        raise ValueError("--expected-code-hash must be a 32-byte hex value")

    signed_authorization = birth_account.sign_authorization(
        {"chainId": 0, "address": to_checksum_address(router), "nonce": 0}
    )

    slots = build_slots(paper_address, device_qx, device_qy, cloud_address)
    init_data = build_init_data(slots, proofs)
    digest = build_init_digest(router, implementation, expected_code_hash, init_data)
    birth_signature = sign_birth_digest(birth_account.key, digest)

    return {
        "account": birth_account.address,
        "router": to_checksum_address(router),
        "implementation": to_checksum_address(implementation),
        "expectedCodeHash": "0x" + expected_code_hash.hex(),
        "authorization": {
            "chainId": signed_authorization.chain_id,
            "address": to_checksum_address(router),
            "nonce": signed_authorization.nonce,
            "yParity": signed_authorization.y_parity,
            "r": hex(signed_authorization.r),
            "s": hex(signed_authorization.s),
        },
        "initData": "0x" + init_data.hex(),
        "birthSig": "0x" + birth_signature.hex(),
    }


def main() -> None:
    """Parse CLI args, build the birth blob, and print it as JSON on stdout."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--router", required=True, help="deployed GlauxDelegate address"
    )
    parser.add_argument(
        "--impl", required=True, help="deployed GlauxAccount implementation address"
    )
    parser.add_argument(
        "--expected-code-hash",
        required=True,
        help="32-byte runtime code hash of --impl (printed by script/Deploy.s.sol)",
    )
    parser.add_argument(
        "--paper", required=True, help="paper factor: secp256k1 address (slot 0)"
    )
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
    parser.add_argument(
        "--cloud", required=True, help="cloud factor: secp256k1 address (slot 2)"
    )
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
