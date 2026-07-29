"""Produce a Glaux possession proof for one factor key.

A Glaux account will not install a key into a factor slot unless that key has
signed a registration challenge. This is not a formality: ECDSA verifies by
recovery, so without it an adversary can choose a signature first and derive the
address it is valid under, producing a perfectly well-formed slot whose private
key never existed — and two such slots meet the 2-of-3 threshold with no keys at
all. The challenge commits to the key material itself, which is what makes that
impossible.

Run this in the environment that holds the factor key, and only there. The
private key never leaves this process, and the printed proof is public data.
The challenge binds neither a chain nor an account, so a proof can be produced
before the account exists — which is what lets an air-gapped paper factor sign
once and never come back online — and the same proof is valid on every chain.

Usage (secp256k1 factor, e.g. the paper or cloud key):
  python3 scripts/prove_possession.py --slot 0 --type 1 --key 0x<privkey>

Usage (P-256 factor, e.g. a device key, when the key is exportable):
  python3 scripts/prove_possession.py --slot 1 --type 2 --p256-key 0x<privkey>

For a hardware-backed P-256 factor the private key is not exportable by design.
Compute the digest with --digest-only and have the platform's signing API sign
that 32-byte value, then encode the resulting (r, s) as two padded uint256s.

Requires: see scripts/requirements.txt
"""

from __future__ import annotations

import argparse

from eth_abi import encode
from eth_account import Account
from eth_utils import keccak, to_bytes, to_checksum_address

REG_DOMAIN = keccak(text="GLAUX_REG_V1")
VERIFIER_SECP256K1 = 1
VERIFIER_P256 = 2
SECP256K1_N_DIV_2 = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0


def registration_digest(index: int, verifier_type: int, key_data: bytes) -> bytes:
    """The 32-byte challenge a key must sign to prove it exists.

    `keccak256(abi.encode(REG_DOMAIN, index, verifierType, keccak256(keyData)))`,
    matching `GlauxAccount._requirePossession`.
    """
    return keccak(
        encode(
            ["bytes32", "uint8", "uint8", "bytes32"],
            [REG_DOMAIN, index, verifier_type, keccak(key_data)],
        )
    )


def secp256k1_key_data(private_key: str) -> bytes:
    """The slot data for a secp256k1 factor: its address, ABI-encoded."""
    account = Account.from_key(private_key)
    return encode(["address"], [to_checksum_address(account.address)])


def sign_secp256k1(private_key: str, digest: bytes) -> bytes:
    """Sign the challenge as a raw 65-byte `r||s||v` secp256k1 signature."""
    signed = Account.unsafe_sign_hash(digest, to_bytes(hexstr=private_key))
    assert signed.v in (27, 28), f"unexpected v: {signed.v}"
    assert signed.s <= SECP256K1_N_DIV_2, "signature s is not canonical"
    return to_bytes(hexstr=signed.signature.to_0x_hex())


def sign_p256(private_key: str, digest: bytes) -> bytes:
    """Sign the challenge with a P-256 key, encoded as two padded uint256s.

    The contract passes `(r, s)` straight to the P256VERIFY precompile, so the
    signature must be exactly 64 bytes — not DER, which is what most crypto
    libraries return by default.
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils

    key = ec.derive_private_key(int(private_key, 16), ec.SECP256R1())
    der = key.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    r, s = utils.decode_dss_signature(der)
    return encode(["uint256", "uint256"], [r, s])


def main() -> None:
    """Parse CLI args and print the possession proof, or just the challenge."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--slot", required=True, type=int, choices=(0, 1, 2), help="slot index"
    )
    parser.add_argument(
        "--type",
        required=True,
        type=int,
        choices=(VERIFIER_SECP256K1, VERIFIER_P256),
        dest="verifier_type",
        help="1 = secp256k1, 2 = P-256",
    )
    parser.add_argument("--key", help="secp256k1 private key (hex)")
    parser.add_argument("--p256-key", help="P-256 private key (hex), when exportable")
    parser.add_argument("--qx", help="P-256 public key x coordinate (hex)")
    parser.add_argument("--qy", help="P-256 public key y coordinate (hex)")
    parser.add_argument(
        "--digest-only",
        action="store_true",
        help="print only the challenge, for signing by an external device",
    )
    args = parser.parse_args()

    if args.verifier_type == VERIFIER_SECP256K1:
        if not args.key:
            parser.error("--key is required for a secp256k1 factor")
        key_data = secp256k1_key_data(args.key)
    else:
        if not (args.qx and args.qy):
            parser.error("--qx and --qy are required for a P-256 factor")
        key_data = encode(["uint256", "uint256"], [int(args.qx, 16), int(args.qy, 16)])

    digest = registration_digest(args.slot, args.verifier_type, key_data)
    if args.digest_only:
        print("0x" + digest.hex())
        return

    if args.verifier_type == VERIFIER_SECP256K1:
        print("0x" + sign_secp256k1(args.key, digest).hex())
        return

    if not args.p256_key:
        parser.error(
            "--p256-key is required to sign, or use --digest-only and have the "
            "device's own API sign the printed challenge"
        )
    print("0x" + sign_p256(args.p256_key, digest).hex())


if __name__ == "__main__":
    main()
