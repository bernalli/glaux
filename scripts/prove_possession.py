"""Produce a Glaux possession proof for one factor key.

A Glaux account will not install a key into a factor slot unless that key has
signed a registration challenge. This is not a formality: ECDSA verifies by
recovery, so without it an adversary can choose a signature first and derive the
address it is valid under, producing a perfectly well-formed slot whose private
key never existed — and two such slots meet the 2-of-3 threshold with no keys at
all. The challenge commits to the key material itself, which is what makes that
impossible.

Run this in the environment that holds the factor key, and only there. The
factor private key is read from the `GLAUX_FACTOR_KEY` environment variable and
is never accepted as a CLI flag or printed: a flag would put the key in the
process table, where every other user of the machine can read it, and in the
invoking shell's history file. Only the proof, which is public data, is
printed. The challenge binds neither a chain nor an account, so a proof can be
produced before the account exists — which is what lets an air-gapped paper
factor sign once and never come back online — and the same proof is valid on
every chain.

Put the key in the variable without typing it on a command line: an inline
`GLAUX_FACTOR_KEY=0x... python3 ...` assignment is written to the history file
by every interactive shell, which is the exposure a flag would have caused.

Usage (secp256k1 factor, e.g. the paper or cloud key):
  read -rs GLAUX_FACTOR_KEY && export GLAUX_FACTOR_KEY   # key never echoed
  python3 scripts/prove_possession.py --slot 0 --type 1
  unset GLAUX_FACTOR_KEY

Usage (P-256 factor, e.g. a device key, when the key is exportable):
  read -rs GLAUX_FACTOR_KEY && export GLAUX_FACTOR_KEY
  python3 scripts/prove_possession.py \\
      --slot 1 --type 2 --qx 0x<qx> --qy 0x<qy>
  unset GLAUX_FACTOR_KEY

For a hardware-backed P-256 factor the private key is not exportable by design.
Print the challenge instead, have the platform's signing API sign that 32-byte
value, then encode the resulting (r, s) as two padded uint256s:

  python3 scripts/prove_possession.py \\
      --slot 1 --type 2 --qx 0x<qx> --qy 0x<qy> --digest-only

Requires: see scripts/requirements.txt
"""

from __future__ import annotations

import argparse
import contextlib
import os
import sys
from collections.abc import Generator

from eth_abi import encode
from eth_account import Account
from eth_utils import keccak, to_bytes, to_checksum_address

FACTOR_KEY_ENV = "GLAUX_FACTOR_KEY"
REG_DOMAIN = keccak(text="GLAUX_REG_V1")
VERIFIER_SECP256K1 = 1
VERIFIER_P256 = 2
SECP256K1_N_DIV_2 = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
CURVE_ORDER = {VERIFIER_SECP256K1: SECP256K1_N, VERIFIER_P256: P256_N}


def parse_factor_key(raw: str, verifier_type: int) -> int:
    """Parse the factor key, refusing anything that is not exactly one scalar.

    Both curves take a 32-byte scalar in `[1, n-1]`, but the libraries below do
    not all enforce that: `int(key, 16)` happily reads a truncated hex string as
    a small integer, and P-256 key derivation accepts it — so a key mangled in
    transit (a partial copy-paste, a stripped leading zero) would silently
    produce a valid-looking proof for a DIFFERENT, low-entropy key, which is
    then what gets installed into the factor slot. Refuse instead of signing:
    a proof is only meaningful if it proves possession of the intended key.
    """
    text = raw.strip()
    body = text[2:] if text.lower().startswith("0x") else text
    if len(body) != 64 or any(c not in "0123456789abcdefABCDEF" for c in body):
        raise SystemExit(
            f"{FACTOR_KEY_ENV} must be exactly 32 bytes of hex (64 hex digits, "
            "with or without a 0x prefix)"
        )
    scalar = int(body, 16)
    if not 1 <= scalar < CURVE_ORDER[verifier_type]:
        raise SystemExit(
            f"{FACTOR_KEY_ENV} is not a valid private key for this factor type: "
            "the scalar is outside the curve order"
        )
    return scalar


@contextlib.contextmanager
def sanitized_key_errors() -> Generator[None, None, None]:
    """Keep key material out of tracebacks.

    Every library that parses a private key puts the offending value straight
    into its exception message, so a malformed `GLAUX_FACTOR_KEY` would be
    printed in full by the default excepthook — and collected by whatever
    gathers that output. That is the same exposure moving the key out of argv
    was meant to prevent, so the original exception is dropped, not chained.
    """
    try:
        yield
    except SystemExit:
        raise
    # Deliberately blind: the point is that NO library exception may reach the
    # default excepthook with the key in its message, so narrowing this to the
    # exception types today's libraries happen to raise would defeat it.
    except Exception:  # noqa: BLE001
        raise SystemExit(
            f"{FACTOR_KEY_ENV} is not a valid private key for this factor type"
        ) from None


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


def sign_p256(scalar: int, digest: bytes) -> bytes:
    """Sign the challenge with a P-256 key, encoded as two padded uint256s.

    The contract passes `(r, s)` straight to the P256VERIFY precompile, so the
    signature must be exactly 64 bytes — not DER, which is what most crypto
    libraries return by default.
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils

    key = ec.derive_private_key(scalar, ec.SECP256R1())
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
    parser.add_argument("--qx", help="P-256 public key x coordinate (hex)")
    parser.add_argument("--qy", help="P-256 public key y coordinate (hex)")
    parser.add_argument(
        "--digest-only",
        action="store_true",
        help="print only the challenge, for signing by an external device",
    )
    # Not `parse_args`: its "unrecognized arguments: --key 0x..." message prints
    # the VALUE to stderr, and the value most likely to turn up here is a private
    # key typed against the removed `--key` / `--p256-key` flags. Report the flag
    # names only, so a mistake does not persist the key in a terminal or a log.
    args, unknown = parser.parse_known_args()
    if unknown:
        flags = sorted(
            {token.split("=", 1)[0] for token in unknown if token.startswith("-")}
        )
        named = " ".join(flags) if flags else "(positional arguments)"
        sys.exit(
            f"unrecognized argument(s): {named} — the factor key is read from "
            f"{FACTOR_KEY_ENV} and is never accepted on the command line"
        )

    # Read once, demanded only where it is actually needed: a P-256 factor's
    # challenge is derived from its PUBLIC coordinates, so --digest-only asks
    # for no key at all — which is the whole point on a device whose key
    # cannot be exported.
    factor_key = os.environ.get(FACTOR_KEY_ENV)

    if args.verifier_type == VERIFIER_SECP256K1:
        if not factor_key:
            sys.exit(f"{FACTOR_KEY_ENV} environment variable is not set")
        parse_factor_key(factor_key, VERIFIER_SECP256K1)
        with sanitized_key_errors():
            key_data = secp256k1_key_data(factor_key)
    else:
        if not (args.qx and args.qy):
            parser.error("--qx and --qy are required for a P-256 factor")
        key_data = encode(["uint256", "uint256"], [int(args.qx, 16), int(args.qy, 16)])

    digest = registration_digest(args.slot, args.verifier_type, key_data)
    if args.digest_only:
        print("0x" + digest.hex())
        return

    if args.verifier_type == VERIFIER_SECP256K1:
        assert factor_key is not None  # refused above when unset
        with sanitized_key_errors():
            signature = sign_secp256k1(factor_key, digest)
        print("0x" + signature.hex())
        return

    if not factor_key:
        sys.exit(
            f"{FACTOR_KEY_ENV} environment variable is not set; set it to the "
            "exportable P-256 private key, or use --digest-only and have the "
            "device's own API sign the printed challenge"
        )
    scalar = parse_factor_key(factor_key, VERIFIER_P256)
    with sanitized_key_errors():
        signature = sign_p256(scalar, digest)
    print("0x" + signature.hex())


if __name__ == "__main__":
    main()
