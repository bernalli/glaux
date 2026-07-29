"""Print and verify the anchored P-256 test vector used by P256Fixture.sol.

Run this script once to print the fixed private key, derived public key, digest, and
committed signature constants. ECDSA signing nonces make r and s non-reproducible by
construction, so --verify re-checks the committed signature instead of re-signing it.

Usage:
    python3 scripts/gen_p256_vector.py
    python3 scripts/gen_p256_vector.py --verify [--r 0x... --s 0x...]

Requires: pip install cryptography
"""

import argparse
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

# These fixed values anchor test/P256Fixture.sol and are not regenerated.
P256_PRIVATE_KEY = 0x7459E13AFD9158A379EE75CA9E80A328916DBA1473C863F800F51EE5F46EB3AB
P256_DIGEST = bytes.fromhex("547c05d9093cf1004d4426a5d03202cf500c22777a87f05c18ac247e38fc572e")
P256_R = 0x56464D0BB7014173461871178E264ACD5E981572BC495D8978BB5B16CA4895BB
P256_S = 0x1018FA59CE5F3BDD39E7DF090DD93309BE390B068A7CD3123A492CCCD3524E5D


def _integer(value: str) -> int:
    return int(value, 0)


def main() -> None:
    """Print the anchored fixture constants or verify its supplied ECDSA signature once."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify", action="store_true", help="verify r and s against the fixture")
    parser.add_argument("--r", type=_integer, default=P256_R, help="signature r (default: fixture r)")
    parser.add_argument("--s", type=_integer, default=P256_S, help="signature s (default: fixture s)")
    args = parser.parse_args()

    private_key = ec.derive_private_key(P256_PRIVATE_KEY, ec.SECP256R1())
    public_numbers = private_key.public_key().public_numbers()

    if args.verify:
        try:
            private_key.public_key().verify(
                utils.encode_dss_signature(args.r, args.s),
                P256_DIGEST,
                ec.ECDSA(utils.Prehashed(hashes.SHA256())),
            )
        except (InvalidSignature, ValueError) as error:
            sys.exit(f"P-256 fixture signature does not verify: {error}")
        print("P-256 fixture signature verifies.")
        return

    print(f"uint256 constant P256_PK   = {hex(P256_PRIVATE_KEY)};")
    print(f"uint256 constant P256_QX   = {hex(public_numbers.x)};")
    print(f"uint256 constant P256_QY   = {hex(public_numbers.y)};")
    print(f"bytes32 constant P256_DIG  = 0x{P256_DIGEST.hex()};")
    print(f"uint256 constant P256_R    = {hex(P256_R)};")
    print(f"uint256 constant P256_S    = {hex(P256_S)};")


if __name__ == "__main__":
    main()
