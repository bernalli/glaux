// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {GlauxStorage} from "../GlauxStorage.sol";

library SignatureVerify {
    address internal constant P256_VERIFIER = address(0x100); // RIP-7212 / EIP-7951
    uint256 internal constant SECP256K1_N_DIV_2 =
        0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;
    uint256 internal constant P256_P =
        0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF;
    uint256 internal constant P256_A = P256_P - 3;
    uint256 internal constant P256_B =
        0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B;

    function isValidKey(uint8 verifierType, bytes memory data) internal pure returns (bool) {
        if (verifierType == GlauxStorage.VERIFIER_SECP256K1) {
            return _isValidSecp256k1Key(data);
        }
        if (verifierType == GlauxStorage.VERIFIER_P256) {
            return _isValidP256Key(data);
        }
        return false;
    }

    function verify(uint8 verifierType, bytes memory data, bytes32 digest, bytes memory signature)
        internal
        view
        returns (bool)
    {
        if (verifierType == GlauxStorage.VERIFIER_SECP256K1) {
            return _verifySecp256k1(data, digest, signature);
        }
        if (verifierType == GlauxStorage.VERIFIER_P256) {
            return _verifyP256(data, digest, signature);
        }
        return false;
    }

    function _verifySecp256k1(bytes memory data, bytes32 digest, bytes memory signature)
        private
        pure
        returns (bool)
    {
        if (signature.length != 65) return false;
        if (data.length != 32) return false;
        bytes32 r;
        bytes32 s;
        uint8 v;
        uint256 signerWord;
        assembly {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
            v := byte(0, mload(add(signature, 0x60)))
            signerWord := mload(add(data, 0x20))
        }
        if (signerWord > type(uint160).max) return false;
        if (uint256(s) > SECP256K1_N_DIV_2) return false;
        if (v != 27 && v != 28) return false;
        address recovered = ecrecover(digest, v, r, s);
        // forge-lint: disable-next-line(unsafe-typecast) -- signerWord is range-checked above.
        return recovered != address(0) && recovered == address(uint160(signerWord));
    }

    function _isValidSecp256k1Key(bytes memory data) private pure returns (bool) {
        if (data.length != 32) return false;
        uint256 signerWord;
        assembly {
            signerWord := mload(add(data, 0x20))
        }
        return signerWord <= type(uint160).max && signerWord != 0;
    }

    function _isValidP256Key(bytes memory data) private pure returns (bool) {
        if (data.length != 64) return false;
        uint256 qx;
        uint256 qy;
        assembly {
            qx := mload(add(data, 0x20))
            qy := mload(add(data, 0x40))
        }
        if (qx >= P256_P || qy >= P256_P || (qx == 0 && qy == 0)) return false;

        uint256 lhs = mulmod(qy, qy, P256_P);
        uint256 xSquared = mulmod(qx, qx, P256_P);
        uint256 rhs = addmod(
            addmod(mulmod(xSquared, qx, P256_P), mulmod(P256_A, qx, P256_P), P256_P), P256_B, P256_P
        );
        return lhs == rhs;
    }

    function _verifyP256(bytes memory data, bytes32 digest, bytes memory signature)
        private
        view
        returns (bool)
    {
        if (signature.length != 64) return false;
        if (data.length != 64) return false;
        (uint256 r, uint256 s) = abi.decode(signature, (uint256, uint256));
        (uint256 qx, uint256 qy) = abi.decode(data, (uint256, uint256));
        (bool ok, bytes memory out) =
            P256_VERIFIER.staticcall(abi.encodePacked(digest, r, s, qx, qy));
        if (!ok || out.length != 32) return false;
        bytes32 result;
        assembly {
            result := mload(add(out, 0x20))
        }
        return result == bytes32(uint256(1));
    }
}
