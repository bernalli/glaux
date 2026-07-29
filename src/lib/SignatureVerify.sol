// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {GlauxStorage} from "../GlauxStorage.sol";

library SignatureVerify {
    address internal constant P256_VERIFIER = address(0x100); // RIP-7212 / EIP-7951
    uint256 internal constant SECP256K1_N_DIV_2 =
        0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

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
