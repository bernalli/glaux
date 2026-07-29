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
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
            v := byte(0, mload(add(signature, 0x60)))
        }
        if (uint256(s) > SECP256K1_N_DIV_2) return false;
        if (v != 27 && v != 28) return false;
        address recovered = ecrecover(digest, v, r, s);
        return recovered != address(0) && recovered == abi.decode(data, (address));
    }

    function _verifyP256(bytes memory data, bytes32 digest, bytes memory signature)
        private
        view
        returns (bool)
    {
        // implemented in Task 4
        data;
        digest;
        signature;
        return false;
    }
}
