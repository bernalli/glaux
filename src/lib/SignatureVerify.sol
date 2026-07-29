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

    /// @dev Known-answer test vector for `p256VerifierAvailable`: a valid signature
    ///      `(PROBE_R, PROBE_S)` over `PROBE_DIGEST = keccak256("GLAUX_P256_PROBE_V1")`
    ///      by the public key `(PROBE_QX, PROBE_QY)`, whose private key is
    ///      `keccak256("glaux.p256.probe.v1")`. That key is PUBLIC and meant to be:
    ///      a known-answer test proves the code at the verifier address computes
    ///      P-256, which requires the answer to be known. `s` is below `n/2`, so
    ///      implementations that reject malleable signatures accept it too.
    ///      `test/P256Probe.t.sol` re-derives the whole vector from those two seed
    ///      strings and checks it against the vendored daimo verifier, so a typo here
    ///      cannot pass unnoticed.
    /// @dev Because that private key is public, this public key must never be
    ///      installed as a factor: `GlauxAccount._validateSlot` refuses it.
    uint256 internal constant PROBE_QX =
        0x6e116efa770f5c5455124d86df9b00525dab28db280c3c8f33bb64c0ef313489;
    uint256 internal constant PROBE_QY =
        0x8961e3da77e0f8d247f099835070289b64906c509ec256eec976858516ae8d81;
    bytes32 internal constant PROBE_DIGEST =
        0x867725ff3c347f7537e90a9166778796299dcc35b965e51a431e53a9d4b2b5a4;
    uint256 internal constant PROBE_R =
        0x980d841a72d73ef73cfd9baadc862485aecac52b199bbd3df24e834f737ed46c;
    uint256 internal constant PROBE_S =
        0x4ac2a1c22aa9ff18958b5d11775f7dced116f8f5a6c95f2d859bf6f0035df385;

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

    /// @notice True when this chain actually verifies P-256 at `P256_VERIFIER`.
    /// @dev A P-256 slot is inert wherever the verifier is absent: nothing it signs
    ///      can be checked, so an account holding two of them can never reach its own
    ///      2-of-3 threshold and is born dead, with no factor left to rescue it.
    ///      Callers must ask this BEFORE installing such a slot.
    /// @dev Both arms are needed. The positive one rejects the plain case — no
    ///      precompile, so the call returns empty — but on its own it would accept any
    ///      code that answers `1`, and a verifier that never says no accepts every
    ///      signature ever presented to that slot, which is worse than no slot at all.
    ///      The negative arm asks the same key and signature about a different
    ///      message: a real implementation must reject it. Together they establish
    ///      that the address discriminates, not merely that it answers.
    function p256VerifierAvailable() internal view returns (bool) {
        if (!_p256Verify(PROBE_DIGEST, PROBE_R, PROBE_S, PROBE_QX, PROBE_QY)) return false;
        return
            !_p256Verify(PROBE_DIGEST ^ bytes32(uint256(1)), PROBE_R, PROBE_S, PROBE_QX, PROBE_QY);
    }

    /// @notice True when `data` encodes the probe vector's public key.
    /// @dev Its private key is published with the vector, so this key belongs to
    ///      everyone. Refusing it as slot material costs one comparison and removes a
    ///      whole class of client mistake — lifting the constants out of this library
    ///      to seed a slot.
    function isProbeKey(bytes memory data) internal pure returns (bool) {
        if (data.length != 64) return false;
        (uint256 qx, uint256 qy) = abi.decode(data, (uint256, uint256));
        return qx == PROBE_QX && qy == PROBE_QY;
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
        return _p256Verify(digest, r, s, qx, qy);
    }

    function _p256Verify(bytes32 digest, uint256 r, uint256 s, uint256 qx, uint256 qy)
        private
        view
        returns (bool)
    {
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
