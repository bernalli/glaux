// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import "forge-std/Test.sol";
import {SignatureVerify} from "../src/lib/SignatureVerify.sol";

contract SigVerifyHarness {
    function verify(uint8 t, bytes calldata d, bytes32 h, bytes calldata sig)
        external
        view
        returns (bool)
    {
        return SignatureVerify.verify(t, d, h, sig);
    }
}

contract SignatureVerifyTest is Test {
    SigVerifyHarness h;
    uint256 pk = 0xA11CE;
    address signer;

    function setUp() public {
        h = new SigVerifyHarness();
        signer = vm.addr(pk);
    }

    function _sig(uint256 key, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        return abi.encodePacked(r, s, v);
    }

    function test_secp256k1_ok() public view {
        bytes32 digest = keccak256("glaux");
        assertTrue(h.verify(1, abi.encode(signer), digest, _sig(pk, digest)));
    }

    function test_secp256k1_wrongSigner() public view {
        bytes32 digest = keccak256("glaux");
        assertFalse(h.verify(1, abi.encode(address(0xDEAD)), digest, _sig(pk, digest)));
    }

    function test_secp256k1_rejectsHighS() public view {
        bytes32 digest = keccak256("glaux");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        // flip to the malleable twin: s' = n - s, v' = v ^ 1
        uint256 N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
        bytes memory mall =
            abi.encodePacked(r, bytes32(N - uint256(s)), v == 27 ? uint8(28) : uint8(27));
        assertFalse(h.verify(1, abi.encode(signer), digest, mall));
    }

    function test_secp256k1_badLength() public view {
        assertFalse(h.verify(1, abi.encode(signer), keccak256("x"), hex"deadbeef"));
    }

    function test_unknownType_false() public view {
        assertFalse(h.verify(0, "", keccak256("x"), ""));
        assertFalse(h.verify(9, "", keccak256("x"), ""));
    }
}
