// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import "forge-std/Test.sol";
import {SignatureVerify} from "../src/lib/SignatureVerify.sol";
import {P256_PK, P256_QX, P256_QY, P256_DIG, P256_R, P256_S} from "./P256Fixture.sol";

contract P256ZeroVerifier {
    fallback() external {
        assembly {
            mstore(0, 0)
            return(0, 32)
        }
    }
}

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
    uint256 internal constant P256_N =
        0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;

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

    function test_secp256k1_rejectsEmptyData() public view {
        bytes32 digest = keccak256("glaux");
        assertFalse(h.verify(1, "", digest, _sig(pk, digest)));
    }

    function test_secp256k1_rejects31ByteData() public view {
        bytes32 digest = keccak256("glaux");
        assertFalse(h.verify(1, new bytes(31), digest, _sig(pk, digest)));
    }

    function test_secp256k1_rejects33ByteData() public view {
        bytes32 digest = keccak256("glaux");
        assertFalse(h.verify(1, new bytes(33), digest, _sig(pk, digest)));
    }

    function test_secp256k1_rejectsDirtyPaddedAddress() public view {
        bytes32 digest = keccak256("glaux");
        bytes memory dirtyPaddedSigner = abi.encodePacked(bytes12(uint96(1)), signer);
        assertFalse(h.verify(1, dirtyPaddedSigner, digest, _sig(pk, digest)));
    }

    function test_secp256k1_rejectsZeroAddressData() public view {
        bytes32 digest = keccak256("glaux");
        assertFalse(h.verify(1, abi.encode(address(0)), digest, _sig(pk, digest)));
    }

    function test_secp256k1_rejects66ByteSignature() public view {
        bytes32 digest = keccak256("glaux");
        bytes memory sigWithTrailingByte = bytes.concat(_sig(pk, digest), hex"00");
        assertFalse(h.verify(1, abi.encode(signer), digest, sigWithTrailingByte));
    }

    function test_secp256k1_rejectsInvalidV() public view {
        bytes32 digest = keccak256("glaux");
        (, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        assertFalse(h.verify(1, abi.encode(signer), digest, abi.encodePacked(r, s, uint8(29))));
        assertFalse(h.verify(1, abi.encode(signer), digest, abi.encodePacked(r, s, uint8(0))));
    }

    function test_secp256k1_rejectsZeroR() public view {
        bytes32 digest = keccak256("glaux");
        (uint8 v,, bytes32 s) = vm.sign(pk, digest);
        assertFalse(h.verify(1, abi.encode(signer), digest, abi.encodePacked(bytes32(0), s, v)));
    }

    function test_secp256k1_rejectsZeroS() public view {
        bytes32 digest = keccak256("glaux");
        (uint8 v, bytes32 r,) = vm.sign(pk, digest);
        assertFalse(h.verify(1, abi.encode(signer), digest, abi.encodePacked(r, bytes32(0), v)));
    }

    function test_secp256k1_rejectsGroupOrderS() public view {
        bytes32 digest = keccak256("glaux");
        (uint8 v, bytes32 r,) = vm.sign(pk, digest);
        uint256 n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
        assertFalse(h.verify(1, abi.encode(signer), digest, abi.encodePacked(r, bytes32(n), v)));
    }

    function test_unknownType_false() public view {
        assertFalse(h.verify(0, "", keccak256("x"), ""));
        assertFalse(h.verify(9, "", keccak256("x"), ""));
    }

    function _etchP256() internal {
        vm.etch(address(0x100), vm.getDeployedCode("P256Verifier.sol:P256Verifier"));
    }

    function test_p256_ok_staticVector() public {
        _etchP256();
        assertTrue(h.verify(2, abi.encode(P256_QX, P256_QY), P256_DIG, abi.encode(P256_R, P256_S)));
    }

    function test_p256_ok_dynamicSign() public {
        _etchP256();
        bytes32 digest = keccak256("glaux-dynamic");
        (bytes32 r, bytes32 s) = vm.signP256(P256_PK, digest);
        assertTrue(
            h.verify(2, abi.encode(P256_QX, P256_QY), digest, abi.encode(uint256(r), uint256(s)))
        );
    }

    function test_p256_wrongKey_false() public {
        _etchP256();
        (uint256 otherQx, uint256 otherQy) = vm.publicKeyP256(0xB0B);
        assertFalse(h.verify(2, abi.encode(otherQx, otherQy), P256_DIG, abi.encode(P256_R, P256_S)));
    }

    function test_p256_noPrecompile_false() public view {
        bytes memory input = abi.encodePacked(P256_DIG, P256_R, P256_S, P256_QX, P256_QY);
        (bool ok, bytes memory out) = address(0x100).staticcall(input);
        assertTrue(ok);
        assertEq(out.length, 0);
        assertFalse(h.verify(2, abi.encode(P256_QX, P256_QY), P256_DIG, abi.encode(P256_R, P256_S)));
    }

    function test_p256_zeroReturn_false() public {
        vm.etch(address(0x100), address(new P256ZeroVerifier()).code);
        assertFalse(h.verify(2, abi.encode(P256_QX, P256_QY), P256_DIG, abi.encode(P256_R, P256_S)));
    }

    function test_p256_publicKeyMatchesFixture() public pure {
        (uint256 qx, uint256 qy) = vm.publicKeyP256(P256_PK);
        assertEq(qx, P256_QX);
        assertEq(qy, P256_QY);
    }

    function test_p256_highS_accepted() public {
        _etchP256();
        assertTrue(
            h.verify(2, abi.encode(P256_QX, P256_QY), P256_DIG, abi.encode(P256_R, P256_N - P256_S))
        );
    }

    function test_p256_badSignatureLength_false() public {
        _etchP256();
        assertFalse(h.verify(2, abi.encode(P256_QX, P256_QY), P256_DIG, hex"deadbeef"));
    }

    function test_p256_badDataLength_false() public {
        _etchP256();
        assertFalse(h.verify(2, new bytes(63), P256_DIG, abi.encode(P256_R, P256_S)));
    }

    function test_p256_invalidScalars_false() public {
        _etchP256();
        bytes memory key = abi.encode(P256_QX, P256_QY);
        assertFalse(h.verify(2, key, P256_DIG, abi.encode(0, P256_S)));
        assertFalse(h.verify(2, key, P256_DIG, abi.encode(P256_N, P256_S)));
        assertFalse(h.verify(2, key, P256_DIG, abi.encode(P256_R, 0)));
        assertFalse(h.verify(2, key, P256_DIG, abi.encode(P256_R, P256_N)));
    }

    function test_p256_notOnCurve_false() public {
        _etchP256();
        assertFalse(h.verify(2, abi.encode(0, 0), P256_DIG, abi.encode(P256_R, P256_S)));
    }
}
