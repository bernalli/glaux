// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {GlauxFixture} from "./GlauxFixture.sol";
import {GlauxAccount} from "../src/GlauxAccount.sol";
import {GlauxStorage, FactorSlot, SlotSig, Update} from "../src/GlauxStorage.sol";
import {
    InvalidSlot,
    InvalidSignature,
    BadUpdateNonce,
    DuplicateSlot,
    InvalidAction
} from "../src/GlauxStorage.sol";

contract UpdateChannelTest is GlauxFixture {
    uint256 internal constant NEW_CLOUD_PK = 0xC10D2;

    function setUp() public override {
        super.setUp();
        _birthAccount();
    }

    function test_rotateCloudKey() public {
        Update memory u =
            Update(1, 0, abi.encode(uint8(2), uint8(1), abi.encode(vm.addr(NEW_CLOUD_PK))));
        GlauxAccount(payable(account)).applyUpdate(u, _twoSigs(_updateDigest(u)));

        (, bytes memory data) = GlauxAccount(payable(account)).getSlot(2);
        assertEq(abi.decode(data, (address)), vm.addr(NEW_CLOUD_PK));
        assertEq(GlauxAccount(payable(account)).updateNonce(), 1);
    }

    function test_rotateSlotToExistingKeyReverts() public {
        Update memory u = Update(1, 0, abi.encode(uint8(2), uint8(1), abi.encode(vm.addr(paperPk))));

        vm.expectRevert(DuplicateSlot.selector);
        GlauxAccount(payable(account)).applyUpdate(u, _twoSigs(_updateDigest(u)));

        _assertNonceRollsBackAndValidNonceOneApplies();
    }

    function test_rotateSlotToItsCurrentValueSucceeds() public {
        Update memory u = Update(1, 0, abi.encode(uint8(2), uint8(1), abi.encode(vm.addr(cloudPk))));

        GlauxAccount(payable(account)).applyUpdate(u, _twoSigs(_updateDigest(u)));

        assertEq(GlauxAccount(payable(account)).updateNonce(), 1);
    }

    function test_duplicateRotationCannotReachSameSignatureTwoSlotAttack() public {
        Update memory collapse =
            Update(1, 0, abi.encode(uint8(2), uint8(1), abi.encode(vm.addr(paperPk))));
        vm.expectRevert(DuplicateSlot.selector);
        GlauxAccount(payable(account)).applyUpdate(collapse, _twoSigs(_updateDigest(collapse)));

        Update memory attack =
            Update(1, 0, abi.encode(uint8(1), uint8(1), abi.encode(address(0xA11CE))));
        bytes32 digest = _updateDigest(attack);
        bytes memory paperSignature = _sig65(paperPk, digest);
        SlotSig[2] memory sigs;
        sigs[0] = SlotSig(0, paperSignature);
        sigs[1] = SlotSig(2, paperSignature);

        vm.expectRevert(InvalidSignature.selector);
        GlauxAccount(payable(account)).applyUpdate(attack, sigs);
        assertEq(GlauxAccount(payable(account)).updateNonce(), 0);
    }

    function test_changeSlotType() public {
        // F3 becomes a P-256 key: factor evolution without fund migration (spec Section 6).
        // It must be a DIFFERENT P-256 key from the device slot: rotating slot 2 onto
        // slot 1's key would collapse the 2-of-3 and is rejected as a duplicate.
        (uint256 qx, uint256 qy) = vm.publicKeyP256(0xD1FF);
        Update memory u = Update(1, 0, abi.encode(uint8(2), uint8(2), abi.encode(qx, qy)));
        GlauxAccount(payable(account)).applyUpdate(u, _twoSigs(_updateDigest(u)));

        (uint8 vType, bytes memory data) = GlauxAccount(payable(account)).getSlot(2);
        assertEq(vType, 2);
        (uint256 gotQx, uint256 gotQy) = abi.decode(data, (uint256, uint256));
        assertEq(gotQx, qx);
        assertEq(gotQy, qy);
        assertTrue(qx != DEVICE_QX || qy != DEVICE_QY);
    }

    function test_nonceMustBeSequential() public {
        Update memory u = Update(2, 0, abi.encode(uint8(2), uint8(1), abi.encode(address(1))));

        vm.expectRevert(abi.encodeWithSelector(BadUpdateNonce.selector, uint64(1), uint64(2)));
        GlauxAccount(payable(account)).applyUpdate(u, _twoSigs(_updateDigest(u)));
    }

    function test_replaySameUpdateReverts() public {
        Update memory u = Update(1, 0, abi.encode(uint8(2), uint8(1), abi.encode(address(1))));
        SlotSig[2] memory sigs = _twoSigs(_updateDigest(u));
        GlauxAccount(payable(account)).applyUpdate(u, sigs);

        vm.expectRevert(abi.encodeWithSelector(BadUpdateNonce.selector, uint64(2), uint64(1)));
        GlauxAccount(payable(account)).applyUpdate(u, sigs);
    }

    function test_sameSlotTwiceRejected() public {
        Update memory u = Update(1, 0, abi.encode(uint8(2), uint8(1), abi.encode(address(1))));
        bytes32 d = _updateDigest(u);
        SlotSig[2] memory sigs;
        sigs[0] = SlotSig(0, _sig65(paperPk, d));
        sigs[1] = SlotSig(0, _sig65(paperPk, d));

        vm.expectRevert(InvalidSignature.selector);
        GlauxAccount(payable(account)).applyUpdate(u, sigs);
    }

    function test_outOfRangeSignatureSlotIndexRejected() public {
        Update memory u = Update(1, 0, abi.encode(uint8(2), uint8(1), abi.encode(address(1))));
        bytes32 d = _updateDigest(u);
        SlotSig[2] memory sigs;
        sigs[0] = SlotSig(0, _sig65(paperPk, d));
        sigs[1] = SlotSig(3, _sig65(cloudPk, d));

        vm.expectRevert(InvalidSignature.selector);
        GlauxAccount(payable(account)).applyUpdate(u, sigs);
    }

    function test_outOfRangeSetSlotTargetRejected() public {
        Update memory u = Update(1, 0, abi.encode(uint8(3), uint8(1), abi.encode(address(1))));

        vm.expectRevert(InvalidSlot.selector);
        GlauxAccount(payable(account)).applyUpdate(u, _twoSigs(_updateDigest(u)));

        _assertNonceRollsBackAndValidNonceOneApplies();
    }

    function test_oneValidOneGarbageRejected() public {
        Update memory u = Update(1, 0, abi.encode(uint8(2), uint8(1), abi.encode(address(1))));
        bytes32 d = _updateDigest(u);
        SlotSig[2] memory sigs;
        sigs[0] = SlotSig(0, _sig65(paperPk, d));
        sigs[1] = SlotSig(2, _sig65(0xBAD, d));

        vm.expectRevert(InvalidSignature.selector);
        GlauxAccount(payable(account)).applyUpdate(u, sigs);
    }

    function test_updateAppliesUnderOriginalChainId() public {
        Update memory u = Update(1, 0, abi.encode(uint8(2), uint8(1), abi.encode(address(1))));
        SlotSig[2] memory sigs = _twoSigs(_updateDigest(u));

        GlauxAccount(payable(account)).applyUpdate(u, sigs);
        assertEq(GlauxAccount(payable(account)).updateNonce(), 1);
    }

    function test_sameSignedUpdateAppliesOnUntouchedChain() public {
        // Same signed update, fresh account state (setUp reruns per test), different
        // chain id: proves the digest carries no chain-id and rotations replay everywhere.
        Update memory u = Update(1, 0, abi.encode(uint8(2), uint8(1), abi.encode(address(1))));
        SlotSig[2] memory sigs = _twoSigs(_updateDigest(u));

        vm.chainId(424242);
        GlauxAccount(payable(account)).applyUpdate(u, sigs);
        assertEq(GlauxAccount(payable(account)).updateNonce(), 1);
    }

    function test_sameNonceDifferentUpdates_divergeAcrossChains() public {
        // A signer must never sign two updates for one nonce, or chains can diverge.
        Update memory updateA =
            Update(1, 0, abi.encode(uint8(2), uint8(1), abi.encode(vm.addr(NEW_CLOUD_PK))));
        Update memory updateB =
            Update(1, 0, abi.encode(uint8(2), uint8(1), abi.encode(address(0xB0B))));
        SlotSig[2] memory sigsA = _twoSigs(_updateDigest(updateA));
        SlotSig[2] memory sigsB = _twoSigs(_updateDigest(updateB));
        uint256 snapshot = vm.snapshot();

        vm.chainId(111);
        GlauxAccount(payable(account)).applyUpdate(updateA, sigsA);
        (, bytes memory dataA) = GlauxAccount(payable(account)).getSlot(2);
        assertEq(GlauxAccount(payable(account)).updateNonce(), 1);

        assertTrue(vm.revertTo(snapshot));
        vm.chainId(222);
        GlauxAccount(payable(account)).applyUpdate(updateB, sigsB);
        (, bytes memory dataB) = GlauxAccount(payable(account)).getSlot(2);
        assertEq(GlauxAccount(payable(account)).updateNonce(), 1);
        assertTrue(keccak256(dataA) != keccak256(dataB));
    }

    function test_anyoneCanRelay() public {
        Update memory u = Update(1, 0, abi.encode(uint8(2), uint8(1), abi.encode(address(1))));
        SlotSig[2] memory sigs = _twoSigs(_updateDigest(u));

        vm.prank(address(0x4E1A7));
        GlauxAccount(payable(account)).applyUpdate(u, sigs);
    }

    function test_permissionlessRelayCannotForge() public {
        Update memory u = Update(1, 0, abi.encode(uint8(2), uint8(1), abi.encode(address(0xE11))));
        bytes32 d = _updateDigest(u);
        SlotSig[2] memory sigs;
        sigs[0] = SlotSig(0, _sig65(0xE11, d));
        sigs[1] = SlotSig(2, _sig65(0xE12, d));

        vm.prank(address(0x4E1A7));
        vm.expectRevert(InvalidSignature.selector);
        GlauxAccount(payable(account)).applyUpdate(u, sigs);
    }

    function test_unknownActionReverts() public {
        Update memory u = Update(1, 7, abi.encode(address(0xBEEF)));

        vm.expectRevert(InvalidAction.selector);
        GlauxAccount(payable(account)).applyUpdate(u, _twoSigs(_updateDigest(u)));

        _assertNonceRollsBackAndValidNonceOneApplies();
    }

    // --- Controller decision 4: a rotation must not install an unusable key ---

    function test_rotateToZeroAddressReverts() public {
        Update memory u = Update(1, 0, abi.encode(uint8(2), uint8(1), abi.encode(address(0))));

        vm.expectRevert(InvalidSlot.selector);
        GlauxAccount(payable(account)).applyUpdate(u, _twoSigs(_updateDigest(u)));

        _assertNonceRollsBackAndValidNonceOneApplies();
    }

    function test_rotateToDirtyPaddedAddressReverts() public {
        bytes memory dirtyPaddedSigner = abi.encodePacked(bytes12(uint96(1)), vm.addr(NEW_CLOUD_PK));
        Update memory u = Update(1, 0, abi.encode(uint8(2), uint8(1), dirtyPaddedSigner));

        vm.expectRevert(InvalidSlot.selector);
        GlauxAccount(payable(account)).applyUpdate(u, _twoSigs(_updateDigest(u)));

        _assertNonceRollsBackAndValidNonceOneApplies();
    }

    function test_rotateToOffCurveP256PointReverts() public {
        Update memory u =
            Update(1, 0, abi.encode(uint8(2), uint8(2), abi.encode(uint256(1), uint256(1))));

        vm.expectRevert(InvalidSlot.selector);
        GlauxAccount(payable(account)).applyUpdate(u, _twoSigs(_updateDigest(u)));

        _assertNonceRollsBackAndValidNonceOneApplies();
    }

    function _assertNonceRollsBackAndValidNonceOneApplies() internal {
        assertEq(GlauxAccount(payable(account)).updateNonce(), 0);
        Update memory valid =
            Update(1, 0, abi.encode(uint8(2), uint8(1), abi.encode(vm.addr(NEW_CLOUD_PK))));
        GlauxAccount(payable(account)).applyUpdate(valid, _twoSigs(_updateDigest(valid)));
        assertEq(GlauxAccount(payable(account)).updateNonce(), 1);
    }
}
