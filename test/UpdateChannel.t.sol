// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {GlauxFixture} from "./GlauxFixture.sol";
import {GlauxAccount} from "../src/GlauxAccount.sol";
import {GlauxStorage, FactorSlot, SlotSig, Update} from "../src/GlauxStorage.sol";
import {
    InvalidSlot,
    InvalidSignature,
    BadUpdateNonce,
    InvalidAction
} from "../src/GlauxStorage.sol";

contract UpdateChannelTest is GlauxFixture {
    uint256 internal constant NEW_CLOUD_PK = 0xC10D2;

    function setUp() public override {
        super.setUp();
        _birthAccount();
    }

    function _updateDigest(Update memory u) internal view returns (bytes32) {
        return keccak256(
            abi.encode(GlauxStorage.UPDATE_DOMAIN, account, u.nonce, u.action, keccak256(u.payload))
        );
    }

    function _twoSigs(bytes32 digest) internal view returns (SlotSig[2] memory sigs) {
        sigs[0] = SlotSig(0, _sig65(paperPk, digest)); // F2 paper
        sigs[1] = SlotSig(2, _sig65(cloudPk, digest)); // F3 cloud
    }

    function test_rotateCloudKey() public {
        Update memory u =
            Update(1, 0, abi.encode(uint8(2), uint8(1), abi.encode(vm.addr(NEW_CLOUD_PK))));
        GlauxAccount(payable(account)).applyUpdate(u, _twoSigs(_updateDigest(u)));

        (, bytes memory data) = GlauxAccount(payable(account)).getSlot(2);
        assertEq(abi.decode(data, (address)), vm.addr(NEW_CLOUD_PK));
        assertEq(GlauxAccount(payable(account)).updateNonce(), 1);
    }

    function test_changeSlotType() public {
        // F3 becomes a P-256 key: factor evolution without fund migration (spec Section 6)
        Update memory u =
            Update(1, 0, abi.encode(uint8(2), uint8(2), abi.encode(DEVICE_QX, DEVICE_QY)));
        GlauxAccount(payable(account)).applyUpdate(u, _twoSigs(_updateDigest(u)));

        (uint8 vType,) = GlauxAccount(payable(account)).getSlot(2);
        assertEq(vType, 2);
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

    function test_outOfRangeSlotIndexRejected() public {
        Update memory u = Update(1, 0, abi.encode(uint8(2), uint8(1), abi.encode(address(1))));
        bytes32 d = _updateDigest(u);
        SlotSig[2] memory sigs;
        sigs[0] = SlotSig(0, _sig65(paperPk, d));
        sigs[1] = SlotSig(3, _sig65(cloudPk, d));

        vm.expectRevert(InvalidSignature.selector);
        GlauxAccount(payable(account)).applyUpdate(u, sigs);
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

    function test_setImplementationActionReverts() public {
        Update memory u = Update(1, 1, abi.encode(address(0xBEEF)));

        vm.expectRevert(InvalidAction.selector);
        GlauxAccount(payable(account)).applyUpdate(u, _twoSigs(_updateDigest(u)));
    }

    function test_unknownActionReverts() public {
        Update memory u = Update(1, 7, abi.encode(address(0xBEEF)));

        vm.expectRevert(InvalidAction.selector);
        GlauxAccount(payable(account)).applyUpdate(u, _twoSigs(_updateDigest(u)));
    }

    // --- Controller decision 4: a rotation must not install an unusable key ---

    function test_rotateToZeroAddressReverts() public {
        Update memory u = Update(1, 0, abi.encode(uint8(2), uint8(1), abi.encode(address(0))));

        vm.expectRevert(InvalidSlot.selector);
        GlauxAccount(payable(account)).applyUpdate(u, _twoSigs(_updateDigest(u)));
    }

    function test_rotateToDirtyPaddedAddressReverts() public {
        bytes memory dirtyPaddedSigner = abi.encodePacked(bytes12(uint96(1)), vm.addr(NEW_CLOUD_PK));
        Update memory u = Update(1, 0, abi.encode(uint8(2), uint8(1), dirtyPaddedSigner));

        vm.expectRevert(InvalidSlot.selector);
        GlauxAccount(payable(account)).applyUpdate(u, _twoSigs(_updateDigest(u)));
    }

    function test_rotateToOffCurveP256PointReverts() public {
        Update memory u =
            Update(1, 0, abi.encode(uint8(2), uint8(2), abi.encode(uint256(1), uint256(1))));

        vm.expectRevert(InvalidSlot.selector);
        GlauxAccount(payable(account)).applyUpdate(u, _twoSigs(_updateDigest(u)));
    }
}
