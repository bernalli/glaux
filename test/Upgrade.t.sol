// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {GlauxFixture} from "./GlauxFixture.sol";
import {GlauxAccountV2Mock} from "./mocks/GlauxAccountV2Mock.sol";
import {GlauxAccount} from "../src/GlauxAccount.sol";
import {GlauxStorage, SlotSig, Update} from "../src/GlauxStorage.sol";
import {InvalidImplementation, InvalidSignature} from "../src/GlauxStorage.sol";

contract IncompatibleImplementation {}

contract UpgradeTest is GlauxFixture {
    function setUp() public override {
        super.setUp();
        _birthAccount();
    }

    function test_upgradePreservesState() public {
        GlauxAccountV2Mock v2 = new GlauxAccountV2Mock(address(0xE47));
        Update memory u = Update(1, 1, _implementationPayload(address(v2)));
        GlauxAccount(payable(account)).applyUpdate(u, _twoSigs(_updateDigest(u)));

        assertEq(GlauxAccountV2Mock(payable(account)).version(), "glaux-v2-mock");

        // Pre-upgrade slots and execNonce are intact; updateNonce advances from 0 to 1.
        (uint8 vType0, bytes memory data0) = GlauxAccount(payable(account)).getSlot(0);
        (uint8 vType1, bytes memory data1) = GlauxAccount(payable(account)).getSlot(1);
        (uint8 vType2, bytes memory data2) = GlauxAccount(payable(account)).getSlot(2);
        assertEq(vType0, GlauxStorage.VERIFIER_SECP256K1);
        assertEq(abi.decode(data0, (address)), vm.addr(paperPk));
        assertEq(vType1, GlauxStorage.VERIFIER_P256);
        (uint256 qx, uint256 qy) = abi.decode(data1, (uint256, uint256));
        assertEq(qx, DEVICE_QX);
        assertEq(qy, DEVICE_QY);
        assertEq(vType2, GlauxStorage.VERIFIER_SECP256K1);
        assertEq(abi.decode(data2, (address)), vm.addr(cloudPk));

        assertEq(GlauxAccount(payable(account)).updateNonce(), 1);
        assertEq(GlauxAccount(payable(account)).execNonce(), 0);
    }

    function test_upgradeToEOARejected() public {
        Update memory u = Update(1, 1, abi.encode(address(0xDEAD), bytes32(0)));
        vm.expectRevert(InvalidImplementation.selector);
        GlauxAccount(payable(account)).applyUpdate(u, _twoSigs(_updateDigest(u)));
    }

    function test_upgradeToZeroAddressRejected() public {
        Update memory u = Update(1, 1, abi.encode(address(0), bytes32(0)));
        vm.expectRevert(InvalidImplementation.selector);
        GlauxAccount(payable(account)).applyUpdate(u, _twoSigs(_updateDigest(u)));
    }

    function test_upgradeNeedsTwoSigs() public {
        GlauxAccountV2Mock v2 = new GlauxAccountV2Mock(address(0xE47));
        Update memory u = Update(1, 1, _implementationPayload(address(v2)));
        bytes32 d = _updateDigest(u);
        SlotSig[2] memory sigs;
        sigs[0] = SlotSig(0, _sig65(paperPk, d));
        sigs[1] = SlotSig(2, hex"00");
        vm.expectRevert(InvalidSignature.selector);
        GlauxAccount(payable(account)).applyUpdate(u, sigs);
    }

    function test_upgradeNeedsTwoDistinctSlots() public {
        GlauxAccountV2Mock v2 = new GlauxAccountV2Mock(address(0xE47));
        Update memory u = Update(1, 1, _implementationPayload(address(v2)));
        bytes32 d = _updateDigest(u);
        SlotSig[2] memory sigs;
        sigs[0] = SlotSig(0, _sig65(paperPk, d));
        sigs[1] = SlotSig(0, _sig65(paperPk, d));
        vm.expectRevert(InvalidSignature.selector);
        GlauxAccount(payable(account)).applyUpdate(u, sigs);
    }

    function test_updateChannelSurvivesItsOwnUpgrade() public {
        GlauxAccountV2Mock v2 = new GlauxAccountV2Mock(address(0xE47));
        Update memory u1 = Update(1, 1, _implementationPayload(address(v2)));
        GlauxAccount(payable(account)).applyUpdate(u1, _twoSigs(_updateDigest(u1)));
        assertEq(GlauxAccount(payable(account)).updateNonce(), 1);

        // The update nonce continues, and a further SetSlot applies through the new
        // implementation code, proving the channel survives its own upgrade.
        Update memory u2 =
            Update(2, 0, abi.encode(uint8(2), uint8(1), abi.encode(vm.addr(0xC10D2))));
        GlauxAccount(payable(account)).applyUpdate(u2, _twoSigs(_updateDigest(u2)));

        (, bytes memory data) = GlauxAccount(payable(account)).getSlot(2);
        assertEq(abi.decode(data, (address)), vm.addr(0xC10D2));
        assertEq(GlauxAccount(payable(account)).updateNonce(), 2);
        assertEq(GlauxAccountV2Mock(payable(account)).version(), "glaux-v2-mock");
    }

    function test_upgradeRejectsMismatchedCodeHashForCompatibleImplementation() public {
        GlauxAccountV2Mock v2 = new GlauxAccountV2Mock(address(0xE47));
        Update memory u = Update(1, 1, abi.encode(address(v2), address(impl).codehash));

        vm.expectRevert(InvalidImplementation.selector);
        GlauxAccount(payable(account)).applyUpdate(u, _twoSigs(_updateDigest(u)));
    }

    function test_upgradeToRouterRejected() public {
        Update memory u = Update(1, 1, _implementationPayload(address(router)));

        vm.expectRevert(InvalidImplementation.selector);
        GlauxAccount(payable(account)).applyUpdate(u, _twoSigs(_updateDigest(u)));
    }

    function test_upgradeToIncompatibleContractRejected() public {
        IncompatibleImplementation incompatible = new IncompatibleImplementation();
        Update memory u = Update(1, 1, _implementationPayload(address(incompatible)));

        vm.expectRevert(InvalidImplementation.selector);
        GlauxAccount(payable(account)).applyUpdate(u, _twoSigs(_updateDigest(u)));
    }
}
