// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {GlauxFixture} from "./GlauxFixture.sol";
import {GlauxAccountV2Mock} from "./mocks/GlauxAccountV2Mock.sol";
import {GlauxAccount} from "../src/GlauxAccount.sol";
import {GlauxStorage, SlotSig, Update} from "../src/GlauxStorage.sol";
import {InvalidImplementation, InvalidSignature} from "../src/GlauxStorage.sol";

contract IncompatibleImplementation {}

/// @notice Answers the marker call successfully with exactly one word — the wrong one.
contract WrongMarkerImplementation {
    function glauxCompatibilityId() external pure returns (bytes32) {
        return keccak256("NOT_GLAUX_V1");
    }
}

/// @notice Answers with fewer than 32 bytes, so the length gate must reject it.
contract ShortMarkerImplementation {
    fallback() external {
        assembly {
            return(0, 4)
        }
    }
}

/// @notice Answers with the right value followed by a second word: 64 bytes, and the
///         exact-length gate must reject it rather than decoding the first word.
contract LongMarkerImplementation {
    function glauxCompatibilityId() external pure returns (bytes32, bytes32) {
        return (GlauxStorage.COMPAT_ID, bytes32(uint256(1)));
    }
}

/// @notice Returns far more data than the 32-byte output window. The bounded
///         staticcall copies only one word, so this is a clean rejection rather
///         than a caller-side memory blow-up.
contract ReturndataBombImplementation {
    fallback() external {
        assembly {
            return(0, 0x20000)
        }
    }
}

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

    /// @notice The code-hash binding is worthless against an EIP-7702 delegated EOA:
    ///         EXTCODEHASH hashes the 23-byte delegation designator while
    ///         DELEGATECALL runs the delegation TARGET's code, and that target can
    ///         hold different code on a different chain. The upgrade path must
    ///         refuse designators, exactly as birth does.
    function test_upgradeToDelegatedEoaRejected() public {
        uint256 decoyPk = 0xDEC0DE;
        address decoy = vm.addr(decoyPk);
        GlauxAccountV2Mock v2 = new GlauxAccountV2Mock(address(0xE47));
        vm.signAndAttachDelegation(address(v2), decoyPk);

        // It would otherwise pass every check: it has code, and the marker
        // staticcall resolves through the delegation to compatible logic.
        bytes memory decoyCode = decoy.code;
        assertEq(decoyCode.length, 23);
        assertEq(uint8(decoyCode[0]), 0xEF);
        assertEq(GlauxAccount(payable(decoy)).glauxCompatibilityId(), GlauxStorage.COMPAT_ID);

        Update memory u = Update(1, 1, _implementationPayload(decoy));
        vm.expectRevert(InvalidImplementation.selector);
        GlauxAccount(payable(account)).applyUpdate(u, _twoSigs(_updateDigest(u)));
    }

    function test_upgradeToWrongMarkerValueRejected() public {
        WrongMarkerImplementation wrong = new WrongMarkerImplementation();
        Update memory u = Update(1, 1, _implementationPayload(address(wrong)));

        vm.expectRevert(InvalidImplementation.selector);
        GlauxAccount(payable(account)).applyUpdate(u, _twoSigs(_updateDigest(u)));
    }

    function test_upgradeToShortMarkerReturndataRejected() public {
        ShortMarkerImplementation short = new ShortMarkerImplementation();
        Update memory u = Update(1, 1, _implementationPayload(address(short)));

        vm.expectRevert(InvalidImplementation.selector);
        GlauxAccount(payable(account)).applyUpdate(u, _twoSigs(_updateDigest(u)));
    }

    function test_upgradeToLongMarkerReturndataRejected() public {
        LongMarkerImplementation long = new LongMarkerImplementation();
        Update memory u = Update(1, 1, _implementationPayload(address(long)));

        vm.expectRevert(InvalidImplementation.selector);
        GlauxAccount(payable(account)).applyUpdate(u, _twoSigs(_updateDigest(u)));
    }

    function test_upgradeToReturndataBombRejected() public {
        ReturndataBombImplementation bomb = new ReturndataBombImplementation();
        Update memory u = Update(1, 1, _implementationPayload(address(bomb)));

        vm.expectRevert(InvalidImplementation.selector);
        GlauxAccount(payable(account)).applyUpdate(u, _twoSigs(_updateDigest(u)));
    }
}
