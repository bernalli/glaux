// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {GlauxFixture} from "./GlauxFixture.sol";
import {GlauxDelegate} from "../src/GlauxDelegate.sol";
import {GlauxAccount} from "../src/GlauxAccount.sol";
import {
    GlauxStorage,
    FactorSlot,
    AlreadyInitialized,
    NotInitialized,
    InvalidImplementation,
    InvalidBirthSignature,
    DuplicateSlot,
    InvalidSlot,
    InvalidVerifierType
} from "../src/GlauxStorage.sol";

contract NonInitializingAccount {
    function initializeAccount(bytes calldata) external {}
}

contract BirthTest is GlauxFixture {
    function test_birth_initializes() public {
        _birthAccount();

        (uint8 vType, bytes memory data) = GlauxAccount(payable(account)).getSlot(0);
        assertEq(vType, GlauxStorage.VERIFIER_SECP256K1);
        assertEq(abi.decode(data, (address)), vm.addr(paperPk));
        assertEq(GlauxAccount(payable(account)).updateNonce(), 0);
        assertEq(GlauxAccount(payable(account)).execNonce(), 0);
        assertEq(GlauxAccount(payable(account)).ENTRYPOINT(), address(0xE47));
    }

    function test_birth_preservesSlotOrdering() public {
        _birthAccount();

        (uint8 paperType, bytes memory paperData) = GlauxAccount(payable(account)).getSlot(0);
        (uint8 deviceType, bytes memory deviceData) = GlauxAccount(payable(account)).getSlot(1);
        (uint8 cloudType, bytes memory cloudData) = GlauxAccount(payable(account)).getSlot(2);

        assertEq(paperType, GlauxStorage.VERIFIER_SECP256K1);
        assertEq(abi.decode(paperData, (address)), vm.addr(paperPk));
        assertEq(deviceType, GlauxStorage.VERIFIER_P256);
        (uint256 qx, uint256 qy) = abi.decode(deviceData, (uint256, uint256));
        assertEq(qx, DEVICE_QX);
        assertEq(qy, DEVICE_QY);
        assertEq(cloudType, GlauxStorage.VERIFIER_SECP256K1);
        assertEq(abi.decode(cloudData, (address)), vm.addr(cloudPk));
    }

    function test_birth_rejectsTwoSlotsWithIdenticalKey() public {
        vm.signAndAttachDelegation(address(router), birthPk);
        FactorSlot[3] memory duplicate = _slots();
        duplicate[2] = duplicate[0];
        bytes memory initData = abi.encode(duplicate);
        bytes32 digest =
            keccak256(abi.encode(GlauxStorage.INIT_DOMAIN, address(impl), keccak256(initData)));

        vm.expectRevert(DuplicateSlot.selector);
        GlauxDelegate(payable(account)).initialize(address(impl), initData, _sig65(birthPk, digest));
    }

    function test_birth_rejectsAllSlotsWithIdenticalKey() public {
        vm.signAndAttachDelegation(address(router), birthPk);
        FactorSlot[3] memory duplicate = _slots();
        duplicate[1] = duplicate[0];
        duplicate[2] = duplicate[0];
        bytes memory initData = abi.encode(duplicate);
        bytes32 digest =
            keccak256(abi.encode(GlauxStorage.INIT_DOMAIN, address(impl), keccak256(initData)));

        vm.expectRevert(DuplicateSlot.selector);
        GlauxDelegate(payable(account)).initialize(address(impl), initData, _sig65(birthPk, digest));
    }

    function test_birth_withThreeDistinctKeysStillSucceeds() public {
        _birthAccount();

        (uint8 paperType, bytes memory paperData) = GlauxAccount(payable(account)).getSlot(0);
        (uint8 deviceType, bytes memory deviceData) = GlauxAccount(payable(account)).getSlot(1);
        (uint8 cloudType, bytes memory cloudData) = GlauxAccount(payable(account)).getSlot(2);
        assertFalse(paperType == deviceType && keccak256(paperData) == keccak256(deviceData));
        assertFalse(paperType == cloudType && keccak256(paperData) == keccak256(cloudData));
        assertFalse(deviceType == cloudType && keccak256(deviceData) == keccak256(cloudData));
    }

    function test_birth_anyoneCanSubmitSameBlob() public {
        vm.signAndAttachDelegation(address(router), birthPk);
        (bytes memory initData, bytes memory sig) = _initBlob();

        vm.prank(address(0xF20A7));
        GlauxDelegate(payable(account)).initialize(address(impl), initData, sig);

        (uint8 vType,) = GlauxAccount(payable(account)).getSlot(1);
        assertEq(vType, GlauxStorage.VERIFIER_P256);
    }

    function test_birth_rejectsForgedBlob() public {
        vm.signAndAttachDelegation(address(router), birthPk);
        bytes memory initData = abi.encode(_slots());
        bytes32 digest =
            keccak256(abi.encode(GlauxStorage.INIT_DOMAIN, address(impl), keccak256(initData)));

        vm.expectRevert(InvalidBirthSignature.selector);
        GlauxDelegate(payable(account)).initialize(address(impl), initData, _sig65(0xE711, digest));
    }

    function test_birth_rejectsDifferentImplementationWithSameSignature() public {
        vm.signAndAttachDelegation(address(router), birthPk);
        (bytes memory initData, bytes memory sig) = _initBlob();
        GlauxAccount otherImpl = new GlauxAccount(address(0xE47));

        vm.expectRevert(InvalidBirthSignature.selector);
        GlauxDelegate(payable(account)).initialize(address(otherImpl), initData, sig);
    }

    function test_birth_rejectsDifferentSlotsWithSameSignature() public {
        vm.signAndAttachDelegation(address(router), birthPk);
        (, bytes memory sig) = _initBlob();
        FactorSlot[3] memory changed = _slots();
        changed[0] = FactorSlot(GlauxStorage.VERIFIER_SECP256K1, abi.encode(address(0xBAD)));

        vm.expectRevert(InvalidBirthSignature.selector);
        GlauxDelegate(payable(account)).initialize(address(impl), abi.encode(changed), sig);
    }

    function test_birth_secondInitReverts() public {
        _birthAccount();
        (bytes memory initData, bytes memory sig) = _initBlob();

        vm.expectRevert(AlreadyInitialized.selector);
        GlauxDelegate(payable(account)).initialize(address(impl), initData, sig);
    }

    function test_birth_noCodeImplementationRevertsAndOriginalBlobIsRetryable() public {
        vm.signAndAttachDelegation(address(router), birthPk);
        address futureImplementation = address(0xF00D);
        bytes memory initData = abi.encode(_slots());
        bytes32 digest = keccak256(
            abi.encode(GlauxStorage.INIT_DOMAIN, futureImplementation, keccak256(initData))
        );
        bytes memory sig = _sig65(birthPk, digest);

        vm.expectRevert(InvalidImplementation.selector);
        GlauxDelegate(payable(account)).initialize(futureImplementation, initData, sig);

        assertEq(vm.load(account, GlauxStorage.ERC1967_IMPL_SLOT), bytes32(0));
        vm.expectRevert(NotInitialized.selector);
        GlauxAccount(payable(account)).updateNonce();

        vm.etch(futureImplementation, address(impl).code);
        GlauxDelegate(payable(account)).initialize(futureImplementation, initData, sig);

        (uint8 vType,) = GlauxAccount(payable(account)).getSlot(0);
        assertEq(vType, GlauxStorage.VERIFIER_SECP256K1);
    }

    function test_birth_zeroImplementationReverts() public {
        vm.signAndAttachDelegation(address(router), birthPk);
        bytes memory initData = abi.encode(_slots());
        bytes32 digest =
            keccak256(abi.encode(GlauxStorage.INIT_DOMAIN, address(0), keccak256(initData)));

        vm.expectRevert(InvalidImplementation.selector);
        GlauxDelegate(payable(account)).initialize(address(0), initData, _sig65(birthPk, digest));
    }

    function test_birth_revertsWhenImplementationDoesNotSetInitialized() public {
        vm.signAndAttachDelegation(address(router), birthPk);
        NonInitializingAccount nonInitializingImplementation = new NonInitializingAccount();
        bytes memory initData = abi.encode(_slots());
        bytes32 digest = keccak256(
            abi.encode(
                GlauxStorage.INIT_DOMAIN,
                address(nonInitializingImplementation),
                keccak256(initData)
            )
        );

        vm.expectRevert(NotInitialized.selector);
        GlauxDelegate(payable(account))
            .initialize(address(nonInitializingImplementation), initData, _sig65(birthPk, digest));

        assertEq(vm.load(account, GlauxStorage.ERC1967_IMPL_SLOT), bytes32(0));
    }

    function test_initializeAccountDirectlyOnImplementationReverts() public {
        vm.expectRevert(AlreadyInitialized.selector);
        impl.initializeAccount(abi.encode(_slots()));
    }

    function test_initializeAccountCannotBypassRouterBeforeBirth() public {
        vm.signAndAttachDelegation(address(router), birthPk);

        vm.expectRevert(NotInitialized.selector);
        GlauxAccount(payable(account)).initializeAccount(abi.encode(_slots()));
    }

    function test_attackerCannotInitializeThroughAccountBeforeBirthWhenLogicExists() public {
        vm.signAndAttachDelegation(address(router), birthPk);
        FactorSlot[3] memory attackerSlots = _slots();
        attackerSlots[0] = FactorSlot(GlauxStorage.VERIFIER_SECP256K1, abi.encode(address(0xBAD)));

        vm.store(account, GlauxStorage.ERC1967_IMPL_SLOT, bytes32(uint256(uint160(address(impl)))));

        vm.prank(address(0xA77AC));
        vm.expectRevert(AlreadyInitialized.selector);
        GlauxAccount(payable(account)).initializeAccount(abi.encode(attackerSlots));
    }

    function test_initializeAccountDirectlyOnBornAccountReverts() public {
        _birthAccount();

        vm.expectRevert(AlreadyInitialized.selector);
        GlauxAccount(payable(account)).initializeAccount(abi.encode(_slots()));
    }

    function test_attackerCannotInitializeThroughAccountAfterBirth() public {
        _birthAccount();
        FactorSlot[3] memory attackerSlots = _slots();
        attackerSlots[0] = FactorSlot(GlauxStorage.VERIFIER_SECP256K1, abi.encode(address(0xBAD)));

        vm.prank(address(0xA77AC));
        vm.expectRevert(AlreadyInitialized.selector);
        GlauxAccount(payable(account)).initializeAccount(abi.encode(attackerSlots));

        (, bytes memory paperData) = GlauxAccount(payable(account)).getSlot(0);
        assertEq(abi.decode(paperData, (address)), vm.addr(paperPk));
    }

    function test_birth_rejectsInvalidSlotAndRollsBackImplementation() public {
        vm.signAndAttachDelegation(address(router), birthPk);
        FactorSlot[3] memory invalid = _slots();
        invalid[0] = FactorSlot(GlauxStorage.VERIFIER_SECP256K1, new bytes(31));
        bytes memory initData = abi.encode(invalid);
        bytes32 digest =
            keccak256(abi.encode(GlauxStorage.INIT_DOMAIN, address(impl), keccak256(initData)));

        vm.expectRevert(InvalidSlot.selector);
        GlauxDelegate(payable(account)).initialize(address(impl), initData, _sig65(birthPk, digest));

        vm.expectRevert(NotInitialized.selector);
        GlauxAccount(payable(account)).updateNonce();
        (bytes memory validData, bytes memory validSig) = _initBlob();
        GlauxDelegate(payable(account)).initialize(address(impl), validData, validSig);
    }

    function test_birth_rejectsOneUnusableSlot() public {
        vm.signAndAttachDelegation(address(router), birthPk);
        FactorSlot[3] memory invalid = _slots();
        invalid[0] = FactorSlot(GlauxStorage.VERIFIER_SECP256K1, abi.encode(address(0)));
        bytes memory initData = abi.encode(invalid);
        bytes32 digest =
            keccak256(abi.encode(GlauxStorage.INIT_DOMAIN, address(impl), keccak256(initData)));

        vm.expectRevert(InvalidSlot.selector);
        GlauxDelegate(payable(account)).initialize(address(impl), initData, _sig65(birthPk, digest));
    }

    function test_birth_rejectsTwoUnusableSlots() public {
        vm.signAndAttachDelegation(address(router), birthPk);
        FactorSlot[3] memory invalid = _slots();
        invalid[0] = FactorSlot(GlauxStorage.VERIFIER_SECP256K1, abi.encode(address(0)));
        invalid[1] = FactorSlot(GlauxStorage.VERIFIER_P256, abi.encode(0, 0));
        bytes memory initData = abi.encode(invalid);
        bytes32 digest =
            keccak256(abi.encode(GlauxStorage.INIT_DOMAIN, address(impl), keccak256(initData)));

        vm.expectRevert(InvalidSlot.selector);
        GlauxDelegate(payable(account)).initialize(address(impl), initData, _sig65(birthPk, digest));
    }

    function test_birth_rejectsInvalidVerifierType() public {
        vm.signAndAttachDelegation(address(router), birthPk);
        FactorSlot[3] memory invalid = _slots();
        invalid[1] = FactorSlot(0, abi.encode(DEVICE_QX, DEVICE_QY));
        bytes memory initData = abi.encode(invalid);
        bytes32 digest =
            keccak256(abi.encode(GlauxStorage.INIT_DOMAIN, address(impl), keccak256(initData)));

        vm.expectRevert(InvalidVerifierType.selector);
        GlauxDelegate(payable(account)).initialize(address(impl), initData, _sig65(birthPk, digest));
    }

    function test_receive_beforeInit() public {
        vm.signAndAttachDelegation(address(router), birthPk);
        vm.deal(address(this), 1 ether);

        (bool ok,) = account.call{value: 0.5 ether}("");

        assertTrue(ok);
        assertEq(account.balance, 0.5 ether);
    }

    function test_fallback_beforeInit_reverts() public {
        vm.signAndAttachDelegation(address(router), birthPk);

        vm.expectRevert(NotInitialized.selector);
        GlauxAccount(payable(account)).updateNonce();
    }

    function test_fallbackSelectorLiteral_matchesNotInitialized() public pure {
        assertEq(bytes4(0x87138d5c), NotInitialized.selector);
    }

    function test_fallback_propagatesSuccessfulReturnData() public {
        _birthAccount();

        (bool ok, bytes memory ret) =
            account.staticcall(abi.encodeCall(GlauxAccount.updateNonce, ()));

        assertTrue(ok);
        assertEq(ret, abi.encode(uint64(0)));
    }

    function test_fallback_propagatesRevertData() public {
        _birthAccount();

        (bool ok, bytes memory ret) = account.call(abi.encodeCall(GlauxAccount.getSlot, (3)));

        assertFalse(ok);
        assertEq(ret, abi.encodeWithSelector(InvalidSlot.selector));
    }
}
