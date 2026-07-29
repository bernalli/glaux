// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import "forge-std/Test.sol";
import {GlauxStorage, FactorSlot} from "../src/GlauxStorage.sol";
import {
    AlreadyInitialized,
    NotInitialized,
    InvalidBirthSignature,
    BadUpdateNonce,
    DuplicateSlot,
    InvalidSignature,
    InvalidSlot,
    InvalidVerifierType,
    InvalidAction,
    NotEntryPoint,
    CallFailed,
    Initialized,
    UpdateApplied,
    Executed
} from "../src/GlauxStorage.sol";

contract StorageHarness {
    function setSlot0(uint8 vType, bytes calldata data) external {
        GlauxStorage.layout().slots[0] = FactorSlot(vType, data);
    }

    function getSlot0() external view returns (uint8, bytes memory) {
        FactorSlot storage s = GlauxStorage.layout().slots[0];
        return (s.verifierType, s.data);
    }

    function setInitialized(bool value) external {
        GlauxStorage.layout().initialized = value;
    }

    function setUpdateNonce(uint64 value) external {
        GlauxStorage.layout().updateNonce = value;
    }

    function setExecNonce(uint64 value) external {
        GlauxStorage.layout().execNonce = value;
    }

    function setSlot(uint8 index, uint8 vType, bytes calldata data) external {
        GlauxStorage.layout().slots[index] = FactorSlot(vType, data);
    }

    function getSlot(uint8 index) external view returns (uint8, bytes memory) {
        FactorSlot storage s = GlauxStorage.layout().slots[index];
        return (s.verifierType, s.data);
    }

    function emitInitialized(address implementation) external {
        emit Initialized(implementation);
    }

    function emitUpdateApplied(uint64 nonce, uint8 action) external {
        emit UpdateApplied(nonce, action);
    }

    function emitExecuted(uint64 execNonce, uint256 numCalls) external {
        emit Executed(execNonce, numCalls);
    }
}

contract StorageTest is Test {
    function test_layout_roundtrip() public {
        StorageHarness h = new StorageHarness();
        h.setSlot0(1, abi.encode(address(0xBEEF)));
        (uint8 v, bytes memory d) = h.getSlot0();
        assertEq(v, 1);
        assertEq(abi.decode(d, (address)), address(0xBEEF));
    }

    function test_namespace_root_matches_literal() public pure {
        bytes32 expectedRoot = keccak256("glaux.account.v1.storage");
        assertEq(GlauxStorage.SLOT, expectedRoot);
    }

    function test_scalar_fields_pack_into_namespace_root_slot() public {
        StorageHarness h = new StorageHarness();
        bytes32 root = keccak256("glaux.account.v1.storage");

        h.setInitialized(true);
        h.setUpdateNonce(0x1122334455667788);
        h.setExecNonce(0x99aabbccddeeff00);

        bytes32 word = vm.load(address(h), root);

        bytes32 expected = bytes32(
            uint256(1) | (uint256(0x1122334455667788) << 8) | (uint256(0x99aabbccddeeff00) << 72)
        );
        assertEq(word, expected);
    }

    function test_factor_slots_begin_at_root_plus_one_and_span_two_slots_each() public {
        StorageHarness h = new StorageHarness();
        bytes32 root = keccak256("glaux.account.v1.storage");

        h.setSlot(2, 7, abi.encode(uint256(1)));

        bytes32 slotWord = vm.load(address(h), bytes32(uint256(root) + 1 + 2 * 2));
        assertEq(uint256(slotWord), 7);
    }

    function test_factor_slot_roundtrip_short_data() public {
        StorageHarness h = new StorageHarness();
        bytes memory shortData = abi.encode(address(0xCAFE));
        h.setSlot(0, GlauxStorage.VERIFIER_SECP256K1, shortData);

        (uint8 v, bytes memory d) = h.getSlot(0);
        assertEq(v, GlauxStorage.VERIFIER_SECP256K1);
        assertEq(d, shortData);
    }

    function test_factor_slot_roundtrip_long_data() public {
        StorageHarness h = new StorageHarness();
        bytes memory longData = abi.encode(uint256(1234567890), uint256(9876543210), uint256(42));
        assertTrue(longData.length > 31);
        h.setSlot(1, GlauxStorage.VERIFIER_P256, longData);

        (uint8 v, bytes memory d) = h.getSlot(1);
        assertEq(v, GlauxStorage.VERIFIER_P256);
        assertEq(d, longData);
    }

    function test_factor_slot_roundtrip_third_slot() public {
        StorageHarness h = new StorageHarness();
        bytes memory data = abi.encode(uint256(1), uint256(2));
        h.setSlot(2, GlauxStorage.VERIFIER_P256, data);

        (uint8 v, bytes memory d) = h.getSlot(2);
        assertEq(v, GlauxStorage.VERIFIER_P256);
        assertEq(d, data);
    }

    function test_verifier_type_constants() public pure {
        assertEq(GlauxStorage.VERIFIER_SECP256K1, 1);
        assertEq(GlauxStorage.VERIFIER_P256, 2);
    }

    function test_action_constants() public pure {
        assertEq(GlauxStorage.ACTION_SET_SLOT, 0);
        assertEq(GlauxStorage.ACTION_SET_IMPLEMENTATION, 1);
    }

    function test_domain_constants() public pure {
        assertEq(GlauxStorage.INIT_DOMAIN, keccak256("GLAUX_INIT_V1"));
        assertEq(GlauxStorage.UPDATE_DOMAIN, keccak256("GLAUX_UPDATE_V1"));
        assertEq(GlauxStorage.EXEC_DOMAIN, keccak256("GLAUX_EXEC_V1"));
    }

    function test_erc1967_impl_slot_constant() public pure {
        bytes32 expected = bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1);
        assertEq(GlauxStorage.ERC1967_IMPL_SLOT, expected);
    }

    function test_error_vocabulary_selectors_are_nonzero() public pure {
        assertTrue(AlreadyInitialized.selector != bytes4(0));
        assertTrue(NotInitialized.selector != bytes4(0));
        assertTrue(InvalidBirthSignature.selector != bytes4(0));
        assertTrue(BadUpdateNonce.selector != bytes4(0));
        assertTrue(DuplicateSlot.selector != bytes4(0));
        assertTrue(InvalidSignature.selector != bytes4(0));
        assertTrue(InvalidSlot.selector != bytes4(0));
        assertTrue(InvalidVerifierType.selector != bytes4(0));
        assertTrue(InvalidAction.selector != bytes4(0));
        assertTrue(NotEntryPoint.selector != bytes4(0));
        assertTrue(CallFailed.selector != bytes4(0));
    }

    function test_event_vocabulary_is_emitted() public {
        StorageHarness h = new StorageHarness();

        vm.expectEmit(true, true, true, true, address(h));
        emit Initialized(address(0x1234));
        h.emitInitialized(address(0x1234));

        vm.expectEmit(true, true, true, true, address(h));
        emit UpdateApplied(7, 1);
        h.emitUpdateApplied(7, 1);

        vm.expectEmit(true, true, true, true, address(h));
        emit Executed(9, 3);
        h.emitExecuted(9, 3);
    }
}
