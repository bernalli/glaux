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

        h.setSlot(0, 0x11, hex"01");
        h.setSlot(1, 0x22, hex"02");
        h.setSlot(2, 0x33, hex"03");

        assertEq(uint256(vm.load(address(h), bytes32(uint256(root) + 1))), 0x11);
        assertEq(uint256(vm.load(address(h), bytes32(uint256(root) + 1 + 2))), 0x22);
        assertEq(uint256(vm.load(address(h), bytes32(uint256(root) + 1 + 2 * 2))), 0x33);
    }

    function test_factor_slot_roundtrip_short_data() public {
        StorageHarness h = new StorageHarness();
        bytes memory shortData0 = hex"01";
        bytes memory shortData1 =
            hex"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        bytes memory shortData2 = hex"aabbcc";
        bytes32 root = keccak256("glaux.account.v1.storage");

        assertTrue(shortData0.length < 32);
        assertTrue(shortData1.length < 32);
        assertTrue(shortData2.length < 32);

        h.setSlot(0, GlauxStorage.VERIFIER_SECP256K1, shortData0);
        h.setSlot(1, GlauxStorage.VERIFIER_P256, shortData1);
        h.setSlot(2, GlauxStorage.VERIFIER_SECP256K1, shortData2);

        assertEq(
            vm.load(address(h), bytes32(uint256(root) + 1 + 1)),
            bytes32((uint256(1) << 248) | uint256(2))
        );

        (uint8 v0, bytes memory d0) = h.getSlot(0);
        (uint8 v1, bytes memory d1) = h.getSlot(1);
        (uint8 v2, bytes memory d2) = h.getSlot(2);
        assertEq(v0, GlauxStorage.VERIFIER_SECP256K1);
        assertEq(d0, shortData0);
        assertEq(v1, GlauxStorage.VERIFIER_P256);
        assertEq(d1, shortData1);
        assertEq(v2, GlauxStorage.VERIFIER_SECP256K1);
        assertEq(d2, shortData2);
    }

    function test_factor_slot_roundtrip_long_data() public {
        StorageHarness h = new StorageHarness();
        bytes memory longData0 =
            hex"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021";
        bytes memory longData1 =
            hex"21201f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100";
        bytes memory longData2 =
            hex"a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1";

        assertTrue(longData0.length > 32);
        assertTrue(longData1.length > 32);
        assertTrue(longData2.length > 32);

        h.setSlot(0, GlauxStorage.VERIFIER_SECP256K1, longData0);
        h.setSlot(1, GlauxStorage.VERIFIER_P256, longData1);
        h.setSlot(2, GlauxStorage.VERIFIER_SECP256K1, longData2);

        (uint8 v0, bytes memory d0) = h.getSlot(0);
        (uint8 v1, bytes memory d1) = h.getSlot(1);
        (uint8 v2, bytes memory d2) = h.getSlot(2);
        assertEq(v0, GlauxStorage.VERIFIER_SECP256K1);
        assertEq(d0, longData0);
        assertEq(v1, GlauxStorage.VERIFIER_P256);
        assertEq(d1, longData1);
        assertEq(v2, GlauxStorage.VERIFIER_SECP256K1);
        assertEq(d2, longData2);
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
