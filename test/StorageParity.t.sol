// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {GlauxFixture} from "./GlauxFixture.sol";
import {GlauxAccount} from "../src/GlauxAccount.sol";
import {GlauxStorage, Update, Call} from "../src/GlauxStorage.sol";

/// @notice Pins the storage-slot arithmetic that scripts/reconcile.py re-implements.
///         The committed fixture (test/fixtures/storage_parity.json) is asserted from
///         BOTH languages; either side changing alone turns it red. Solidity's
///         packing (initialized byte 0, updateNonce bytes 1-8, execNonce bytes 9-16)
///         and the bytes long form are facts of the compiler, proven here rather
///         than assumed — if these assertions disagree with the derivation in the
///         Phase 2 spec, the compiler wins and the spec table gets corrected.
contract StorageParityTest is GlauxFixture {
    bytes32 internal constant BASE = GlauxStorage.SLOT;
    string internal constant FIXTURE = "test/fixtures/storage_parity.json";
    uint256 internal constant NEW_CLOUD_PK = 0xC10D2;

    function setUp() public override {
        super.setUp();
        _birthAccount();
        vm.warp(1_800_000_000);

        // execNonce 0 -> 2: two empty batches. Two, not one, so the two counters
        // hold DIFFERENT values and a packing-order mistake cannot cancel out.
        // Executed BEFORE the rotation: _twoSigs signs with the original cloud key.
        Call[] memory none = new Call[](0);
        for (uint256 i = 0; i < 2; i++) {
            GlauxAccount(payable(account))
                .executeWithSigs(none, FAR_FUTURE, _twoSigs(_execDigest(none, FAR_FUTURE)));
        }

        // updateNonce 0 -> 1: rotate the cloud slot to a fresh key, so the fixture
        // also captures a slot whose content differs from the birth configuration.
        Update memory u = Update(1, GlauxStorage.ACTION_SET_SLOT, _setSlotPayload(2, NEW_CLOUD_PK));
        GlauxAccount(payable(account)).applyUpdate(u, _twoSigs(_updateDigest(u)));
    }

    function _typeSlot(uint256 i) internal pure returns (bytes32) {
        return bytes32(uint256(BASE) + 1 + 2 * i);
    }

    function _dataSlot(uint256 i) internal pure returns (bytes32) {
        return bytes32(uint256(BASE) + 2 + 2 * i);
    }

    function test_derivedSlotKeysFindTheCompilersValues() public view {
        GlauxAccount a = GlauxAccount(payable(account));

        uint256 header = uint256(vm.load(account, BASE));
        assertEq(header & 0xff, 1, "initialized at byte 0");
        assertEq(uint64(header >> 8), a.updateNonce(), "updateNonce at bytes 1-8");
        assertEq(uint64(header >> 72), a.execNonce(), "execNonce at bytes 9-16");
        assertEq(a.updateNonce(), 1);
        assertEq(a.execNonce(), 2);

        for (uint256 i = 0; i < 3; i++) {
            (uint8 vt, bytes memory data) = a.getSlot(uint8(i));
            assertEq(uint256(vm.load(account, _typeSlot(i))), vt, "verifierType slot");

            uint256 hdr = uint256(vm.load(account, _dataSlot(i)));
            // All production payloads are >= 32 bytes (32 for secp256k1, 64 for
            // P-256): long form, header word = 2*len+1, payload from keccak(dataSlot).
            assertEq(hdr, 2 * data.length + 1, "bytes long-form header");
            bytes32 payloadBase = keccak256(abi.encode(_dataSlot(i)));
            for (uint256 j = 0; j * 32 < data.length; j++) {
                bytes32 word = vm.load(account, bytes32(uint256(payloadBase) + j));
                bytes32 expectedWord;
                assembly {
                    expectedWord := mload(add(add(data, 0x20), mul(j, 0x20)))
                }
                assertEq(word, expectedWord, "payload word");
            }
        }
    }

    function _entry(bytes32 slot) internal view returns (string memory) {
        return string.concat(
            "{\"slot\": \"",
            vm.toString(slot),
            "\", \"value\": \"",
            vm.toString(vm.load(account, slot)),
            "\"}"
        );
    }

    /// @dev Run with GLAUX_WRITE_PARITY_FIXTURE=true to (re)generate the committed
    ///      fixture after any storage-layout-affecting change.
    function test_writeFixtureWhenAsked() public {
        if (!vm.envOr("GLAUX_WRITE_PARITY_FIXTURE", false)) return;
        GlauxAccount a = GlauxAccount(payable(account));

        string memory entries = _entry(BASE);
        string memory expectedSlots = "";
        for (uint256 i = 0; i < 3; i++) {
            (uint8 vt, bytes memory data) = a.getSlot(uint8(i));
            entries = string.concat(entries, ",\n    ", _entry(_typeSlot(i)));
            entries = string.concat(entries, ",\n    ", _entry(_dataSlot(i)));
            bytes32 payloadBase = keccak256(abi.encode(_dataSlot(i)));
            for (uint256 j = 0; j * 32 < data.length; j++) {
                entries =
                    string.concat(entries, ",\n    ", _entry(bytes32(uint256(payloadBase) + j)));
            }
            expectedSlots = string.concat(
                expectedSlots,
                i == 0 ? "" : ",\n      ",
                "{\"verifierType\": ",
                vm.toString(vt),
                ", \"data\": \"",
                vm.toString(data),
                "\"}"
            );
        }

        string memory json = string.concat(
            "{\n  \"account\": \"",
            vm.toString(account),
            "\",\n  \"base\": \"",
            vm.toString(BASE),
            "\",\n  \"entries\": [\n    ",
            entries,
            "\n  ],\n  \"expected\": {\n    \"initialized\": true,\n    \"updateNonce\": ",
            vm.toString(a.updateNonce()),
            ",\n    \"execNonce\": ",
            vm.toString(a.execNonce()),
            ",\n    \"slots\": [\n      ",
            expectedSlots,
            "\n    ]\n  }\n}\n"
        );
        vm.writeFile(FIXTURE, json);
    }
}
