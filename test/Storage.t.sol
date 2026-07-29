// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import "forge-std/Test.sol";
import {GlauxStorage, FactorSlot} from "../src/GlauxStorage.sol";

contract StorageHarness {
    function setSlot0(uint8 vType, bytes calldata data) external {
        GlauxStorage.layout().slots[0] = FactorSlot(vType, data);
    }

    function getSlot0() external view returns (uint8, bytes memory) {
        FactorSlot storage s = GlauxStorage.layout().slots[0];
        return (s.verifierType, s.data);
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
}
