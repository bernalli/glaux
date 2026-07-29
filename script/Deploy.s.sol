// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import "forge-std/Script.sol";
import {GlauxAccount} from "../src/GlauxAccount.sol";
import {GlauxDelegate} from "../src/GlauxDelegate.sol";

contract Deploy is Script {
    bytes32 constant SALT = keccak256("glaux.v1");
    // EntryPoint v0.7 canonical address.
    address constant ENTRYPOINT = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;

    function run() external {
        vm.startBroadcast();
        GlauxAccount impl = new GlauxAccount{salt: SALT}(ENTRYPOINT);
        GlauxDelegate router = new GlauxDelegate{salt: SALT}();
        vm.stopBroadcast();
        console2.log("GlauxAccount:", address(impl));
        console2.log("GlauxDelegate:", address(router));
        console2.logBytes32(address(impl).codehash);
    }
}
