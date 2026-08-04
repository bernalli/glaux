// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import "forge-std/Script.sol";
import {GlauxAccount} from "../src/GlauxAccount.sol";
import {GlauxDelegate} from "../src/GlauxDelegate.sol";

contract Deploy is Script {
    bytes32 constant SALT = keccak256("glaux.v1");
    // EntryPoint v0.7 canonical address.
    address constant ENTRYPOINT = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;
    // The CREATE2 factory Foundry routes `new C{salt: ...}()` through, so the
    // predicted address below is the one the broadcast will actually produce.
    address constant CREATE2_DEPLOYER = 0x4e59b44847b379578588920cA78FbF26c0B4956C;

    /// @dev Deploys only what is missing. The router is immutable and its bytecode never
    /// changes, so its CREATE2 address is the same on every chain and stays occupied once
    /// reached: a plain `new` collides there while the implementation — which does change
    /// between versions, and therefore lands on a fresh address — has not been deployed yet.
    /// Because a collision reverts the whole script, the unconditional version could not
    /// deploy a new implementation onto any chain the router had already reached. That is
    /// the normal case for a redeploy, not an edge case.
    function run() external {
        address implAddr = vm.computeCreate2Address(
            SALT,
            keccak256(abi.encodePacked(type(GlauxAccount).creationCode, abi.encode(ENTRYPOINT))),
            CREATE2_DEPLOYER
        );
        address routerAddr = vm.computeCreate2Address(
            SALT, keccak256(type(GlauxDelegate).creationCode), CREATE2_DEPLOYER
        );

        bool implExisted = implAddr.code.length != 0;
        bool routerExisted = routerAddr.code.length != 0;

        vm.startBroadcast();
        if (!implExisted) {
            require(
                address(new GlauxAccount{salt: SALT}(ENTRYPOINT)) == implAddr,
                "impl address mismatch"
            );
        }
        if (!routerExisted) {
            require(
                address(new GlauxDelegate{salt: SALT}()) == routerAddr, "router address mismatch"
            );
        }
        vm.stopBroadcast();

        console2.log(
            "GlauxAccount:", implAddr, implExisted ? "(already deployed)" : "(deployed now)"
        );
        console2.log(
            "GlauxDelegate:", routerAddr, routerExisted ? "(already deployed)" : "(deployed now)"
        );
        console2.logBytes32(implAddr.codehash);
    }
}
