// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {GlauxAccount} from "../../src/GlauxAccount.sol";

contract GlauxAccountV2Mock is GlauxAccount {
    constructor(address entryPoint) GlauxAccount(entryPoint) {}

    function version() external pure returns (string memory) {
        return "glaux-v2-mock";
    }
}
