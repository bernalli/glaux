// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";

/// @notice Test-only ERC-721 with an open safe-mint, so tests can drive the
///         receiver hook through the real OZ checked-transfer path.
contract TestERC721 is ERC721("Test", "TST") {
    function mint(address to, uint256 id) external {
        _safeMint(to, id);
    }
}
