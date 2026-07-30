// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {GlauxFixture} from "./GlauxFixture.sol";
import {GlauxAccount} from "../src/GlauxAccount.sol";
import {Call} from "../src/GlauxStorage.sol";
import {TestERC721} from "./mocks/TestERC721.sol";
import {TestERC1155} from "./mocks/TestERC1155.sol";

/// @notice A reference smart account is expected to receive checked transfers.
///         Before Phase 2 every safeTransferFrom into a Glaux account reverted
///         through the router's unknown-selector path.
contract AccountSurfaceTest is GlauxFixture {
    TestERC721 internal nft;
    TestERC1155 internal multi;

    function setUp() public override {
        super.setUp();
        _birthAccount();
        nft = new TestERC721();
        multi = new TestERC1155();
        vm.warp(1_800_000_000);
    }

    function test_receives721SafeMint() public {
        nft.mint(account, 1);
        assertEq(nft.ownerOf(1), account);
    }

    function test_receives1155SingleAndBatch() public {
        multi.mint(account, 1, 5);
        assertEq(multi.balanceOf(account, 1), 5);

        uint256[] memory ids = new uint256[](2);
        uint256[] memory amounts = new uint256[](2);
        ids[0] = 2;
        ids[1] = 3;
        amounts[0] = 1;
        amounts[1] = 7;
        multi.mintBatch(account, ids, amounts);
        assertEq(multi.balanceOf(account, 2), 1);
        assertEq(multi.balanceOf(account, 3), 7);
    }

    /// @dev The common case: the account executes a batch and a token calls back in
    ///      while `_execute` holds the reentrancy guard. The hooks must not take the
    ///      guard, or receiving-while-executing becomes impossible.
    function test_hooksCallableWhileExecuteIsOnTheStack() public {
        Call[] memory calls = new Call[](1);
        calls[0] = Call(address(nft), 0, abi.encodeCall(TestERC721.mint, (account, 42)));

        GlauxAccount(payable(account))
            .executeWithSigs(calls, FAR_FUTURE, _twoSigs(_execDigest(calls, FAR_FUTURE)));

        assertEq(nft.ownerOf(42), account);
    }

    function test_supportsInterfaceAnswersTheFourIds() public view {
        GlauxAccount a = GlauxAccount(payable(account));
        assertTrue(a.supportsInterface(0x01ffc9a7)); // ERC-165
        assertTrue(a.supportsInterface(0x150b7a02)); // IERC721Receiver
        assertTrue(a.supportsInterface(0x4e2312e0)); // IERC1155Receiver
        assertTrue(a.supportsInterface(0x1626ba7e)); // IERC1271
        assertFalse(a.supportsInterface(0xffffffff)); // required false by ERC-165
        assertFalse(a.supportsInterface(0xdeadbeef));
    }
}
