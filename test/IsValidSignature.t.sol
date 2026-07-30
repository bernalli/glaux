// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {GlauxFixture} from "./GlauxFixture.sol";
import {GlauxAccount} from "../src/GlauxAccount.sol";
import {GlauxStorage, SlotSig} from "../src/GlauxStorage.sol";

/// @notice ERC-1271 makes the account a signer. A message signature is an
///         authorization that moves funds through Permit2 without any Glaux nonce
///         advancing, so this channel is bounded (deadline) and bound (chain id,
///         account, own domain) everywhere the other channels are.
contract IsValidSignatureTest is GlauxFixture {
    bytes4 internal constant MAGIC = 0x1626ba7e;
    bytes4 internal constant INVALID = 0xffffffff;
    bytes32 internal constant HASH = keccak256("a message a protocol wants signed");

    function setUp() public override {
        super.setUp();
        _birthAccount();
        vm.warp(1_800_000_000);
    }

    function _acct() internal view returns (GlauxAccount) {
        return GlauxAccount(payable(account));
    }

    function test_acceptsAQuorumSignatureBeforeTheDeadline() public view {
        uint48 validUntil = uint48(block.timestamp + 1 hours);
        assertEq(_acct().isValidSignature(HASH, _msgSignature(HASH, validUntil)), MAGIC);
    }

    function test_acceptsExactlyAtTheDeadline() public view {
        uint48 validUntil = uint48(block.timestamp);
        assertEq(_acct().isValidSignature(HASH, _msgSignature(HASH, validUntil)), MAGIC);
    }

    /// @dev Both verifier types must work as either signer; the paper+cloud default
    ///      pair is secp256k1-only, so pin the P-256 device factor explicitly.
    function test_acceptsWithTheP256FactorAsOneSigner() public view {
        uint48 validUntil = uint48(block.timestamp + 1 hours);
        bytes32 digest = _msgDigest(HASH, validUntil);
        SlotSig[2] memory sigs;
        sigs[0] = SlotSig(1, _sigP256(DEVICE_P256_PK, digest));
        sigs[1] = SlotSig(2, _sig65(cloudPk, digest));
        assertEq(_acct().isValidSignature(HASH, abi.encode(validUntil, sigs)), MAGIC);
    }
}
