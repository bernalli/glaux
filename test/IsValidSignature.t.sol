// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {GlauxFixture} from "./GlauxFixture.sol";
import {GlauxAccount} from "../src/GlauxAccount.sol";
import {GlauxStorage, SlotSig, Call} from "../src/GlauxStorage.sol";

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

    // --- deadline ---

    function test_rejectsAfterTheDeadline() public {
        uint48 validUntil = uint48(block.timestamp + 1 hours);
        bytes memory sig = _msgSignature(HASH, validUntil);
        vm.warp(uint256(validUntil) + 1);
        assertEq(_acct().isValidSignature(HASH, sig), INVALID);
    }

    /// @dev Zero is a deadline in the past everywhere in Glaux, never no-expiry.
    function test_rejectsZeroDeadline() public view {
        assertEq(_acct().isValidSignature(HASH, _msgSignature(HASH, 0)), INVALID);
    }

    /// @dev The deadline rides inside the digest: a holder rewriting the window
    ///      invalidates the signatures they were handed.
    function test_deadlineCannotBeWidenedByTheHolder() public view {
        uint48 signed = uint48(block.timestamp + 1 hours);
        SlotSig[2] memory sigs = _twoSigs(_msgDigest(HASH, signed));
        bytes memory widened = abi.encode(uint48(block.timestamp + 365 days), sigs);
        assertEq(_acct().isValidSignature(HASH, widened), INVALID);
    }

    // --- cross-channel: a signature is valid on exactly the channel it was made for ---

    /// @dev An exec-channel pair offered as a message signature for the same inner
    ///      hash. If this passed, isValidSignature would be an oracle over every
    ///      other channel's digests.
    function test_rejectsAnExecSignatureAsAMessageSignature() public view {
        Call[] memory calls = new Call[](0);
        uint48 validUntil = uint48(block.timestamp + 1 hours);
        bytes32 execStruct = keccak256(
            abi.encode(
                GlauxStorage.EXEC_DOMAIN,
                block.chainid,
                account,
                uint64(0),
                keccak256(abi.encode(calls)),
                validUntil
            )
        );
        SlotSig[2] memory execSigs = _twoSigs(_execDigest(calls, validUntil));
        assertEq(_acct().isValidSignature(execStruct, abi.encode(validUntil, execSigs)), INVALID);
    }

    /// @dev And the reverse: a message pair offered to executeWithSigs.
    function test_aMessageSignatureCannotExecute() public {
        Call[] memory calls = new Call[](0);
        uint48 validUntil = uint48(block.timestamp + 1 hours);
        SlotSig[2] memory msgSigs = _twoSigs(_msgDigest(keccak256(abi.encode(calls)), validUntil));
        vm.expectRevert(); // InvalidSignature
        _acct().executeWithSigs(calls, validUntil, msgSigs);
    }

    // --- chain binding ---

    /// @dev Same account address, same Permit2 address, different chain: without the
    ///      chain id in the digest this would be MAGIC, and one signature would
    ///      authorize the identical action on every chain the account lives on.
    function test_aSignatureFromAnotherChainIsRejected() public {
        uint48 validUntil = uint48(block.timestamp + 1 hours);
        bytes memory sig = _msgSignature(HASH, validUntil); // signed under this chainid
        vm.chainId(block.chainid + 1);
        assertEq(_acct().isValidSignature(HASH, sig), INVALID);
    }

    // --- malformed blobs: never a revert, always the sentinel ---

    function test_garbageBytesReturnTheSentinel() public view {
        assertEq(_acct().isValidSignature(HASH, hex"deadbeef"), INVALID);
        assertEq(_acct().isValidSignature(HASH, ""), INVALID);
    }

    function test_anOverlongBlobReturnsTheSentinel() public view {
        bytes memory fat = new bytes(577);
        assertEq(_acct().isValidSignature(HASH, fat), INVALID);
    }

    // --- quorum ---

    function test_rejectsARepeatedSlotIndex() public view {
        uint48 validUntil = uint48(block.timestamp + 1 hours);
        bytes32 digest = _msgDigest(HASH, validUntil);
        SlotSig[2] memory sigs;
        sigs[0] = SlotSig(0, _sig65(paperPk, digest));
        sigs[1] = SlotSig(0, _sig65(paperPk, digest));
        assertEq(_acct().isValidSignature(HASH, abi.encode(validUntil, sigs)), INVALID);
    }

    function test_rejectsASharedRS() public view {
        uint48 validUntil = uint48(block.timestamp + 1 hours);
        bytes32 digest = _msgDigest(HASH, validUntil);
        bytes memory one = _sig65(paperPk, digest);
        SlotSig[2] memory sigs;
        sigs[0] = SlotSig(0, one);
        sigs[1] = SlotSig(2, one); // same (r,s) offered for a different slot
        assertEq(_acct().isValidSignature(HASH, abi.encode(validUntil, sigs)), INVALID);
    }

    function test_oneValidSignatureAloneIsNotAQuorum() public view {
        uint48 validUntil = uint48(block.timestamp + 1 hours);
        bytes32 digest = _msgDigest(HASH, validUntil);
        SlotSig[2] memory sigs;
        sigs[0] = SlotSig(0, _sig65(paperPk, digest));
        sigs[1] = SlotSig(2, _sig65(uint256(0xBAD), digest)); // not the cloud key
        assertEq(_acct().isValidSignature(HASH, abi.encode(validUntil, sigs)), INVALID);
    }

    // --- the birth boundary ---

    /// @dev The bare implementation is born-like (constructor sets initialized) with
    ///      empty slots: the sentinel, not a revert.
    function test_emptySlotsReturnTheSentinel() public view {
        assertEq(impl.isValidSignature(HASH, _msgSignature(HASH, FAR_FUTURE)), INVALID);
    }

    /// @dev An account never born has no implementation pointer: the ROUTER reverts
    ///      before any implementation code runs. Pinned so it stays a stated
    ///      property; consumers that treat revert-as-invalid handle it correctly.
    function test_anUnbornAccountRevertsAtTheRouter() public {
        uint256 unbornPk = 0xDEAD1;
        address unborn = vm.addr(unbornPk);
        vm.signAndAttachDelegation(address(router), unbornPk);
        vm.expectRevert(); // NotInitialized, raised by the router fallback
        GlauxAccount(payable(unborn)).isValidSignature(HASH, "");
    }
}
