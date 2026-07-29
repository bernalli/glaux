// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {GlauxFixture} from "./GlauxFixture.sol";
import {Counter} from "./Execute.t.sol";
import {GlauxAccount} from "../src/GlauxAccount.sol";
import {GlauxStorage, SlotSig, Call, OperationExpired} from "../src/GlauxStorage.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";

/// @notice Submission is permissionless by design: whoever holds a signed operation
///         chooses whether and when to send it. Without a deadline that "when" is
///         forever — a relayer can sit on a signed batch and land it at a moment of
///         its choosing, months later, and the only thing that ever invalidates it is
///         the account executing something else first. A deadline is the signers'
///         half of that bargain.
contract ValidUntilTest is GlauxFixture {
    Counter internal counter;

    function setUp() public override {
        super.setUp();
        _birthAccount();
        counter = new Counter();
        vm.warp(1_800_000_000);
    }

    function _bump() internal view returns (Call[] memory calls) {
        calls = new Call[](1);
        calls[0] = Call(address(counter), 0, abi.encodeCall(Counter.bump, ()));
    }

    function test_execute_succeedsBeforeTheDeadline() public {
        Call[] memory calls = _bump();
        uint48 validUntil = uint48(block.timestamp + 1 hours);

        GlauxAccount(payable(account))
            .executeWithSigs(calls, validUntil, _twoSigs(_execDigest(calls, validUntil)));

        assertEq(counter.n(), 1);
    }

    function test_execute_succeedsExactlyAtTheDeadline() public {
        Call[] memory calls = _bump();
        uint48 validUntil = uint48(block.timestamp);

        GlauxAccount(payable(account))
            .executeWithSigs(calls, validUntil, _twoSigs(_execDigest(calls, validUntil)));

        assertEq(counter.n(), 1);
    }

    function test_execute_revertsAfterTheDeadline() public {
        Call[] memory calls = _bump();
        uint48 validUntil = uint48(block.timestamp + 1 hours);
        SlotSig[2] memory sigs = _twoSigs(_execDigest(calls, validUntil));
        vm.warp(uint256(validUntil) + 1);

        vm.expectRevert(
            abi.encodeWithSelector(OperationExpired.selector, validUntil, block.timestamp)
        );
        GlauxAccount(payable(account)).executeWithSigs(calls, validUntil, sigs);

        assertEq(counter.n(), 0);
        assertEq(GlauxAccount(payable(account)).execNonce(), 0);
    }

    /// @dev Zero is not a licence to run forever anywhere in Glaux — on this path it is
    ///      simply a deadline in the past. The ERC-4337 path has to refuse it
    ///      explicitly, because there zero means "no expiry" to the EntryPoint.
    function test_execute_zeroDeadlineIsAlreadyExpired() public {
        Call[] memory calls = _bump();
        // Built BEFORE arming the cheat: `_execDigest` staticcalls `execNonce()`, and
        // `vm.expectRevert` attaches to the next external call it sees, whichever that is.
        SlotSig[2] memory sigs = _twoSigs(_execDigest(calls, 0));

        vm.expectRevert(
            abi.encodeWithSelector(OperationExpired.selector, uint48(0), block.timestamp)
        );
        GlauxAccount(payable(account)).executeWithSigs(calls, 0, sigs);
    }

    /// @dev The deadline is inside the digest, so a relayer holding a signed batch
    ///      cannot widen its window: changing the value invalidates the signatures it
    ///      was given. Without this the whole control would be decorative.
    function test_execute_deadlineCannotBeWidenedBySubmitter() public {
        Call[] memory calls = _bump();
        uint48 signed = uint48(block.timestamp + 1 hours);
        SlotSig[2] memory sigs = _twoSigs(_execDigest(calls, signed));
        vm.warp(uint256(signed) + 1);

        vm.expectRevert(); // InvalidSignature: the digest no longer matches
        GlauxAccount(payable(account)).executeWithSigs(calls, signed + 2 hours, sigs);

        assertEq(counter.n(), 0);
    }

    /// @dev Expiry is checked before the signature work, so an operation that is dead
    ///      on arrival costs a timestamp comparison rather than two curve operations.
    function test_execute_expiryIsCheckedBeforeSignatures() public {
        Call[] memory calls = _bump();
        SlotSig[2] memory garbage;
        garbage[0] = SlotSig(0, hex"00");
        garbage[1] = SlotSig(2, hex"00");
        uint48 validUntil = uint48(block.timestamp - 1);

        vm.expectRevert(
            abi.encodeWithSelector(OperationExpired.selector, validUntil, block.timestamp)
        );
        GlauxAccount(payable(account)).executeWithSigs(calls, validUntil, garbage);
    }

    // --- ERC-4337 path ---
    //
    // The EntryPoint computes `userOpHash` from the operation's own fields, so a Glaux
    // deadline cannot ride inside it. It travels in the signature blob instead, and the
    // factors sign over both — otherwise whoever submits the operation could rewrite the
    // window while the signature stayed valid. The account reports the window to the
    // EntryPoint through `validationData` and lets the EntryPoint enforce it, which is
    // what makes bundlers drop an expired operation instead of landing it.

    function _packedOp(Call[] memory calls) internal view returns (PackedUserOperation memory op) {
        op.sender = account;
        op.nonce = ep.getNonce(account, 0);
        op.initCode = "";
        op.callData = abi.encodeCall(GlauxAccount.executeFromEntryPoint, (calls));
        op.accountGasLimits = bytes32(abi.encodePacked(uint128(600_000), uint128(600_000)));
        op.preVerificationGas = 100_000;
        op.gasFees = bytes32(abi.encodePacked(uint128(1 gwei), uint128(20 gwei)));
        op.paymasterAndData = "";
    }

    function _handle(PackedUserOperation memory op) internal {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        ep.handleOps(ops, payable(address(0xFEE)));
    }

    function test_userOp_executesBeforeTheDeadline() public {
        vm.deal(account, 2 ether);
        PackedUserOperation memory op = _packedOp(_bump());
        uint48 validUntil = uint48(block.timestamp + 1 hours);
        op.signature = _userOpSignature(ep.getUserOpHash(op), validUntil);

        _handle(op);

        assertEq(counter.n(), 1);
    }

    /// @dev The EntryPoint is the one that refuses it: the account hands back the window
    ///      it was given and `AA22 expired or not due` is the EntryPoint acting on it.
    function test_userOp_expiredIsRejectedByTheEntryPoint() public {
        vm.deal(account, 2 ether);
        PackedUserOperation memory op = _packedOp(_bump());
        uint48 validUntil = uint48(block.timestamp + 1 hours);
        op.signature = _userOpSignature(ep.getUserOpHash(op), validUntil);
        vm.warp(uint256(validUntil) + 1);

        vm.expectRevert(
            abi.encodeWithSelector(
                IEntryPoint.FailedOp.selector, uint256(0), "AA22 expired or not due"
            )
        );
        _handle(op);

        assertEq(counter.n(), 0);
    }

    /// @dev Zero is exactly the state this task existed to remove: the EntryPoint reads
    ///      a zero `validUntil` as "no expiry", so the account must never hand one back.
    ///      It fails validation instead.
    function test_userOp_zeroDeadlineFailsValidation() public {
        vm.deal(account, 2 ether);
        PackedUserOperation memory op = _packedOp(_bump());
        op.signature = _userOpSignature(ep.getUserOpHash(op), 0);

        vm.expectRevert(
            abi.encodeWithSelector(
                IEntryPoint.FailedOp.selector, uint256(0), "AA24 signature error"
            )
        );
        _handle(op);
    }

    function test_userOp_deadlineCannotBeWidenedBySubmitter() public {
        vm.deal(account, 2 ether);
        PackedUserOperation memory op = _packedOp(_bump());
        bytes32 opHash = ep.getUserOpHash(op);
        uint48 signed = uint48(block.timestamp + 1 hours);
        // Signatures made for `signed`, blob rewritten to claim a year.
        op.signature =
            abi.encode(uint48(block.timestamp + 365 days), _twoSigs(_userOpDigest(opHash, signed)));

        vm.expectRevert(
            abi.encodeWithSelector(
                IEntryPoint.FailedOp.selector, uint256(0), "AA24 signature error"
            )
        );
        _handle(op);
    }

    /// @dev The packing the EntryPoint reads: authorizer in the low 160 bits (zero on
    ///      success), then `validUntil`, then `validAfter`. Glaux does not use
    ///      `validAfter`, so it stays zero.
    function test_userOp_validationDataCarriesTheDeadline() public {
        PackedUserOperation memory op = _packedOp(_bump());
        bytes32 opHash = ep.getUserOpHash(op);
        uint48 validUntil = uint48(block.timestamp + 1 hours);
        op.signature = _userOpSignature(opHash, validUntil);

        vm.prank(address(ep));
        uint256 validationData = GlauxAccount(payable(account)).validateUserOp(op, opHash, 0);

        assertEq(validationData, uint256(validUntil) << 160);
        assertEq(uint160(validationData), 0); // authorizer: success
        assertEq(uint48(validationData >> 208), 0); // validAfter unused
    }

    function test_userOp_signatureBlobFitsTheBound() public view {
        bytes memory signature = _userOpSignature(bytes32(uint256(1)), FAR_FUTURE);
        assertLe(signature.length, 576);
    }
}
