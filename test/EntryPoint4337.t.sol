// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {GlauxFixture} from "./GlauxFixture.sol";
import {Counter} from "./Execute.t.sol";
import {GlauxAccount} from "../src/GlauxAccount.sol";
import {
    GlauxStorage,
    SlotSig,
    Call,
    NotEntryPoint,
    ReentrantCall,
    CallFailed
} from "../src/GlauxStorage.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {TestPaymasterAcceptAll} from "account-abstraction/test/TestPaymasterAcceptAll.sol";
import {Vm} from "forge-std/Vm.sol";

/// @notice Calls back into the account's executeWithSigs (the direct path) during a
/// batch driven through the EntryPoint, to prove the shared `_execute` reentrancy
/// guard also stops reentrancy that crosses the 4337 path into the direct path.
contract Reenterer4337 {
    address public account;
    Call[] internal replayCalls;
    SlotSig[2] internal replaySigs;

    function arm(address _account, Call[] memory _calls, SlotSig[2] memory _sigs) external {
        account = _account;
        delete replayCalls;
        for (uint256 i = 0; i < _calls.length; i++) {
            replayCalls.push(_calls[i]);
        }
        replaySigs[0] = _sigs[0];
        replaySigs[1] = _sigs[1];
    }

    function reenter() external {
        GlauxAccount(payable(account)).executeWithSigs(replayCalls, replaySigs);
    }
}

/// @notice Records the account's balances from inside the sponsored execution.
contract SponsorshipObserver {
    IEntryPoint internal immutable entryPoint;
    address internal immutable account;
    uint256 public accountBalanceDuringExecution;
    uint256 public accountDepositDuringExecution;

    constructor(IEntryPoint _entryPoint, address _account) {
        entryPoint = _entryPoint;
        account = _account;
    }

    function observe() external {
        accountBalanceDuringExecution = account.balance;
        accountDepositDuringExecution = entryPoint.balanceOf(account);
    }
}

contract EntryPoint4337Test is GlauxFixture {
    bytes32 internal constant USER_OPERATION_EVENT =
        keccak256("UserOperationEvent(bytes32,address,address,uint256,bool,uint256,uint256)");

    Counter internal counter;

    function setUp() public override {
        super.setUp();
        _birthAccount();
        counter = new Counter();
    }

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

    function test_userOp_executes() public {
        vm.deal(account, 2 ether);
        Call[] memory calls = new Call[](1);
        calls[0] = Call(address(counter), 0, abi.encodeCall(Counter.bump, ()));
        PackedUserOperation memory op = _packedOp(calls);
        bytes32 opHash = ep.getUserOpHash(op);
        op.signature = abi.encode(_twoSigs(opHash));
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        ep.handleOps(ops, payable(address(0xFEE)));
        assertEq(counter.n(), 1);
    }

    function test_userOp_badSigRejected() public {
        vm.deal(account, 2 ether);
        Call[] memory calls = new Call[](1);
        calls[0] = Call(address(counter), 0, abi.encodeCall(Counter.bump, ()));
        PackedUserOperation memory op = _packedOp(calls);
        bytes32 opHash = ep.getUserOpHash(op);
        SlotSig[2] memory sigs;
        sigs[0] = SlotSig(0, _sig65(0xE711, opHash));
        sigs[1] = SlotSig(2, _sig65(0xE712, opHash));
        op.signature = abi.encode(sigs);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        vm.expectRevert(
            abi.encodeWithSelector(
                IEntryPoint.FailedOp.selector, uint256(0), "AA24 signature error"
            )
        );
        ep.handleOps(ops, payable(address(0xFEE)));
        assertEq(counter.n(), 0);
    }

    function test_executeFromEntryPoint_onlyEntryPoint() public {
        Call[] memory calls = new Call[](0);
        vm.expectRevert(NotEntryPoint.selector);
        GlauxAccount(payable(account)).executeFromEntryPoint(calls);
    }

    function test_validateUserOp_onlyEntryPoint() public {
        Call[] memory calls = new Call[](0);
        PackedUserOperation memory op = _packedOp(calls);
        bytes32 opHash = ep.getUserOpHash(op);
        op.signature = abi.encode(_twoSigs(opHash));
        vm.expectRevert(NotEntryPoint.selector);
        GlauxAccount(payable(account)).validateUserOp(op, opHash, 0);
    }

    function _assertUserOpSignatureFailsValidation(bytes memory signature) internal {
        Call[] memory calls = new Call[](1);
        calls[0] = Call(address(counter), 0, abi.encodeCall(Counter.bump, ()));
        PackedUserOperation memory op = _packedOp(calls);
        op.signature = signature;
        bytes32 opHash = ep.getUserOpHash(op);

        vm.prank(address(ep));
        uint256 validationData = GlauxAccount(payable(account)).validateUserOp(op, opHash, 0);
        assertEq(validationData, 1);
    }

    function test_userOp_emptySignatureFailsValidationWithoutReverting() public {
        _assertUserOpSignatureFailsValidation("");
    }

    function test_userOp_truncatedSignatureHeadFailsValidationWithoutReverting() public {
        bytes memory truncatedHead = new bytes(96);
        assembly ("memory-safe") {
            // Outer offset and the two SlotSig[2] element offsets, without either element head.
            mstore(add(truncatedHead, 0x20), 0x20)
            mstore(add(truncatedHead, 0x40), 0x40)
            mstore(add(truncatedHead, 0x60), 0x100)
        }
        _assertUserOpSignatureFailsValidation(truncatedHead);
    }

    function test_userOp_absurdSignatureOffsetFailsValidationWithoutReverting() public {
        bytes memory absurdOffset = abi.encode(_twoSigs(bytes32(0)));
        assembly ("memory-safe") {
            // The first SlotSig.signature offset is word four of the encoding.
            mstore(add(absurdOffset, 0xa0), not(0))
        }
        _assertUserOpSignatureFailsValidation(absurdOffset);
    }

    function test_userOp_outOfBoundsSignatureOffsetFailsValidationWithoutReverting() public {
        bytes memory outOfBoundsOffset = abi.encode(_twoSigs(bytes32(0)));
        assembly ("memory-safe") {
            // The first SlotSig.signature offset is word four of the encoding.
            mstore(add(outOfBoundsOffset, 0xa0), 0x1000)
        }
        _assertUserOpSignatureFailsValidation(outOfBoundsOffset);
    }

    function test_userOp_oversizedSignatureFailsValidationWithoutReverting() public {
        bytes memory oversizedSignature = new bytes(1_000_000);
        Call[] memory calls = new Call[](0);
        PackedUserOperation memory op = _packedOp(calls);
        op.signature = oversizedSignature;
        bytes32 opHash = ep.getUserOpHash(op);

        vm.prank(address(ep));
        (bool ok, bytes memory result) = address(impl).call{gas: 600_000}(
            abi.encodeCall(GlauxAccount.validateUserOp, (op, opHash, 0))
        );
        assertTrue(ok);
        assertEq(abi.decode(result, (uint256)), 1);
    }

    function test_userOp_sameSlotIndexRejected() public {
        vm.deal(account, 2 ether);
        Call[] memory calls = new Call[](1);
        calls[0] = Call(address(counter), 0, abi.encodeCall(Counter.bump, ()));
        PackedUserOperation memory op = _packedOp(calls);
        bytes32 opHash = ep.getUserOpHash(op);
        SlotSig[2] memory sigs;
        sigs[0] = SlotSig(0, _sig65(paperPk, opHash));
        sigs[1] = SlotSig(0, _sig65(paperPk, opHash));
        op.signature = abi.encode(sigs);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        vm.expectRevert(
            abi.encodeWithSelector(
                IEntryPoint.FailedOp.selector, uint256(0), "AA24 signature error"
            )
        );
        ep.handleOps(ops, payable(address(0xFEE)));
        assertEq(counter.n(), 0);
    }

    function test_userOp_doesNotConsumeExecNonce() public {
        vm.deal(account, 2 ether);
        Call[] memory calls = new Call[](1);
        calls[0] = Call(address(counter), 0, abi.encodeCall(Counter.bump, ()));
        PackedUserOperation memory op = _packedOp(calls);
        bytes32 opHash = ep.getUserOpHash(op);
        op.signature = abi.encode(_twoSigs(opHash));
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        ep.handleOps(ops, payable(address(0xFEE)));
        assertEq(counter.n(), 1);
        assertEq(GlauxAccount(payable(account)).execNonce(), 0);
    }

    function test_userOp_sponsoredExecutionWithZeroBalanceAccount() public {
        TestPaymasterAcceptAll paymaster = new TestPaymasterAcceptAll(ep);
        vm.deal(address(this), 11 ether);
        ep.depositTo{value: 10 ether}(address(paymaster));
        vm.deal(paymaster.owner(), 1 ether);
        vm.prank(paymaster.owner());
        paymaster.addStake{value: 1 ether}(1);

        uint256 accountBalanceBefore = account.balance;
        uint256 accountDepositBefore = ep.balanceOf(account);
        uint256 paymasterDepositBefore = ep.balanceOf(address(paymaster));
        assertEq(accountBalanceBefore, 0);
        assertEq(accountDepositBefore, 0);

        SponsorshipObserver observer = new SponsorshipObserver(ep, account);
        Call[] memory calls = new Call[](2);
        calls[0] = Call(address(observer), 0, abi.encodeCall(SponsorshipObserver.observe, ()));
        calls[1] = Call(address(counter), 0, abi.encodeCall(Counter.bump, ()));
        PackedUserOperation memory op = _packedOp(calls);
        op.paymasterAndData =
            abi.encodePacked(address(paymaster), uint128(200_000), uint128(200_000));
        bytes32 opHash = ep.getUserOpHash(op);
        op.signature = abi.encode(_twoSigs(opHash));
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        vm.recordLogs();
        ep.handleOps(ops, payable(address(0xFEE)));
        Vm.Log[] memory logs = vm.getRecordedLogs();

        assertEq(counter.n(), 1);
        assertEq(observer.accountBalanceDuringExecution(), accountBalanceBefore);
        assertEq(observer.accountDepositDuringExecution(), accountDepositBefore);
        assertEq(account.balance, accountBalanceBefore);
        assertEq(ep.balanceOf(account), accountDepositBefore);
        uint256 actualGasCost = _userOpActualGasCost(logs, opHash, address(paymaster));
        assertGt(actualGasCost, 0);
        assertEq(paymasterDepositBefore - ep.balanceOf(address(paymaster)), actualGasCost);
    }

    function test_userOp_reentrancyIntoDirectPathStoppedByGuard() public {
        vm.deal(account, 2 ether);
        Reenterer4337 reenterer = new Reenterer4337();
        Call[] memory nestedCalls = new Call[](1);
        nestedCalls[0] = Call(address(counter), 0, abi.encodeCall(Counter.bump, ()));
        SlotSig[2] memory nestedSigs = _twoSigs(_execDigestAtNonce(nestedCalls, 0));
        reenterer.arm(account, nestedCalls, nestedSigs);

        Call[] memory calls = new Call[](1);
        calls[0] = Call(address(reenterer), 0, abi.encodeCall(Reenterer4337.reenter, ()));
        PackedUserOperation memory op = _packedOp(calls);
        bytes32 opHash = ep.getUserOpHash(op);
        op.signature = abi.encode(_twoSigs(opHash));
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;

        vm.expectEmit(true, true, false, true, address(ep));
        emit IEntryPoint.UserOperationRevertReason(
            opHash,
            account,
            op.nonce,
            abi.encodeWithSelector(
                CallFailed.selector, uint256(0), abi.encodeWithSelector(ReentrantCall.selector)
            )
        );
        ep.handleOps(ops, payable(address(0xFEE)));

        assertEq(counter.n(), 0);
        assertEq(GlauxAccount(payable(account)).execNonce(), 0);
    }

    function _userOpActualGasCost(Vm.Log[] memory logs, bytes32 userOpHash, address paymaster)
        internal
        view
        returns (uint256 actualGasCost)
    {
        for (uint256 i = 0; i < logs.length; i++) {
            Vm.Log memory log = logs[i];
            if (
                log.emitter == address(ep) && log.topics.length == 4
                    && log.topics[0] == USER_OPERATION_EVENT && log.topics[1] == userOpHash
                    && log.topics[2] == bytes32(uint256(uint160(account)))
                    && log.topics[3] == bytes32(uint256(uint160(paymaster)))
            ) {
                (uint256 nonce, bool success, uint256 gasCost,) =
                    abi.decode(log.data, (uint256, bool, uint256, uint256));
                assertEq(nonce, 0);
                assertTrue(success);
                return gasCost;
            }
        }
        revert("missing UserOperationEvent");
    }
}
