// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {GlauxFixture} from "./GlauxFixture.sol";
import {Counter} from "./Execute.t.sol";
import {GlauxAccount} from "../src/GlauxAccount.sol";
import {GlauxStorage, SlotSig, Call} from "../src/GlauxStorage.sol";
import {NotEntryPoint} from "../src/GlauxStorage.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {TestPaymasterAcceptAll} from "account-abstraction/test/TestPaymasterAcceptAll.sol";

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

contract EntryPoint4337Test is GlauxFixture {
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
        vm.expectRevert(); // EntryPoint reverts with AA24 signature error
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

    function test_userOp_garbageSignatureFailsValidationWithoutReverting() public {
        vm.deal(account, 2 ether);
        Call[] memory calls = new Call[](1);
        calls[0] = Call(address(counter), 0, abi.encodeCall(Counter.bump, ()));
        PackedUserOperation memory op = _packedOp(calls);
        op.signature = hex"deadbeef";
        bytes32 opHash = ep.getUserOpHash(op);

        vm.prank(address(ep));
        uint256 validationData = GlauxAccount(payable(account)).validateUserOp(op, opHash, 0);
        assertEq(validationData, 1);
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
        vm.expectRevert(); // EntryPoint reverts with AA24 signature error
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

        assertEq(account.balance, 0);

        Call[] memory calls = new Call[](1);
        calls[0] = Call(address(counter), 0, abi.encodeCall(Counter.bump, ()));
        PackedUserOperation memory op = _packedOp(calls);
        op.paymasterAndData =
            abi.encodePacked(address(paymaster), uint128(200_000), uint128(200_000));
        bytes32 opHash = ep.getUserOpHash(op);
        op.signature = abi.encode(_twoSigs(opHash));
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        ep.handleOps(ops, payable(address(0xFEE)));

        assertEq(counter.n(), 1);
        assertEq(account.balance, 0);
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

        // Validation succeeds; execution reverts inside executeFromEntryPoint due to
        // the reentrancy guard, but the EntryPoint swallows execution reverts rather
        // than reverting the whole bundle.
        ep.handleOps(ops, payable(address(0xFEE)));

        assertEq(counter.n(), 0);
        assertEq(GlauxAccount(payable(account)).execNonce(), 0);
    }
}
