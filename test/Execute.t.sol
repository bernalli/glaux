// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {GlauxFixture} from "./GlauxFixture.sol";
import {GlauxAccount} from "../src/GlauxAccount.sol";
import {GlauxStorage, SlotSig, Update, Call} from "../src/GlauxStorage.sol";
import {InvalidSignature, ReentrantCall, CallFailed, Executed} from "../src/GlauxStorage.sol";

contract Counter {
    uint256 public n;
    mapping(address => uint256) public paid;

    function bump() external payable {
        n++;
        paid[msg.sender] += msg.value;
    }

    function boom() external pure {
        revert("boom");
    }
}

/// @notice Calls back into the account's executeWithSigs during a batch, replaying the
/// exact same signed batch that is currently in flight (execNonce already advanced).
contract Reenterer {
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

contract ExecuteTest is GlauxFixture {
    Counter internal counter;

    function setUp() public override {
        super.setUp();
        _birthAccount();
        counter = new Counter();
    }

    function test_executeBatchWithValue() public {
        vm.deal(account, 1 ether);
        Call[] memory calls = new Call[](2);
        calls[0] = Call(address(counter), 0.1 ether, abi.encodeCall(Counter.bump, ()));
        calls[1] = Call(address(counter), 0, abi.encodeCall(Counter.bump, ()));
        GlauxAccount(payable(account)).executeWithSigs(calls, _twoSigs(_execDigest(calls)));
        assertEq(counter.n(), 2);
        assertEq(counter.paid(account), 0.1 ether);
        assertEq(GlauxAccount(payable(account)).execNonce(), 1);
    }

    function test_executeRevertBubbles() public {
        Call[] memory calls = new Call[](1);
        calls[0] = Call(address(counter), 0, abi.encodeCall(Counter.boom, ()));
        SlotSig[2] memory sigs = _twoSigs(_execDigest(calls));
        vm.expectRevert(
            abi.encodeWithSelector(
                CallFailed.selector, uint256(0), abi.encodeWithSignature("Error(string)", "boom")
            )
        );
        GlauxAccount(payable(account)).executeWithSigs(calls, sigs);
        assertEq(GlauxAccount(payable(account)).execNonce(), 0); // whole tx reverted
    }

    function test_executeIsChainBound() public {
        Call[] memory calls = new Call[](1);
        calls[0] = Call(address(counter), 0, abi.encodeCall(Counter.bump, ()));
        SlotSig[2] memory sigs = _twoSigs(_execDigest(calls));
        vm.chainId(424242);
        vm.expectRevert(); // digest was bound to the old chain id
        GlauxAccount(payable(account)).executeWithSigs(calls, sigs);
    }

    function test_executeReplayRejected() public {
        Call[] memory calls = new Call[](1);
        calls[0] = Call(address(counter), 0, abi.encodeCall(Counter.bump, ()));
        SlotSig[2] memory sigs = _twoSigs(_execDigest(calls));
        GlauxAccount(payable(account)).executeWithSigs(calls, sigs);
        vm.expectRevert(); // execNonce advanced
        GlauxAccount(payable(account)).executeWithSigs(calls, sigs);
    }

    function test_executeSingleSigRejected() public {
        Call[] memory calls = new Call[](1);
        calls[0] = Call(address(counter), 0, abi.encodeCall(Counter.bump, ()));
        bytes32 d = _execDigest(calls);
        SlotSig[2] memory sigs;
        sigs[0] = SlotSig(0, _sig65(paperPk, d));
        sigs[1] = SlotSig(1, hex"00");
        vm.expectRevert();
        GlauxAccount(payable(account)).executeWithSigs(calls, sigs);
    }

    // --- additional coverage this surface warrants ---

    function test_executeEmptyBatchConsumesNonce() public {
        // An empty batch is a valid no-op execution: it still requires two signatures
        // over the (empty) call array and still advances execNonce, so a signed "do
        // nothing" batch cannot be replayed either.
        Call[] memory calls = new Call[](0);
        GlauxAccount(payable(account)).executeWithSigs(calls, _twoSigs(_execDigest(calls)));
        assertEq(GlauxAccount(payable(account)).execNonce(), 1);
    }

    function test_executeAllOrNothingRollsBackFirstCall() public {
        vm.deal(account, 1 ether);
        Call[] memory calls = new Call[](2);
        calls[0] = Call(address(counter), 0, abi.encodeCall(Counter.bump, ())); // would succeed alone
        calls[1] = Call(address(counter), 0, abi.encodeCall(Counter.boom, ())); // reverts
        SlotSig[2] memory sigs = _twoSigs(_execDigest(calls));
        vm.expectRevert(
            abi.encodeWithSelector(
                CallFailed.selector, uint256(1), abi.encodeWithSignature("Error(string)", "boom")
            )
        );
        GlauxAccount(payable(account)).executeWithSigs(calls, sigs);

        // First call's effect must be rolled back with the rest of the tx.
        assertEq(counter.n(), 0);
        assertEq(GlauxAccount(payable(account)).execNonce(), 0);
    }

    function test_executeCannotRouteApplyUpdateWithoutUpdateSigs() public {
        // Routing applyUpdate through executeWithSigs confers no authority of its own:
        // the inner call still needs a validly signed Update with its own two sigs.
        Update memory u =
            Update(1, 0, abi.encode(uint8(2), uint8(1), abi.encode(address(1)), bytes("")));
        bytes32 badDigest = keccak256("not a real update signature");
        SlotSig[2] memory badSigs;
        badSigs[0] = SlotSig(0, _sig65(paperPk, badDigest));
        badSigs[1] = SlotSig(2, _sig65(cloudPk, badDigest));

        Call[] memory calls = new Call[](1);
        calls[0] = Call(account, 0, abi.encodeCall(GlauxAccount.applyUpdate, (u, badSigs)));
        SlotSig[2] memory outerSigs = _twoSigs(_execDigest(calls));

        vm.expectRevert(
            abi.encodeWithSelector(
                CallFailed.selector, uint256(0), abi.encodeWithSelector(InvalidSignature.selector)
            )
        );
        GlauxAccount(payable(account)).executeWithSigs(calls, outerSigs);
        assertEq(GlauxAccount(payable(account)).updateNonce(), 0);
    }

    function test_executeReentrancyCannotReplay() public {
        Reenterer reenterer = new Reenterer();
        Call[] memory nestedCalls = new Call[](1);
        nestedCalls[0] = Call(address(counter), 0, abi.encodeCall(Counter.bump, ()));
        SlotSig[2] memory nestedSigs = _twoSigs(_execDigestAtNonce(nestedCalls, 1));
        reenterer.arm(account, nestedCalls, nestedSigs);

        Call[] memory calls = new Call[](1);
        calls[0] = Call(address(reenterer), 0, abi.encodeCall(Reenterer.reenter, ()));
        SlotSig[2] memory sigs = _twoSigs(_execDigest(calls));

        vm.expectRevert(
            abi.encodeWithSelector(
                CallFailed.selector, uint256(0), abi.encodeWithSelector(ReentrantCall.selector)
            )
        );
        GlauxAccount(payable(account)).executeWithSigs(calls, sigs);
        assertEq(GlauxAccount(payable(account)).execNonce(), 0);
        assertEq(counter.n(), 0);
    }

    function test_executeSequentialBatchesEmitDistinctIncreasingNonces() public {
        Call[] memory calls = new Call[](1);
        calls[0] = Call(address(counter), 0, abi.encodeCall(Counter.bump, ()));

        vm.expectEmit(true, true, true, true, account);
        emit Executed(1, 1);
        GlauxAccount(payable(account)).executeWithSigs(calls, _twoSigs(_execDigest(calls)));

        vm.expectEmit(true, true, true, true, account);
        emit Executed(2, 1);
        GlauxAccount(payable(account)).executeWithSigs(calls, _twoSigs(_execDigest(calls)));
    }

    function test_relayerWithNoKeysCanSubmitValidBatch() public {
        Call[] memory calls = new Call[](1);
        calls[0] = Call(address(counter), 0, abi.encodeCall(Counter.bump, ()));
        SlotSig[2] memory sigs = _twoSigs(_execDigest(calls));

        vm.prank(address(0x4E1A7));
        GlauxAccount(payable(account)).executeWithSigs(calls, sigs);
        assertEq(counter.n(), 1);
        assertEq(GlauxAccount(payable(account)).execNonce(), 1);
    }

    function test_relayerCannotAlterCallsWithoutInvalidatingSigs() public {
        Call[] memory calls = new Call[](1);
        calls[0] = Call(address(counter), 0, abi.encodeCall(Counter.bump, ()));
        SlotSig[2] memory sigs = _twoSigs(_execDigest(calls));

        // Relayer tampers with the batch after signing (e.g. swaps in boom()).
        calls[0] = Call(address(counter), 0, abi.encodeCall(Counter.boom, ()));

        vm.prank(address(0x4E1A7));
        vm.expectRevert(InvalidSignature.selector);
        GlauxAccount(payable(account)).executeWithSigs(calls, sigs);
    }

    function test_executeSpendsAccountBalanceBeyondMsgValue() public {
        // The account can spend its own balance, not just msg.value forwarded in.
        vm.deal(account, 1 ether);
        Call[] memory calls = new Call[](1);
        calls[0] = Call(address(counter), 1 ether, abi.encodeCall(Counter.bump, ()));
        GlauxAccount(payable(account)).executeWithSigs(calls, _twoSigs(_execDigest(calls)));
        assertEq(counter.paid(account), 1 ether);
        assertEq(account.balance, 0);
    }

    function test_executeInsufficientBalanceFailsCleanly() public {
        // No vm.deal: account has zero balance, batch asks to send 1 ether -> the
        // call itself fails and the whole batch reverts, no partial spend.
        Call[] memory calls = new Call[](1);
        calls[0] = Call(address(counter), 1 ether, abi.encodeCall(Counter.bump, ()));
        SlotSig[2] memory sigs = _twoSigs(_execDigest(calls));
        vm.expectRevert(abi.encodeWithSelector(CallFailed.selector, uint256(0), bytes("")));
        GlauxAccount(payable(account)).executeWithSigs(calls, sigs);
        assertEq(GlauxAccount(payable(account)).execNonce(), 0);
    }
}
