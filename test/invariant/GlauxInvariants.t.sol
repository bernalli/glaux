// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import "forge-std/Test.sol";
import {GlauxDelegate} from "../../src/GlauxDelegate.sol";
import {GlauxAccount} from "../../src/GlauxAccount.sol";
import {GlauxStorage, FactorSlot} from "../../src/GlauxStorage.sol";
import {Handler} from "./Handler.sol";

/// @notice Property-based defence for the update channel: no sequence of authorized
///         rotations and rejected forgeries may ever move the account somewhere the
///         independent ghost model in `Handler` does not predict.
contract GlauxInvariants is Test {
    GlauxDelegate internal router;
    GlauxAccount internal impl;
    address internal account;
    Handler internal handler;

    uint256 internal constant K0 = 0xAA01;
    uint256 internal constant K1 = 0xAA02;
    uint256 internal constant K2 = 0xAA03;
    uint256 internal constant BIRTH_PK = 0xB112;

    function setUp() public {
        impl = new GlauxAccount(address(0xE47105157017));
        router = new GlauxDelegate();
        account = vm.addr(BIRTH_PK);

        FactorSlot[3] memory slots;
        slots[0] = FactorSlot(GlauxStorage.VERIFIER_SECP256K1, abi.encode(vm.addr(K0)));
        slots[1] = FactorSlot(GlauxStorage.VERIFIER_SECP256K1, abi.encode(vm.addr(K1)));
        slots[2] = FactorSlot(GlauxStorage.VERIFIER_SECP256K1, abi.encode(vm.addr(K2)));
        bytes memory initData = abi.encode(slots);
        bytes32 digest =
            keccak256(abi.encode(GlauxStorage.INIT_DOMAIN, address(impl), keccak256(initData)));
        bytes memory birthSig = _sig65(BIRTH_PK, digest);

        vm.signAndAttachDelegation(address(router), BIRTH_PK);
        GlauxDelegate(payable(account)).initialize(address(impl), initData, birthSig);

        handler = new Handler(account, K0, K1, K2);

        // Only the handler's own entry points may act as the account/attacker; the
        // account itself and the test contract must never be targeted directly, or
        // the fuzzer would bypass the ghost-model bookkeeping entirely.
        targetContract(address(handler));
        bytes4[] memory selectors = new bytes4[](4);
        selectors[0] = Handler.rotate.selector;
        selectors[1] = Handler.tryForgeUpdate.selector;
        selectors[2] = Handler.tryDuplicateSlot.selector;
        selectors[3] = Handler.tryWrongNonce.selector;
        targetSelector(FuzzSelector({addr: address(handler), selectors: selectors}));
    }

    function _sig65(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    /// On-chain update nonce always equals the ghost model: no update ever applied
    /// outside the handler's authorized rotations.
    function invariant_nonceMatchesGhost() public view {
        assertEq(GlauxAccount(payable(account)).updateNonce(), handler.ghostUpdateNonce());
    }

    /// Every slot always holds exactly the key the ghost model says it holds.
    function invariant_slotsMatchGhost() public view {
        for (uint8 i = 0; i < 3; i++) {
            (uint8 vType, bytes memory data) = GlauxAccount(payable(account)).getSlot(i);
            assertEq(vType, GlauxStorage.VERIFIER_SECP256K1);
            assertEq(abi.decode(data, (address)), vm.addr(handler.keys(i)));
        }
    }

    /// Every slot always carries a valid verifier type.
    function invariant_slotsAlwaysValidVerifierType() public view {
        for (uint8 i = 0; i < 3; i++) {
            (uint8 vType,) = GlauxAccount(payable(account)).getSlot(i);
            assertTrue(
                vType == GlauxStorage.VERIFIER_SECP256K1 || vType == GlauxStorage.VERIFIER_P256
            );
        }
    }

    /// The three slots are always pairwise distinct. This is the single most
    /// important invariant in the system: its violation collapses the 2-of-3
    /// threshold to a 1-of-1, since one key would then satisfy two slot signatures.
    function invariant_slotsAlwaysPairwiseDistinct() public view {
        (uint8 t0, bytes memory d0) = GlauxAccount(payable(account)).getSlot(0);
        (uint8 t1, bytes memory d1) = GlauxAccount(payable(account)).getSlot(1);
        (uint8 t2, bytes memory d2) = GlauxAccount(payable(account)).getSlot(2);
        assertFalse(t0 == t1 && keccak256(d0) == keccak256(d1));
        assertFalse(t0 == t2 && keccak256(d0) == keccak256(d2));
        assertFalse(t1 == t2 && keccak256(d1) == keccak256(d2));
    }

    /// The account is always initialized and its ERC-1967 implementation pointer is
    /// never zero once born: this is the property whose violation means permanently
    /// frozen funds (the fallback reverts InvalidImplementation on a zero pointer,
    /// and every state-mutating entry point requires `initialized`).
    function invariant_accountAlwaysInitializedWithImplementationSet() public view {
        assertTrue(vm.load(account, GlauxStorage.ERC1967_IMPL_SLOT) != bytes32(0));
        // Reverts NotInitialized() if the account ever lost its initialized flag.
        GlauxAccount(payable(account)).updateNonce();
    }

    /// Runs once at the end of each fuzzed call sequence (not after every single
    /// call, unlike the invariant_* checks above): guards against a vacuous
    /// campaign in which the fuzzer happened never to attempt an attack, which
    /// would otherwise let every invariant above pass by never being exercised.
    function afterInvariant() public view {
        assertGt(handler.successfulRotations(), 0);
        assertGt(handler.rejectedForgeries(), 0);
        assertGt(handler.rejectedDuplicateSlotAttempts(), 0);
        assertGt(handler.rejectedWrongNonceAttempts(), 0);
    }
}
