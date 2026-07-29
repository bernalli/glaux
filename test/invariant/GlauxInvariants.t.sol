// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import "forge-std/Test.sol";
import {GlauxDelegate} from "../../src/GlauxDelegate.sol";
import {GlauxAccount} from "../../src/GlauxAccount.sol";
import {GlauxStorage, FactorSlot} from "../../src/GlauxStorage.sol";
import {GlauxAccountV2Mock} from "../mocks/GlauxAccountV2Mock.sol";
import {Handler} from "./Handler.sol";

contract NoMarkerImplementation {}

/// @notice Property-based defence for the update channel: no sequence of authorized
///         rotations and rejected forgeries may ever move the account somewhere the
///         independent ghost model in `Handler` does not predict.
contract GlauxInvariants is Test {
    GlauxDelegate internal router;
    GlauxAccount internal impl;
    GlauxAccountV2Mock internal compatibleImpl;
    NoMarkerImplementation internal noMarkerImpl;
    address internal account;
    Handler internal handler;

    uint256 internal constant K0 = 0xAA01;
    uint256 internal constant K1 = 0xAA02;
    uint256 internal constant K2 = 0xAA03;
    uint256 internal constant BIRTH_PK = 0xB112;

    function setUp() public {
        impl = new GlauxAccount(address(0xE47105157017));
        compatibleImpl = new GlauxAccountV2Mock(address(0xE47105157017));
        noMarkerImpl = new NoMarkerImplementation();
        router = new GlauxDelegate();
        account = vm.addr(BIRTH_PK);

        FactorSlot[3] memory slots;
        slots[0] = FactorSlot(GlauxStorage.VERIFIER_SECP256K1, abi.encode(vm.addr(K0)));
        slots[1] = FactorSlot(GlauxStorage.VERIFIER_SECP256K1, abi.encode(vm.addr(K1)));
        slots[2] = FactorSlot(GlauxStorage.VERIFIER_SECP256K1, abi.encode(vm.addr(K2)));
        bytes memory initData = abi.encode(slots);
        bytes32 digest = keccak256(
            abi.encode(
                GlauxStorage.INIT_DOMAIN, address(impl), address(impl).codehash, keccak256(initData)
            )
        );
        bytes memory birthSig = _sig65(BIRTH_PK, digest);

        vm.signAndAttachDelegation(address(router), BIRTH_PK);
        GlauxDelegate(payable(account))
            .initialize(address(impl), address(impl).codehash, initData, birthSig);

        handler = new Handler(
            account, address(impl), address(compatibleImpl), address(noMarkerImpl), K0, K1, K2
        );

        // Only the handler's own entry points may act as the account/attacker; the
        // account itself and the test contract must never be targeted directly, or
        // the fuzzer would bypass the ghost-model bookkeeping entirely.
        targetContract(address(handler));
        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = Handler.exerciseAll.selector;
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
        bytes32 layoutWord = vm.load(account, keccak256("glaux.account.v1.storage"));
        assertEq(uint8(uint256(layoutWord)), 1);
    }

    /// No update action may point the account anywhere other than the independent
    /// implementation ghost maintained by the handler after successful upgrades.
    function invariant_implementationMatchesGhost() public view {
        assertEq(
            address(uint160(uint256(vm.load(account, GlauxStorage.ERC1967_IMPL_SLOT)))),
            handler.ghostImplementation()
        );
    }

    /// Rejected attack calls must never be accepted or fail with a different error.
    /// This runs after every fuzzed step, so fail_on_revert cannot hide a regression.
    function invariant_attacksRejectWithExpectedErrors() public view {
        assertEq(handler.acceptedForgeAttacks(), 0);
        assertEq(handler.wrongErrorForgeries(), 0);
        assertEq(handler.acceptedDuplicateSlotAttacks(), 0);
        assertEq(handler.wrongErrorDuplicateSlotAttempts(), 0);
        assertEq(handler.acceptedWrongNonceAttacks(), 0);
        assertEq(handler.wrongErrorWrongNonceAttempts(), 0);
        assertEq(handler.acceptedWrongCodeHashAttacks(), 0);
        assertEq(handler.wrongErrorWrongCodeHashAttempts(), 0);
        assertEq(handler.acceptedNoMarkerAttacks(), 0);
        assertEq(handler.wrongErrorNoMarkerAttempts(), 0);
    }

    /// Correctly authorized updates are never allowed to fail silently.
    function invariant_authorizedUpdatesSucceed() public view {
        assertEq(handler.failedRotations(), 0);
        assertEq(handler.failedValidUpgrades(), 0);
    }

    /// Runs once at the end of each fuzzed call sequence (not after every single
    /// call, unlike the invariant_* checks above): guards against a vacuous
    /// campaign in which the fuzzer happened never to attempt an attack, which
    /// would otherwise let every invariant above pass by never being exercised.
    function afterInvariant() public view {
        assertGt(handler.successfulRotations(), 0);
        assertGt(handler.actualSlotChanges(), 0);
        assertGt(handler.rejectedForgeries(), 0);
        assertGt(handler.rejectedDuplicateSlotAttempts(), 0);
        assertGt(handler.rejectedWrongNonceAttempts(), 0);
        assertGt(handler.successfulUpgrades(), 0);
        assertGt(handler.rejectedWrongCodeHashAttempts(), 0);
        assertGt(handler.rejectedNoMarkerAttempts(), 0);
    }
}
