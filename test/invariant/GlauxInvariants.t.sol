// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import "forge-std/Test.sol";
import {GlauxDelegate} from "../../src/GlauxDelegate.sol";
import {GlauxAccount} from "../../src/GlauxAccount.sol";
import {GlauxStorage, FactorSlot} from "../../src/GlauxStorage.sol";
import {GlauxAccountV2Mock} from "../mocks/GlauxAccountV2Mock.sol";
import {Handler} from "./Handler.sol";

contract NoMarkerImplementation {}

/// @dev A benign call target that always accepts a zero-value call, so an
///      authorized execution never fails for a reason unrelated to authorization.
contract ExecutionSink {
    receive() external payable {}
}

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
        bytes[3] memory proofs;
        uint256[3] memory keys = [K0, K1, K2];
        for (uint8 i = 0; i < 3; i++) {
            proofs[i] = _sig65(keys[i], _regDigest(i, slots[i].verifierType, slots[i].data));
        }
        bytes memory initData = abi.encode(slots, proofs);
        bytes32 digest = GlauxStorage.eip191(
            address(router),
            keccak256(
                abi.encode(
                    GlauxStorage.INIT_DOMAIN,
                    address(impl),
                    address(impl).codehash,
                    keccak256(initData)
                )
            )
        );
        bytes memory birthSig = _sig65(BIRTH_PK, digest);

        vm.signAndAttachDelegation(address(router), BIRTH_PK);
        GlauxDelegate(payable(account))
            .initialize(address(impl), address(impl).codehash, initData, birthSig);

        ExecutionSink sink = new ExecutionSink();

        handler = new Handler(
            account,
            address(impl),
            address(compatibleImpl),
            address(noMarkerImpl),
            K0,
            K1,
            K2,
            address(sink)
        );

        // Only the handler's own entry points may act as the account/attacker; the
        // account itself and the test contract must never be targeted directly, or
        // the fuzzer would bypass the ghost-model bookkeeping entirely. All seven
        // actions are registered independently (not behind a fixed macro) so the
        // fuzzer is free to explore every ordering and interleaving -- upgrade
        // before any rotation, consecutive rotations, consecutive upgrades, attacks
        // interleaved anywhere, etc. Reachability of each individual action is
        // proven separately and deterministically by test_allNineActionsReachable
        // below, so this campaign never needs a seed-dependent liveness check.
        targetContract(address(handler));
        bytes4[] memory selectors = new bytes4[](9);
        selectors[0] = Handler.rotate.selector;
        selectors[1] = Handler.tryForgeUpdate.selector;
        selectors[2] = Handler.tryDuplicateSlot.selector;
        selectors[3] = Handler.tryWrongNonce.selector;
        selectors[4] = Handler.tryUpgradeValid.selector;
        selectors[5] = Handler.tryUpgradeWrongCodeHash.selector;
        selectors[6] = Handler.tryUpgradeNoMarker.selector;
        selectors[7] = Handler.execute.selector;
        selectors[8] = Handler.tryExecuteForge.selector;
        targetSelector(FuzzSelector({addr: address(handler), selectors: selectors}));
    }

    function _regDigest(uint8 index, uint8 verifierType, bytes memory data)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(GlauxStorage.REG_DOMAIN, index, verifierType, keccak256(data)));
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

    /// The three slots are always pairwise distinct as `(verifierType, data)` pairs,
    /// so the same credential can never be installed twice and satisfy two slot
    /// signatures with one key.
    ///
    /// Be precise about what this does NOT prove: distinct slot DATA is not distinct
    /// CREDENTIALS. One ECDSA signature `(r, s)` verifies against more than one
    /// public key for a fixed digest, so two slots holding different addresses can
    /// still be covered by a single keypair. That gap is closed in the contract by
    /// the `(r, s)` distinctness check in `_checkTwoSigs`, and proved by
    /// `test_threshold_rejectsOneKeypairSplitAcrossTwoSlotsByVFlip` — not here.
    function invariant_slotsAlwaysPairwiseDistinct() public view {
        (uint8 t0, bytes memory d0) = GlauxAccount(payable(account)).getSlot(0);
        (uint8 t1, bytes memory d1) = GlauxAccount(payable(account)).getSlot(1);
        (uint8 t2, bytes memory d2) = GlauxAccount(payable(account)).getSlot(2);
        assertFalse(t0 == t1 && keccak256(d0) == keccak256(d1));
        assertFalse(t0 == t2 && keccak256(d0) == keccak256(d2));
        assertFalse(t1 == t2 && keccak256(d1) == keccak256(d2));
    }

    /// The account is always initialized and its authoritative implementation
    /// pointer is never zero once born: this is the property whose violation means
    /// permanently frozen funds (the fallback reverts NotInitialized on a zero
    /// pointer, and every state-mutating entry point requires `initialized`).
    /// Reads `IMPL_SLOT`, the slot Glaux owns — never the ERC-1967 mirror.
    function invariant_accountAlwaysInitializedWithImplementationSet() public view {
        assertTrue(vm.load(account, GlauxStorage.IMPL_SLOT) != bytes32(0));
        bytes32 layoutWord = vm.load(account, keccak256("glaux.account.v1.storage"));
        assertEq(uint8(uint256(layoutWord)), 1);
    }

    /// No update action may point the account anywhere other than the independent
    /// implementation ghost maintained by the handler after successful upgrades.
    function invariant_implementationMatchesGhost() public view {
        assertEq(
            address(uint160(uint256(vm.load(account, GlauxStorage.IMPL_SLOT)))),
            handler.ghostImplementation()
        );
    }

    /// On-chain execNonce always equals the ghost: executeWithSigs advances it
    /// exactly once per authorized execution and never under a forged signature.
    function invariant_execNonceMatchesGhost() public view {
        assertEq(GlauxAccount(payable(account)).execNonce(), handler.ghostExecNonce());
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
        assertEq(handler.acceptedExecForgeAttacks(), 0);
        assertEq(handler.wrongErrorExecForgeries(), 0);
    }

    /// Correctly authorized updates are never allowed to fail silently.
    function invariant_authorizedUpdatesSucceed() public view {
        assertEq(handler.failedRotations(), 0);
        assertEq(handler.failedValidUpgrades(), 0);
        assertEq(handler.failedExecs(), 0);
    }

    /// @notice Deterministic reachability proof for every one of the nine handler
    ///         actions, run once each in a fixed order. This is a plain unit test,
    ///         not an invariant: it never depends on what the fuzzer decided to
    ///         explore, so it cannot flake on any seed. It is the sole place where
    ///         "this action fires and is wired correctly" is asserted -- the
    ///         invariant campaign above only ever asserts that nothing bad happened,
    ///         never that something specific ran, which is what keeps it
    ///         seed-independent while still being free to explore every ordering.
    function test_allNineActionsReachable() public {
        // 1. rotate(): authorized 2-of-3 rotation of slot 0 to a fresh key. Must
        //    succeed and really move the on-chain slot to the new key.
        uint64 nonceBeforeRotate = handler.ghostUpdateNonce();
        handler.rotate(0, 0x1234);
        assertEq(handler.successfulRotations(), 1);
        assertEq(handler.actualSlotChanges(), 1);
        assertEq(handler.failedRotations(), 0);
        assertEq(handler.ghostUpdateNonce(), nonceBeforeRotate + 1);
        (, bytes memory slot0Data) = GlauxAccount(payable(account)).getSlot(0);
        assertEq(abi.decode(slot0Data, (address)), vm.addr(handler.keys(0)));

        // 2. tryForgeUpdate(): an attacker holding none of the real keys signs with
        //    their own key instead of a real quorum. Must revert InvalidSignature.
        handler.tryForgeUpdate(0x9999, 1);
        assertEq(handler.rejectedForgeries(), 1);
        assertEq(handler.acceptedForgeAttacks(), 0);
        assertEq(handler.wrongErrorForgeries(), 0);

        // 3. tryDuplicateSlot(): a real quorum tries to rotate slot 0 onto the
        //    current key of slot 1. Must revert DuplicateSlot and never advance
        //    the nonce.
        uint64 nonceBeforeDuplicate = handler.ghostUpdateNonce();
        handler.tryDuplicateSlot(0, true);
        assertEq(handler.rejectedDuplicateSlotAttempts(), 1);
        assertEq(handler.acceptedDuplicateSlotAttacks(), 0);
        assertEq(handler.wrongErrorDuplicateSlotAttempts(), 0);
        assertEq(handler.ghostUpdateNonce(), nonceBeforeDuplicate);

        // 4. tryWrongNonce(): a real quorum authorizes a valid rotation but under a
        //    nonce that is not exactly current+1. Must revert BadUpdateNonce.
        handler.tryWrongNonce(1, 0x4321, 999);
        assertEq(handler.rejectedWrongNonceAttempts(), 1);
        assertEq(handler.acceptedWrongNonceAttacks(), 0);
        assertEq(handler.wrongErrorWrongNonceAttempts(), 0);

        // 5. tryUpgradeValid(): a real quorum upgrades to the Glaux-compatible mock
        //    implementation. Must succeed and really move the ERC-1967 pointer.
        handler.tryUpgradeValid();
        assertEq(handler.successfulUpgrades(), 1);
        assertEq(handler.failedValidUpgrades(), 0);
        assertEq(handler.ghostImplementation(), address(compatibleImpl));
        assertEq(
            address(uint160(uint256(vm.load(account, GlauxStorage.IMPL_SLOT)))),
            address(compatibleImpl)
        );

        // 6. tryUpgradeWrongCodeHash(): a real quorum authorizes an upgrade whose
        //    declared code hash does not match. Must revert InvalidImplementation.
        handler.tryUpgradeWrongCodeHash();
        assertEq(handler.rejectedWrongCodeHashAttempts(), 1);
        assertEq(handler.acceptedWrongCodeHashAttacks(), 0);
        assertEq(handler.wrongErrorWrongCodeHashAttempts(), 0);

        // 7. tryUpgradeNoMarker(): a real quorum authorizes an upgrade to a contract
        //    with code but no compatibility marker. Must revert InvalidImplementation.
        handler.tryUpgradeNoMarker();
        assertEq(handler.rejectedNoMarkerAttempts(), 1);
        assertEq(handler.acceptedNoMarkerAttacks(), 0);
        assertEq(handler.wrongErrorNoMarkerAttempts(), 0);

        // 8. execute(): an authorized 2-of-3 execution of a single zero-value call.
        //    Must succeed and really advance the on-chain execNonce.
        handler.execute();
        assertEq(handler.successfulExecs(), 1);
        assertEq(handler.failedExecs(), 0);
        assertEq(GlauxAccount(payable(account)).execNonce(), 1);

        // 9. tryExecuteForge(): an attacker holding none of the real keys signs an
        //    execution with their own key instead of a real quorum. Must revert
        //    InvalidSignature.
        handler.tryExecuteForge(0x9999, 1);
        assertEq(handler.rejectedExecForgeries(), 1);
        assertEq(handler.acceptedExecForgeAttacks(), 0);
        assertEq(handler.wrongErrorExecForgeries(), 0);
    }
}
