// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import "forge-std/Test.sol";
import {GlauxAccount} from "../../src/GlauxAccount.sol";
import {GlauxStorage, SlotSig, Update} from "../../src/GlauxStorage.sol";
import {
    BadUpdateNonce,
    DuplicateSlot,
    InvalidImplementation,
    InvalidSignature
} from "../../src/GlauxStorage.sol";

/// @notice Drives the fuzzer against a live, born GlauxAccount while keeping an
///         independent "ghost" model of what the on-chain state must be. The ghost
///         is updated ONLY on calls this contract itself proves succeeded (or, for
///         attack attempts, never updated at all) -- it never reads back from the
///         account it is supposed to be checking.
contract Handler is Test {
    address public account;
    uint256[3] public keys; // ghost: current secp256k1 private key per slot
    uint64 public ghostUpdateNonce;
    address public ghostImplementation;
    address public immutable compatibleImplementation;
    address public immutable noMarkerImplementation;

    uint256 public successfulRotations;
    uint256 public actualSlotChanges;
    uint256 public failedRotations;
    uint256 public rejectedForgeries;
    uint256 public acceptedForgeAttacks;
    uint256 public wrongErrorForgeries;
    uint256 public rejectedDuplicateSlotAttempts;
    uint256 public acceptedDuplicateSlotAttacks;
    uint256 public wrongErrorDuplicateSlotAttempts;
    uint256 public rejectedWrongNonceAttempts;
    uint256 public acceptedWrongNonceAttacks;
    uint256 public wrongErrorWrongNonceAttempts;
    uint256 public successfulUpgrades;
    uint256 public failedValidUpgrades;
    uint256 public rejectedWrongCodeHashAttempts;
    uint256 public acceptedWrongCodeHashAttacks;
    uint256 public wrongErrorWrongCodeHashAttempts;
    uint256 public rejectedNoMarkerAttempts;
    uint256 public acceptedNoMarkerAttacks;
    uint256 public wrongErrorNoMarkerAttempts;

    constructor(
        address account_,
        address implementation_,
        address compatibleImplementation_,
        address noMarkerImplementation_,
        uint256 k0,
        uint256 k1,
        uint256 k2
    ) {
        account = account_;
        keys = [k0, k1, k2];
        ghostImplementation = implementation_;
        compatibleImplementation = compatibleImplementation_;
        noMarkerImplementation = noMarkerImplementation_;
    }

    function _sig65(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _digest(Update memory u) internal view returns (bytes32) {
        return keccak256(
            abi.encode(GlauxStorage.UPDATE_DOMAIN, account, u.nonce, u.action, keccak256(u.payload))
        );
    }

    function _slotPayload(uint8 slot, uint256 pk) internal pure returns (bytes memory) {
        return abi.encode(slot, GlauxStorage.VERIFIER_SECP256K1, abi.encode(vm.addr(pk)));
    }

    /// @dev Bounds a candidate private key so its derived address differs from all
    ///      three ghost slots. The contract rejects collisions with untouched slots;
    ///      excluding the target slot too makes a successful rotation a real change.
    function _freshKey(uint256 seed) internal view returns (uint256 pk) {
        pk = bound(seed, 1, type(uint128).max);
        while (
            vm.addr(pk) == vm.addr(keys[0]) || vm.addr(pk) == vm.addr(keys[1])
                || vm.addr(pk) == vm.addr(keys[2])
        ) {
            pk++;
        }
    }

    function _applyUpdate(Update memory u, SlotSig[2] memory sigs)
        internal
        returns (bool ok, bytes memory ret)
    {
        return account.call(abi.encodeCall(GlauxAccount.applyUpdate, (u, sigs)));
    }

    function _hasSelector(bytes memory revertData, bytes4 expectedSelector)
        internal
        pure
        returns (bool)
    {
        if (revertData.length < 4) return false;
        bytes4 actualSelector;
        assembly {
            actualSelector := mload(add(revertData, 0x20))
        }
        return actualSelector == expectedSelector;
    }

    /// @notice An authorized 2-of-3 rotation of a bounded slot to a bounded fresh key.
    function rotate(uint8 slotSeed, uint256 newPkSeed) public {
        uint8 slot = uint8(slotSeed % 3);
        uint8 a = uint8((uint256(slot) + 1) % 3);
        uint8 b = uint8((uint256(slot) + 2) % 3);
        uint256 newPk = _freshKey(newPkSeed);

        uint64 nonce = ghostUpdateNonce + 1;
        Update memory u = Update(nonce, GlauxStorage.ACTION_SET_SLOT, _slotPayload(slot, newPk));
        bytes32 d = _digest(u);
        SlotSig[2] memory sigs;
        sigs[0] = SlotSig(a, _sig65(keys[a], d));
        sigs[1] = SlotSig(b, _sig65(keys[b], d));

        (bool ok,) = _applyUpdate(u, sigs);
        if (!ok) {
            failedRotations++;
            return;
        }

        keys[slot] = newPk;
        ghostUpdateNonce = nonce;
        successfulRotations++;
        actualSlotChanges++;
    }

    /// @notice An attacker who does not hold any of the three real factor keys tries
    ///         to install their own key into a slot, signing with their own key
    ///         instead of the two real slot keys. Must always revert.
    function tryForgeUpdate(uint256 attackerPkSeed, uint8 slotSeed) public {
        uint8 slot = uint8(slotSeed % 3);
        uint256 attackerPk = bound(attackerPkSeed, 1, type(uint128).max);
        while (attackerPk == keys[0] || attackerPk == keys[1] || attackerPk == keys[2]) {
            attackerPk++;
        }

        uint64 nonce = ghostUpdateNonce + 1;
        Update memory u =
            Update(nonce, GlauxStorage.ACTION_SET_SLOT, _slotPayload(slot, attackerPk));
        bytes32 d = _digest(u);
        uint8 a = uint8((uint256(slot) + 1) % 3);
        uint8 b = uint8((uint256(slot) + 2) % 3);
        SlotSig[2] memory sigs;
        sigs[0] = SlotSig(a, _sig65(attackerPk, d));
        sigs[1] = SlotSig(b, _sig65(attackerPk, d));

        (bool ok, bytes memory ret) = _applyUpdate(u, sigs);
        if (ok) {
            acceptedForgeAttacks++;
        } else if (_hasSelector(ret, InvalidSignature.selector)) {
            rejectedForgeries++;
        } else {
            wrongErrorForgeries++;
        }
    }

    /// @notice A fully authorized (real quorum, correct nonce) attempt to rotate a
    ///         slot onto the CURRENT key of one of the other two slots. Must revert
    ///         DuplicateSlot() and must never advance the nonce.
    function tryDuplicateSlot(uint8 slotSeed, bool copyFromA) public {
        uint8 slot = uint8(slotSeed % 3);
        uint8 a = uint8((uint256(slot) + 1) % 3);
        uint8 b = uint8((uint256(slot) + 2) % 3);
        uint8 copyFrom = copyFromA ? a : b;

        uint64 nonce = ghostUpdateNonce + 1;
        Update memory u =
            Update(nonce, GlauxStorage.ACTION_SET_SLOT, _slotPayload(slot, keys[copyFrom]));
        bytes32 d = _digest(u);
        SlotSig[2] memory sigs;
        sigs[0] = SlotSig(a, _sig65(keys[a], d));
        sigs[1] = SlotSig(b, _sig65(keys[b], d));

        (bool ok, bytes memory ret) = _applyUpdate(u, sigs);
        if (ok) {
            acceptedDuplicateSlotAttacks++;
        } else if (_hasSelector(ret, DuplicateSlot.selector)) {
            rejectedDuplicateSlotAttempts++;
        } else {
            wrongErrorDuplicateSlotAttempts++;
        }
    }

    /// @notice A correctly authorized update (real quorum, valid non-colliding key)
    ///         submitted under a nonce that is not exactly ghostUpdateNonce + 1. Must
    ///         revert BadUpdateNonce() and must never advance the nonce or the ghost.
    function tryWrongNonce(uint8 slotSeed, uint256 newPkSeed, uint64 wrongNonceSeed) public {
        uint8 slot = uint8(slotSeed % 3);
        uint8 a = uint8((uint256(slot) + 1) % 3);
        uint8 b = uint8((uint256(slot) + 2) % 3);
        uint256 newPk = _freshKey(newPkSeed);

        uint64 correctNonce = ghostUpdateNonce + 1;
        uint64 wrongNonce = uint64(bound(wrongNonceSeed, 0, type(uint64).max));
        if (wrongNonce == correctNonce) {
            wrongNonce = correctNonce == type(uint64).max ? correctNonce - 1 : correctNonce + 1;
        }

        Update memory u =
            Update(wrongNonce, GlauxStorage.ACTION_SET_SLOT, _slotPayload(slot, newPk));
        bytes32 d = _digest(u);
        SlotSig[2] memory sigs;
        sigs[0] = SlotSig(a, _sig65(keys[a], d));
        sigs[1] = SlotSig(b, _sig65(keys[b], d));

        (bool ok, bytes memory ret) = _applyUpdate(u, sigs);
        if (ok) {
            acceptedWrongNonceAttacks++;
        } else if (_hasSelector(ret, BadUpdateNonce.selector)) {
            rejectedWrongNonceAttempts++;
        } else {
            wrongErrorWrongNonceAttempts++;
        }
    }

    /// @notice A real quorum upgrades to a Glaux-compatible implementation. The
    ///         pointer ghost is updated only after this low-level call succeeds.
    function tryUpgradeValid() public {
        uint64 nonce = ghostUpdateNonce + 1;
        Update memory u = Update(
            nonce,
            GlauxStorage.ACTION_SET_IMPLEMENTATION,
            abi.encode(compatibleImplementation, compatibleImplementation.codehash)
        );
        bytes32 d = _digest(u);
        SlotSig[2] memory sigs;
        sigs[0] = SlotSig(0, _sig65(keys[0], d));
        sigs[1] = SlotSig(1, _sig65(keys[1], d));

        (bool ok,) = _applyUpdate(u, sigs);
        if (!ok) {
            failedValidUpgrades++;
            return;
        }

        ghostUpdateNonce = nonce;
        ghostImplementation = compatibleImplementation;
        successfulUpgrades++;
    }

    /// @notice A correctly authorized upgrade with an intentionally wrong code hash
    ///         must be rejected as InvalidImplementation().
    function tryUpgradeWrongCodeHash() public {
        uint64 nonce = ghostUpdateNonce + 1;
        Update memory u = Update(
            nonce,
            GlauxStorage.ACTION_SET_IMPLEMENTATION,
            abi.encode(compatibleImplementation, bytes32(uint256(1)))
        );
        bytes32 d = _digest(u);
        SlotSig[2] memory sigs;
        sigs[0] = SlotSig(0, _sig65(keys[0], d));
        sigs[1] = SlotSig(1, _sig65(keys[1], d));

        (bool ok, bytes memory ret) = _applyUpdate(u, sigs);
        if (ok) {
            acceptedWrongCodeHashAttacks++;
        } else if (_hasSelector(ret, InvalidImplementation.selector)) {
            rejectedWrongCodeHashAttempts++;
        } else {
            wrongErrorWrongCodeHashAttempts++;
        }
    }

    /// @notice A contract with code but no compatibility marker must never become
    ///         the implementation, even under a valid 2-of-3 authorization.
    function tryUpgradeNoMarker() public {
        uint64 nonce = ghostUpdateNonce + 1;
        Update memory u = Update(
            nonce,
            GlauxStorage.ACTION_SET_IMPLEMENTATION,
            abi.encode(noMarkerImplementation, noMarkerImplementation.codehash)
        );
        bytes32 d = _digest(u);
        SlotSig[2] memory sigs;
        sigs[0] = SlotSig(0, _sig65(keys[0], d));
        sigs[1] = SlotSig(1, _sig65(keys[1], d));

        (bool ok, bytes memory ret) = _applyUpdate(u, sigs);
        if (ok) {
            acceptedNoMarkerAttacks++;
        } else if (_hasSelector(ret, InvalidImplementation.selector)) {
            rejectedNoMarkerAttempts++;
        } else {
            wrongErrorNoMarkerAttempts++;
        }
    }

    /// @notice One fuzz step deliberately traverses every update class. This keeps
    ///         afterInvariant's liveness checks deterministic while still varying
    ///         fresh keys, forged keys, slots, duplicate source, and wrong nonces.
    function exerciseAll(
        uint8 slotSeed,
        uint256 newPkSeed,
        uint256 attackerPkSeed,
        uint64 wrongNonceSeed,
        bool copyFromA
    ) external {
        rotate(slotSeed, newPkSeed);
        tryForgeUpdate(attackerPkSeed, slotSeed);
        tryDuplicateSlot(slotSeed, copyFromA);
        tryWrongNonce(slotSeed, newPkSeed, wrongNonceSeed);
        tryUpgradeValid();
        tryUpgradeWrongCodeHash();
        tryUpgradeNoMarker();
    }
}
