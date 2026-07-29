// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import "forge-std/Test.sol";
import {GlauxAccount} from "../../src/GlauxAccount.sol";
import {GlauxStorage, SlotSig, Update} from "../../src/GlauxStorage.sol";
import {BadUpdateNonce, DuplicateSlot} from "../../src/GlauxStorage.sol";

/// @notice Drives the fuzzer against a live, born GlauxAccount while keeping an
///         independent "ghost" model of what the on-chain state must be. The ghost
///         is updated ONLY on calls this contract itself proves succeeded (or, for
///         attack attempts, never updated at all) -- it never reads back from the
///         account it is supposed to be checking.
contract Handler is Test {
    address public account;
    uint256[3] public keys; // ghost: current secp256k1 private key per slot
    uint64 public ghostUpdateNonce;

    uint256 public successfulRotations;
    uint256 public rejectedForgeries;
    uint256 public rejectedDuplicateSlotAttempts;
    uint256 public rejectedWrongNonceAttempts;

    constructor(address account_, uint256 k0, uint256 k1, uint256 k2) {
        account = account_;
        keys = [k0, k1, k2];
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

    /// @dev Bounds a candidate private key so its derived address differs from the
    ///      two OTHER ghost slots (the ones not being rotated). The contract itself
    ///      rejects any rotation that would collide with either untouched slot
    ///      (DuplicateSlot), so an unbounded random key would revert almost every
    ///      call and starve the fuzzer of real coverage.
    function _freshKeyFor(uint8 slot, uint256 seed) internal view returns (uint256 pk) {
        uint8 a = uint8((uint256(slot) + 1) % 3);
        uint8 b = uint8((uint256(slot) + 2) % 3);
        address addrA = vm.addr(keys[a]);
        address addrB = vm.addr(keys[b]);
        pk = bound(seed, 1, type(uint128).max);
        while (vm.addr(pk) == addrA || vm.addr(pk) == addrB) {
            pk++;
        }
    }

    /// @notice An authorized 2-of-3 rotation of a bounded slot to a bounded fresh key.
    function rotate(uint8 slotSeed, uint256 newPkSeed) external {
        uint8 slot = uint8(slotSeed % 3);
        uint8 a = uint8((uint256(slot) + 1) % 3);
        uint8 b = uint8((uint256(slot) + 2) % 3);
        uint256 newPk = _freshKeyFor(slot, newPkSeed);

        uint64 nonce = ghostUpdateNonce + 1;
        Update memory u = Update(nonce, GlauxStorage.ACTION_SET_SLOT, _slotPayload(slot, newPk));
        bytes32 d = _digest(u);
        SlotSig[2] memory sigs;
        sigs[0] = SlotSig(a, _sig65(keys[a], d));
        sigs[1] = SlotSig(b, _sig65(keys[b], d));

        GlauxAccount(payable(account)).applyUpdate(u, sigs);

        keys[slot] = newPk;
        ghostUpdateNonce = nonce;
        successfulRotations++;
    }

    /// @notice An attacker who does not hold any of the three real factor keys tries
    ///         to install their own key into a slot, signing with their own key
    ///         instead of the two real slot keys. Must always revert.
    function tryForgeUpdate(uint256 attackerPkSeed, uint8 slotSeed) external {
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

        vm.expectRevert();
        GlauxAccount(payable(account)).applyUpdate(u, sigs);
        rejectedForgeries++;
    }

    /// @notice A fully authorized (real quorum, correct nonce) attempt to rotate a
    ///         slot onto the CURRENT key of one of the other two slots. Must revert
    ///         DuplicateSlot() and must never advance the nonce.
    function tryDuplicateSlot(uint8 slotSeed, bool copyFromA) external {
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

        vm.expectRevert(DuplicateSlot.selector);
        GlauxAccount(payable(account)).applyUpdate(u, sigs);
        rejectedDuplicateSlotAttempts++;
    }

    /// @notice A correctly authorized update (real quorum, valid non-colliding key)
    ///         submitted under a nonce that is not exactly ghostUpdateNonce + 1. Must
    ///         revert BadUpdateNonce() and must never advance the nonce or the ghost.
    function tryWrongNonce(uint8 slotSeed, uint256 newPkSeed, uint64 wrongNonceSeed) external {
        uint8 slot = uint8(slotSeed % 3);
        uint8 a = uint8((uint256(slot) + 1) % 3);
        uint8 b = uint8((uint256(slot) + 2) % 3);
        uint256 newPk = _freshKeyFor(slot, newPkSeed);

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

        vm.expectRevert(abi.encodeWithSelector(BadUpdateNonce.selector, correctNonce, wrongNonce));
        GlauxAccount(payable(account)).applyUpdate(u, sigs);
        rejectedWrongNonceAttempts++;
    }
}
