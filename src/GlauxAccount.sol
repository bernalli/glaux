// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {
    GlauxStorage,
    FactorSlot,
    SlotSig,
    Update,
    Call,
    AlreadyInitialized,
    NotInitialized,
    BadUpdateNonce,
    CallFailed,
    InvalidAction,
    InvalidImplementation,
    InvalidSignature,
    InvalidSlot,
    InvalidVerifierType,
    DuplicateSlot,
    NotEntryPoint,
    ReentrantCall,
    UpdateApplied,
    Executed
} from "./GlauxStorage.sol";
import {SignatureVerify} from "./lib/SignatureVerify.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";

/// @notice Glaux account logic. Reached only by delegatecall from GlauxDelegate.
contract GlauxAccount {
    // Two 65-byte secp256k1 signatures encode as SlotSig[2] in 480 bytes. 512 bytes
    // leaves room for one trailing ABI word while bounding the self-call copy.
    uint256 internal constant MAX_USEROP_SIGNATURE_LENGTH = 512;

    address public immutable ENTRYPOINT;
    bool private transient executing;

    constructor(address entryPoint) {
        ENTRYPOINT = entryPoint;
        GlauxStorage.layout().initialized = true;
    }

    function initializeAccount(bytes calldata initData) external {
        GlauxStorage.Layout storage l = GlauxStorage.layout();
        if (l.initialized) revert AlreadyInitialized();
        bytes32 implementationSlot = GlauxStorage.ERC1967_IMPL_SLOT;
        address implementation;
        assembly {
            implementation := sload(implementationSlot)
        }
        if (implementation != address(0)) revert AlreadyInitialized();
        FactorSlot[3] memory slots = abi.decode(initData, (FactorSlot[3]));
        for (uint256 i = 0; i < 3; i++) {
            _validateSlot(slots[i]);
        }
        for (uint256 i = 0; i < 3; i++) {
            for (uint256 j = i + 1; j < 3; j++) {
                if (_isDuplicateSlot(slots[i], slots[j])) revert DuplicateSlot();
            }
        }
        for (uint256 i = 0; i < 3; i++) {
            l.slots[i] = slots[i];
        }
        l.initialized = true;
    }

    function _validateSlot(FactorSlot memory s) internal pure {
        if (
            s.verifierType != GlauxStorage.VERIFIER_SECP256K1
                && s.verifierType != GlauxStorage.VERIFIER_P256
        ) {
            revert InvalidVerifierType();
        }
        if (!SignatureVerify.isValidKey(s.verifierType, s.data)) revert InvalidSlot();
    }

    function _isDuplicateSlot(FactorSlot memory a, FactorSlot memory b)
        internal
        pure
        returns (bool)
    {
        return a.verifierType == b.verifierType && keccak256(a.data) == keccak256(b.data);
    }

    function getSlot(uint8 index) external view returns (uint8, bytes memory) {
        if (index > 2) revert InvalidSlot();
        FactorSlot storage s = GlauxStorage.layout().slots[index];
        return (s.verifierType, s.data);
    }

    function updateNonce() external view returns (uint64) {
        return GlauxStorage.layout().updateNonce;
    }

    function execNonce() external view returns (uint64) {
        return GlauxStorage.layout().execNonce;
    }

    function glauxCompatibilityId() external pure returns (bytes32) {
        return GlauxStorage.COMPAT_ID;
    }

    function applyUpdate(Update calldata u, SlotSig[2] calldata sigs) external {
        GlauxStorage.Layout storage l = GlauxStorage.layout();
        if (!l.initialized) revert NotInitialized();
        if (u.nonce != l.updateNonce + 1) revert BadUpdateNonce(l.updateNonce + 1, u.nonce);
        bytes32 digest = keccak256(
            abi.encode(
                GlauxStorage.UPDATE_DOMAIN, address(this), u.nonce, u.action, keccak256(u.payload)
            )
        );
        _requireTwoSigs(digest, [sigs[0], sigs[1]]);
        l.updateNonce = u.nonce;

        if (u.action == GlauxStorage.ACTION_SET_SLOT) {
            (uint8 index, uint8 verifierType, bytes memory data) =
                abi.decode(u.payload, (uint8, uint8, bytes));
            if (index > 2) revert InvalidSlot();
            FactorSlot memory s = FactorSlot(verifierType, data);
            _validateSlot(s);
            for (uint8 i = 0; i < 3; i++) {
                if (i != index && _isDuplicateSlot(s, l.slots[i])) revert DuplicateSlot();
            }
            l.slots[index] = s;
        } else if (u.action == GlauxStorage.ACTION_SET_IMPLEMENTATION) {
            (address newImplementation, bytes32 expectedCodeHash) =
                abi.decode(u.payload, (address, bytes32));
            if (
                newImplementation.code.length == 0 || newImplementation.codehash != expectedCodeHash
            ) revert InvalidImplementation();
            (bool ok, bytes memory ret) = newImplementation.staticcall(
                abi.encodeWithSelector(this.glauxCompatibilityId.selector)
            );
            if (!ok || ret.length != 32 || abi.decode(ret, (bytes32)) != GlauxStorage.COMPAT_ID) {
                revert InvalidImplementation();
            }
            bytes32 slot = GlauxStorage.ERC1967_IMPL_SLOT;
            assembly {
                sstore(slot, newImplementation)
            }
        } else {
            revert InvalidAction();
        }
        emit UpdateApplied(u.nonce, u.action);
    }

    function executeWithSigs(Call[] calldata calls, SlotSig[2] calldata sigs) external payable {
        GlauxStorage.Layout storage l = GlauxStorage.layout();
        if (!l.initialized) revert NotInitialized();
        bytes32 digest = keccak256(
            abi.encode(
                GlauxStorage.EXEC_DOMAIN,
                block.chainid,
                address(this),
                l.execNonce,
                keccak256(abi.encode(calls))
            )
        );
        _requireTwoSigs(digest, [sigs[0], sigs[1]]);
        uint64 nonce = l.execNonce + 1;
        l.execNonce = nonce;
        _execute(calls);
        emit Executed(nonce, calls.length);
    }

    /// @notice ERC-4337 entry point validation hook. Only ENTRYPOINT may call this.
    /// @dev userOp.signature is attacker-controlled and may be malformed; decoding is
    ///      done through a try/catch so garbage bytes yield SIG_VALIDATION_FAILED (1)
    ///      instead of a revert, which would be a worse failure mode for the bundler.
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external returns (uint256 validationData) {
        if (msg.sender != ENTRYPOINT) revert NotEntryPoint();
        (bool decoded, SlotSig[2] memory sigs) = _tryDecodeSigs(userOp.signature);
        validationData = (decoded && _checkTwoSigs(userOpHash, sigs)) ? 0 : 1;
        if (missingAccountFunds > 0) {
            (bool ok,) = msg.sender.call{value: missingAccountFunds}("");
            ok; // EntryPoint verifies the deposit; a failed prefund fails the op there
        }
    }

    /// @notice ERC-4337 execution hook, reached only from the EntryPoint after
    ///         validateUserOp succeeded. The EntryPoint owns replay protection through
    ///         its own per-account nonce, so this path does not touch execNonce.
    function executeFromEntryPoint(Call[] calldata calls) external {
        if (msg.sender != ENTRYPOINT) revert NotEntryPoint();
        _execute(calls);
        emit Executed(GlauxStorage.layout().execNonce, calls.length);
    }

    function _tryDecodeSigs(bytes calldata signature)
        internal
        view
        returns (bool ok, SlotSig[2] memory sigs)
    {
        if (signature.length > MAX_USEROP_SIGNATURE_LENGTH) {
            return (false, sigs);
        }
        try this.decodeSlotSigs(signature) returns (SlotSig[2] memory decoded) {
            return (true, decoded);
        } catch {
            return (false, sigs);
        }
    }

    /// @notice Pure decode helper, external so `_tryDecodeSigs` can call it through a
    ///         try/catch and turn a malformed signature into a bool instead of a revert.
    function decodeSlotSigs(bytes calldata signature) external pure returns (SlotSig[2] memory) {
        return abi.decode(signature, (SlotSig[2]));
    }

    function _execute(Call[] memory calls) internal {
        if (executing) revert ReentrantCall();
        executing = true;
        for (uint256 i = 0; i < calls.length; i++) {
            (bool ok, bytes memory ret) = calls[i].to.call{value: calls[i].value}(calls[i].data);
            if (!ok) revert CallFailed(i, ret);
        }
        executing = false;
    }

    function _requireTwoSigs(bytes32 digest, SlotSig[2] memory sigs) internal view {
        if (!_checkTwoSigs(digest, sigs)) revert InvalidSignature();
    }

    function _checkTwoSigs(bytes32 digest, SlotSig[2] memory sigs) internal view returns (bool) {
        if (sigs[0].slotIndex > 2 || sigs[1].slotIndex > 2) return false;
        if (sigs[0].slotIndex == sigs[1].slotIndex) return false;
        GlauxStorage.Layout storage l = GlauxStorage.layout();
        if (!l.initialized) return false;
        FactorSlot storage a = l.slots[sigs[0].slotIndex];
        FactorSlot storage b = l.slots[sigs[1].slotIndex];
        return SignatureVerify.verify(a.verifierType, a.data, digest, sigs[0].signature)
            && SignatureVerify.verify(b.verifierType, b.data, digest, sigs[1].signature);
    }
}
