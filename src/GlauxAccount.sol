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
    UpdateApplied,
    Executed
} from "./GlauxStorage.sol";
import {SignatureVerify} from "./lib/SignatureVerify.sol";

/// @notice Glaux account logic. Reached only by delegatecall from GlauxDelegate.
contract GlauxAccount {
    address public immutable ENTRYPOINT;

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
            l.slots[index] = s;
        } else if (u.action == GlauxStorage.ACTION_SET_IMPLEMENTATION) {
            address newImplementation = abi.decode(u.payload, (address));
            if (newImplementation.code.length == 0) revert InvalidImplementation();
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
        l.execNonce += 1;
        _execute(calls);
        emit Executed(l.execNonce, calls.length);
    }

    function _execute(Call[] memory calls) internal {
        for (uint256 i = 0; i < calls.length; i++) {
            (bool ok, bytes memory ret) = calls[i].to.call{value: calls[i].value}(calls[i].data);
            if (!ok) revert CallFailed(i, ret);
        }
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
