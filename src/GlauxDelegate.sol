// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {
    GlauxStorage,
    AlreadyInitialized,
    NotInitialized,
    InvalidImplementation,
    InvalidBirthSignature,
    ReentrantCall,
    Initialized
} from "./GlauxStorage.sol";
import {SignatureVerify} from "./lib/SignatureVerify.sol";
import {ImplementationCheck} from "./lib/ImplementationCheck.sol";

/// @notice Immutable EIP-7702 delegation target. Frozen forever: keep minimal.
contract GlauxDelegate {
    /// @dev Guards the window in which the untrusted initializer runs. The pointer
    ///      is only written after the delegatecall returns, so without this flag a
    ///      re-entrant `initialize` would still see an unset pointer and could
    ///      splice two independently signed birth blobs — taking the implementation
    ///      from one and the factor configuration from the other. The shipped
    ///      implementation happens to prevent that by setting `initialized` before
    ///      returning, but that is a convention of replaceable code and this
    ///      contract is permanent.
    bool private transient initializing;

    /// @notice One-time initialization, authenticated by the birth key.
    /// @dev The birth key IS address(this) (EIP-7702 EOA). The digest contains
    ///      no chain-id: the same signed blob replays on every chain. Submitting
    ///      is permissionless; forging is impossible without the birth key.
    /// @dev Slither reports `reentrancy-no-eth` because state is written after the
    ///      delegatecall. That state IS the reentrancy guard being released; the
    ///      flag is set before the call and any re-entry reverts `ReentrantCall()`.
    // slither-disable-next-line reentrancy-no-eth
    function initialize(
        address implementation,
        bytes32 expectedCodeHash,
        bytes calldata initData,
        bytes calldata birthSig
    ) external {
        if (initializing) revert ReentrantCall();
        initializing = true;

        bytes32 slot = GlauxStorage.IMPL_SLOT;
        address current;
        assembly {
            current := sload(slot)
        }
        if (current != address(0)) revert AlreadyInitialized();

        bytes32 digest = keccak256(
            abi.encode(
                GlauxStorage.INIT_DOMAIN, implementation, expectedCodeHash, keccak256(initData)
            )
        );
        if (!SignatureVerify.verify(
                GlauxStorage.VERIFIER_SECP256K1, abi.encode(address(this)), digest, birthSig
            )) revert InvalidBirthSignature();

        if (!ImplementationCheck.isInstallable(implementation, expectedCodeHash)) {
            revert InvalidImplementation();
        }

        // Delegatecall to a signed target is what a proxy IS. The function id is a
        // hardcoded literal, not input; the target is bound by the birth signature
        // and by the code-hash and marker checks immediately above.
        // slither-disable-next-line controlled-delegatecall
        (bool ok, bytes memory ret) = implementation.delegatecall(
            abi.encodeWithSignature("initializeAccount(bytes)", initData)
        );
        if (!ok) {
            assembly {
                revert(add(ret, 0x20), mload(ret))
            }
        }
        if (!GlauxStorage.layout().initialized) revert NotInitialized();
        bytes32 mirror = GlauxStorage.ERC1967_IMPL_SLOT;
        assembly {
            sstore(slot, implementation)
            // Mirror for explorer tooling. Never read back: see IMPL_SLOT.
            sstore(mirror, implementation)
        }
        initializing = false;
        emit Initialized(implementation);
    }

    fallback() external payable {
        bytes32 slot = GlauxStorage.IMPL_SLOT;
        assembly {
            let impl := sload(slot)
            if iszero(impl) {
                mstore(0x00, 0x87138d5c)
                revert(0x1c, 0x04)
            }
            calldatacopy(0, 0, calldatasize())
            let ok := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch ok
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    receive() external payable {}
}
