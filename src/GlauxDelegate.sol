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
    /// @notice One-time initialization, authenticated by the birth key.
    /// @dev The birth key IS address(this) (EIP-7702 EOA). The digest contains
    ///      no chain-id: the same signed blob replays on every chain. Submitting
    ///      is permissionless; forging is impossible without the birth key.
    function initialize(
        address implementation,
        bytes32 expectedCodeHash,
        bytes calldata initData,
        bytes calldata birthSig
    ) external {
        // Guards the window in which the untrusted initializer runs. The pointer is
        // only written after the delegatecall returns, so without this a re-entrant
        // `initialize` would still see an unset pointer and could splice two
        // independently signed birth blobs — implementation from one, factor
        // configuration from the other. The shipped implementation happens to prevent
        // that by setting `initialized` before returning, but that is a convention of
        // replaceable code and this contract is permanent.
        //
        // Held in a NAMESPACED transient slot: Solidity would place a `transient`
        // state variable at transient slot 0, which the implementation's own first
        // transient variable also occupies, since both run with `address(this)` set
        // to the account. The router must not squat a slot it does not own.
        bytes32 guard = GlauxStorage.DELEGATE_BIRTH_GUARD_SLOT;
        uint256 busy;
        assembly {
            busy := tload(guard)
        }
        if (busy != 0) revert ReentrantCall();
        assembly {
            tstore(guard, 1)
        }

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
        assembly {
            sstore(slot, implementation)
            tstore(guard, 0)
        }
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
