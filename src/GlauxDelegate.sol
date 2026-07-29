// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {
    GlauxStorage,
    AlreadyInitialized,
    InvalidBirthSignature,
    Initialized
} from "./GlauxStorage.sol";
import {SignatureVerify} from "./lib/SignatureVerify.sol";

/// @notice Immutable EIP-7702 delegation target. Frozen forever: keep minimal.
contract GlauxDelegate {
    /// @notice One-time initialization, authenticated by the birth key.
    /// @dev The birth key IS address(this) (EIP-7702 EOA). The digest contains
    ///      no chain-id: the same signed blob replays on every chain. Submitting
    ///      is permissionless; forging is impossible without the birth key.
    function initialize(address implementation, bytes calldata initData, bytes calldata birthSig)
        external
    {
        bytes32 slot = GlauxStorage.ERC1967_IMPL_SLOT;
        address current;
        assembly {
            current := sload(slot)
        }
        if (current != address(0)) revert AlreadyInitialized();

        bytes32 digest =
            keccak256(abi.encode(GlauxStorage.INIT_DOMAIN, implementation, keccak256(initData)));
        if (!SignatureVerify.verify(
                GlauxStorage.VERIFIER_SECP256K1, abi.encode(address(this)), digest, birthSig
            )) revert InvalidBirthSignature();

        assembly {
            sstore(slot, implementation)
        }
        (bool ok, bytes memory ret) = implementation.delegatecall(
            abi.encodeWithSignature("initializeAccount(bytes)", initData)
        );
        if (!ok) {
            assembly {
                revert(add(ret, 0x20), mload(ret))
            }
        }
        emit Initialized(implementation);
    }

    fallback() external payable {
        bytes32 slot = GlauxStorage.ERC1967_IMPL_SLOT;
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
