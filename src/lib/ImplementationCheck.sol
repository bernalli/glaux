// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {GlauxStorage} from "../GlauxStorage.sol";

/// @notice The single definition of "may this code be installed as the account's
///         implementation", shared by the birth path in the immutable router and
///         by the SetImplementation update action. Both must accept exactly the
///         same set of implementations: birth and upgrade install code the same
///         way, so any divergence between them would be a hole in whichever check
///         is weaker.
library ImplementationCheck {
    /// @return True when `implementation` holds real deployed code whose runtime
    ///         hash is exactly `expectedCodeHash` and which identifies itself as a
    ///         Glaux account by answering `glauxCompatibilityId()` with
    ///         `GlauxStorage.COMPAT_ID`.
    /// @dev Three properties this deliberately enforces:
    ///
    ///      1. The code hash is bound because one blob replays on every chain,
    ///         and the same ADDRESS does not hold the same CODE everywhere.
    ///
    ///      2. EIP-7702 delegation designators are rejected. EIP-3541 forbids
    ///         deploying code that begins with 0xEF, so a leading 0xEF byte can
    ///         only be a designator — and for one of those, EXTCODEHASH hashes the
    ///         23-byte designator while DELEGATECALL executes the delegation
    ///         TARGET's code. Binding the hash would then bind nothing: the
    ///         identical designator can point at an address holding different code
    ///         on a different chain, which is the very substitution the hash exists
    ///         to prevent.
    ///
    ///      3. The marker staticcall writes into a fixed 32-byte window, so a
    ///         candidate returning enormous returndata cannot be materialised into
    ///         memory. The call fails as a clean rejection instead of exhausting
    ///         the gas of the transaction that carries it.
    ///
    ///      The marker is self-attestation: it stops accidents and incompatible
    ///      logic, never an adversary who already holds two factors and therefore
    ///      owns the account by definition.
    function isInstallable(address implementation, bytes32 expectedCodeHash)
        internal
        view
        returns (bool)
    {
        if (implementation.code.length == 0 || implementation.codehash != expectedCodeHash) {
            return false;
        }

        bytes4 selector = bytes4(keccak256("glauxCompatibilityId()"));
        bytes32 compatId = GlauxStorage.COMPAT_ID;
        bool ok;
        assembly {
            extcodecopy(implementation, 0x00, 0, 1)
            ok := iszero(eq(byte(0, mload(0x00)), 0xEF))
            if ok {
                mstore(0x00, selector)
                let called := staticcall(gas(), implementation, 0x00, 0x04, 0x20, 0x20)
                ok := and(called, and(eq(returndatasize(), 32), eq(mload(0x20), compatId)))
            }
        }
        return ok;
    }
}
