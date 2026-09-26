// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @notice The packed user operation defined by ERC-4337
///         (https://eips.ethereum.org/EIPS/eip-4337; the text of the standard is CC0).
/// @dev ABI-identical to the struct the EntryPoint passes to `validateUserOp`: same
///      fields, same types, same order. It is defined here so that `src/` does not
///      import GPL-licensed code.
struct PackedUserOperation {
    address sender;
    uint256 nonce;
    bytes initCode;
    bytes callData;
    bytes32 accountGasLimits;
    uint256 preVerificationGas;
    bytes32 gasFees;
    bytes paymasterAndData;
    bytes signature;
}
