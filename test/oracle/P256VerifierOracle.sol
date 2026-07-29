// SPDX-License-Identifier: MIT
pragma solidity 0.8.21;

import {P256Verifier} from "p256-verifier/P256Verifier.sol";

/// @dev Exists only to pull the vendored daimo P256Verifier into the build as its
/// own compilation unit. Upstream pins solc 0.8.21 and needs via_ir, while Glaux is
/// on 0.8.28 without via_ir; a direct import from the test suite would force one
/// version on both. Tests etch the artifact with vm.getDeployedCode instead.
contract P256VerifierOracle is P256Verifier {}
