// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import "forge-std/Test.sol";
import {SignatureVerify} from "../src/lib/SignatureVerify.sol";

/// @notice The probe, asked of real chains instead of a stand-in.
/// @dev Every other test that exercises `p256VerifierAvailable` runs against the
///      vendored daimo verifier etched at `0x100`. That answers whether the probe
///      recognises a correct P-256 implementation; it cannot answer whether the
///      chains Glaux actually targets ship one, which is a fact about those chains
///      and changes when they fork. Sepolia gained `P256VERIFY` with Fusaka
///      (EIP-7951, 2025-10-14) and Base Sepolia with Fjord (RIP-7212) — this test is
///      how that claim stays checked rather than remembered.
///
///      Skipped unless the RPC is configured, so the default suite and CI stay
///      offline and deterministic. To run it:
///
///      ```
///      GLAUX_RPC_SEPOLIA=https://ethereum-sepolia-rpc.publicnode.com \
///      GLAUX_RPC_BASE_SEPOLIA=https://base-sepolia-rpc.publicnode.com \
///        forge test --match-contract P256ForkProbe --evm-version osaka -vv
///      ```
///
///      `--evm-version osaka` is required and is not a detail. A fork supplies the
///      chain's STATE, while the calls still execute in the local EVM at the
///      configured spec — and this repo builds for `prague`, which predates
///      EIP-7951, so `0x100` is not a precompile there and every chain looks broken.
///      Without the flag this test fails against perfectly healthy chains.
///
///      The flag does not reach the compiler, and that is why it is safe to pass.
///      `foundry.toml` pins `src`/`script` to solc 0.8.28, which has no `osaka`
///      target, so Foundry clamps the compiler input to `prague` and raises only the
///      executor spec — verified by reading the solc standard-json, which is not
///      emitted by default: `forge build --evm-version osaka --build-info --force`,
///      then `input.settings.evmVersion` in `out/build-info/*.json` (2026-07-29:
///      `prague` under both invocations).
///      The addresses and the implementation code hash are therefore byte-identical
///      with and without it, and nothing a birth blob commits to moves.
///
///      That guarantee is tied to the pinned compiler. Should `src` ever move to
///      solc >= 0.8.29, `osaka` would reach the compiler for real and could change
///      the emitted bytecode — which would move the CREATE2 addresses and the signed
///      code hash. At that point this test needs its own compilation profile rather
///      than a global flag. `prague` stays the build target regardless: the deployed
///      bytecode must run on chains that have not forked to Osaka.
///
///      Read-only: it calls the precompile and nothing else, so it needs no funded
///      key and no deployment. A failure here means the target chain cannot host a
///      P-256 factor — birth carrying one will revert `P256VerifierUnavailable`,
///      by design and before any funds move.
contract P256ForkProbeTest is Test {
    function test_sepolia_verifiesP256() public {
        _assertChainVerifiesP256("GLAUX_RPC_SEPOLIA", 11_155_111);
    }

    function test_baseSepolia_verifiesP256() public {
        _assertChainVerifiesP256("GLAUX_RPC_BASE_SEPOLIA", 84_532);
    }

    function _assertChainVerifiesP256(string memory rpcVar, uint256 expectedChainId) internal {
        string memory rpc = vm.envOr(rpcVar, string(""));
        if (bytes(rpc).length == 0) {
            // Skipping keeps CI offline, but a skipped test is still a passing
            // `forge test`, and this suite is meant to be run as a pre-flight before
            // a broadcast — where "green" would read as "both chains verified" when
            // nothing was checked at all. Set GLAUX_REQUIRE_FORK_CHECKS to make the
            // absence of an endpoint a failure instead, and use it in that runbook.
            if (vm.envOr("GLAUX_REQUIRE_FORK_CHECKS", false)) {
                revert(string.concat(rpcVar, " is unset: this chain was not verified"));
            }
            vm.skip(true);
            return;
        }

        vm.createSelectFork(rpc);
        assertEq(block.chainid, expectedChainId, "RPC points at a different chain");

        // Both arms separately, so a failure names which half of the probe broke:
        // a chain with no verifier fails the first, one that answers "valid" to
        // everything fails the second. The first arm also fails when the local EVM
        // spec predates EIP-7951, which is indistinguishable from here and is by far
        // the likelier cause — hence the reminder in the message.
        assertTrue(
            _rawVerify(SignatureVerify.PROBE_DIGEST),
            "valid signature not accepted: chain lacks P256VERIFY, or run with --evm-version osaka"
        );
        assertFalse(
            _rawVerify(SignatureVerify.PROBE_DIGEST ^ bytes32(uint256(1))),
            "signature accepted for the wrong message"
        );

        assertTrue(SignatureVerify.p256VerifierAvailable(), "probe refuses this chain");
    }

    function _rawVerify(bytes32 digest) internal view returns (bool) {
        (bool ok, bytes memory out) = address(0x100)
            .staticcall(
                abi.encodePacked(
                    digest,
                    SignatureVerify.PROBE_R,
                    SignatureVerify.PROBE_S,
                    SignatureVerify.PROBE_QX,
                    SignatureVerify.PROBE_QY
                )
            );
        return ok && out.length == 32 && abi.decode(out, (uint256)) == 1;
    }
}
