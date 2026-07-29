// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {GlauxFixture} from "./GlauxFixture.sol";
import {Counter} from "./Execute.t.sol";
import {GlauxDelegate} from "../src/GlauxDelegate.sol";
import {GlauxAccount} from "../src/GlauxAccount.sol";
import {
    GlauxStorage,
    FactorSlot,
    SlotSig,
    Call,
    Update,
    P256VerifierUnavailable,
    ProbeKeyNotInstallable
} from "../src/GlauxStorage.sol";
import {SignatureVerify} from "../src/lib/SignatureVerify.sol";

/// @notice Answers "valid" to every input. Stands in for whatever else a chain may
///         one day put at 0x100 — a different precompile, a genesis allocation, a
///         fork that reuses the address. A verifier that never says no would let any
///         P-256 signature pass, so a probe that only asks "does something answer
///         here?" is not enough.
contract P256AlwaysAcceptVerifier {
    fallback() external {
        assembly {
            mstore(0, 1)
            return(0, 32)
        }
    }
}

/// @notice Answers the probe's two questions correctly and "valid" to everything else.
///         This is the shape no known-answer test can catch, and the reason the threat
///         model says the probe stops accidents rather than a hostile chain: a fresh
///         challenge cannot be verified on chain without the very verifier under test,
///         so a known answer must be publicly known, and code can special-case it.
contract P256SelectiveVerifier {
    bytes32 private immutable NEGATIVE_ARM;

    constructor(bytes32 negativeArm) {
        NEGATIVE_ARM = negativeArm;
    }

    fallback() external {
        uint256 answer = keccak256(msg.data) == NEGATIVE_ARM ? 0 : 1;
        assembly {
            mstore(0, answer)
            return(0, 32)
        }
    }
}

/// @notice Answers "invalid" to every input, the way an address with unrelated code
///         plausibly would.
contract P256AlwaysRejectVerifier {
    fallback() external {
        assembly {
            mstore(0, 0)
            return(0, 32)
        }
    }
}

/// @notice A P-256 slot is inert on a chain whose P-256 verifier is missing or
///         broken: nothing that slot signs can ever be verified. An account born
///         with two such slots cannot reach its own 2-of-3 threshold — it is born
///         dead, with no factor able to rescue it. Installing a P-256 slot must
///         therefore probe the verifier first and refuse, at birth and at rotation
///         alike.
contract P256ProbeTest is GlauxFixture {
    bytes4 internal immutable UNAVAILABLE = P256VerifierUnavailable.selector;
    bytes4 internal immutable PROBE_KEY_REFUSED = ProbeKeyNotInstallable.selector;

    /// @dev The two seed strings the probe vector in `SignatureVerify` is derived
    ///      from. Re-deriving here is the provenance check: the constants shipped in
    ///      production code are not numbers anyone has to take on faith.
    uint256 internal constant PROBE_PK = uint256(keccak256("glaux.p256.probe.v1"));

    uint256 internal constant SECOND_DEVICE_P256_PK =
        0x3f1e2d4c5b6a798897a6b5c4d3e2f10123456789abcdef0123456789abcdef01;
    uint256 internal constant THIRD_SECP256K1_PK = 0xD3E71CE;
    uint256 internal constant NEW_CLOUD_PK = 0xC10D2;

    function _removeP256Verifier() internal {
        vm.etch(address(0x100), hex"");
    }

    /// @notice The reference configuration with the device factor moved off P-256, so
    ///         no slot depends on the verifier.
    function _secp256k1OnlySlots() internal view returns (FactorSlot[3] memory slots) {
        slots[0] = FactorSlot(GlauxStorage.VERIFIER_SECP256K1, abi.encode(vm.addr(paperPk)));
        slots[1] =
            FactorSlot(GlauxStorage.VERIFIER_SECP256K1, abi.encode(vm.addr(THIRD_SECP256K1_PK)));
        slots[2] = FactorSlot(GlauxStorage.VERIFIER_SECP256K1, abi.encode(vm.addr(cloudPk)));
    }

    function _birthWith(FactorSlot[3] memory slots, uint256[3] memory keys) internal {
        vm.signAndAttachDelegation(address(router), birthPk);
        bytes memory initData = _initDataFor(slots, keys);
        bytes32 digest = _initDigest(address(impl), address(impl).codehash, initData);
        GlauxDelegate(payable(account))
            .initialize(address(impl), address(impl).codehash, initData, _sig65(birthPk, digest));
    }

    function test_birth_withP256Slot_revertsWhenVerifierAbsent() public {
        _removeP256Verifier();
        vm.signAndAttachDelegation(address(router), birthPk);
        (bytes memory initData, bytes memory sig) = _initBlob();

        vm.expectRevert(UNAVAILABLE);
        GlauxDelegate(payable(account))
            .initialize(address(impl), address(impl).codehash, initData, sig);
    }

    /// @dev The dangerous shape the roadmap names: two P-256 slots against one
    ///      secp256k1 slot. Without the verifier the account could never assemble two
    ///      valid signatures, so birth must not complete.
    function test_birth_withTwoP256Slots_revertsWhenVerifierAbsent() public {
        _removeP256Verifier();
        (uint256 qx, uint256 qy) = vm.publicKeyP256(SECOND_DEVICE_P256_PK);
        FactorSlot[3] memory slots = _slots();
        slots[2] = FactorSlot(GlauxStorage.VERIFIER_P256, abi.encode(qx, qy));
        vm.signAndAttachDelegation(address(router), birthPk);
        bytes memory initData =
            _initDataFor(slots, [paperPk, DEVICE_P256_PK, SECOND_DEVICE_P256_PK]);
        bytes32 digest = _initDigest(address(impl), address(impl).codehash, initData);

        vm.expectRevert(UNAVAILABLE);
        GlauxDelegate(payable(account))
            .initialize(address(impl), address(impl).codehash, initData, _sig65(birthPk, digest));
    }

    function test_birth_withP256Slot_revertsWhenVerifierAlwaysAccepts() public {
        vm.etch(address(0x100), address(new P256AlwaysAcceptVerifier()).code);
        vm.signAndAttachDelegation(address(router), birthPk);
        (bytes memory initData, bytes memory sig) = _initBlob();

        vm.expectRevert(UNAVAILABLE);
        GlauxDelegate(payable(account))
            .initialize(address(impl), address(impl).codehash, initData, sig);
    }

    function test_birth_withP256Slot_revertsWhenVerifierAlwaysRejects() public {
        vm.etch(address(0x100), address(new P256AlwaysRejectVerifier()).code);
        vm.signAndAttachDelegation(address(router), birthPk);
        (bytes memory initData, bytes memory sig) = _initBlob();

        vm.expectRevert(UNAVAILABLE);
        GlauxDelegate(payable(account))
            .initialize(address(impl), address(impl).codehash, initData, sig);
    }

    /// @dev Guard against probing unconditionally: an account with no P-256 slot has
    ///      no reason to care whether the chain verifies P-256.
    function test_birth_withoutP256Slots_succeedsWhenVerifierAbsent() public {
        _removeP256Verifier();
        _birthWith(_secp256k1OnlySlots(), [paperPk, THIRD_SECP256K1_PK, cloudPk]);

        (uint8 verifierType, bytes memory data) = GlauxAccount(payable(account)).getSlot(1);
        assertEq(verifierType, GlauxStorage.VERIFIER_SECP256K1);
        assertEq(abi.decode(data, (address)), vm.addr(THIRD_SECP256K1_PK));
    }

    function test_setSlot_toP256_revertsWhenVerifierAbsent() public {
        _birthAccount();
        _removeP256Verifier();
        Update memory u = Update(1, 0, _setSlotPayloadP256(1, SECOND_DEVICE_P256_PK));

        vm.expectRevert(UNAVAILABLE);
        GlauxAccount(payable(account)).applyUpdate(u, _twoSigs(_updateDigest(u)));
    }

    /// @dev The rescue path must stay open: an account that already carries a P-256
    ///      slot on a chain without the verifier is rotating AWAY from it, and the
    ///      two secp256k1 factors it still has are enough to authorize that.
    function test_setSlot_awayFromP256_succeedsWhenVerifierAbsent() public {
        _birthAccount();
        _removeP256Verifier();
        Update memory u = Update(1, 0, _setSlotPayload(1, NEW_CLOUD_PK));

        GlauxAccount(payable(account)).applyUpdate(u, _twoSigs(_updateDigest(u)));

        (uint8 verifierType, bytes memory data) = GlauxAccount(payable(account)).getSlot(1);
        assertEq(verifierType, GlauxStorage.VERIFIER_SECP256K1);
        assertEq(abi.decode(data, (address)), vm.addr(NEW_CLOUD_PK));
    }

    function test_birth_withP256Slot_succeedsWhenVerifierWorks() public {
        _birthAccount();

        (uint8 verifierType,) = GlauxAccount(payable(account)).getSlot(1);
        assertEq(verifierType, GlauxStorage.VERIFIER_P256);
    }

    /// @dev The probe vector's private key is published — it has to be, a
    ///      known-answer test needs a known answer. So the one thing that key must
    ///      never be is a factor: anyone could sign for it, including the possession
    ///      proof, and a client that lifted the constants out of the library would be
    ///      handing a slot to the whole world.
    function test_birth_withProbeKeyAsFactor_reverts() public {
        (uint256 qx, uint256 qy) = vm.publicKeyP256(PROBE_PK);
        FactorSlot[3] memory slots = _slots();
        slots[1] = FactorSlot(GlauxStorage.VERIFIER_P256, abi.encode(qx, qy));
        vm.signAndAttachDelegation(address(router), birthPk);
        bytes memory initData = _initDataFor(slots, [paperPk, PROBE_PK, cloudPk]);
        bytes32 digest = _initDigest(address(impl), address(impl).codehash, initData);

        vm.expectRevert(PROBE_KEY_REFUSED);
        GlauxDelegate(payable(account))
            .initialize(address(impl), address(impl).codehash, initData, _sig65(birthPk, digest));
    }

    function test_setSlot_toProbeKey_reverts() public {
        _birthAccount();
        Update memory u = Update(1, 0, _setSlotPayloadP256(1, PROBE_PK));

        vm.expectRevert(PROBE_KEY_REFUSED);
        GlauxAccount(payable(account)).applyUpdate(u, _twoSigs(_updateDigest(u)));
    }

    function test_probeVector_isDerivedFromItsSeeds() public pure {
        (uint256 qx, uint256 qy) = vm.publicKeyP256(PROBE_PK);
        assertEq(qx, SignatureVerify.PROBE_QX);
        assertEq(qy, SignatureVerify.PROBE_QY);
        assertEq(SignatureVerify.PROBE_DIGEST, keccak256("GLAUX_P256_PROBE_V1"));
    }

    /// @dev What the probe asserts about the chain is only as good as its vector: a
    ///      mistyped digit would make every chain look broken (positive arm fails) or
    ///      every chain look fine (negative arm passes for the wrong reason). Both arms
    ///      are pinned here against the vendored daimo verifier, which is an
    ///      implementation independent of the one that produced the vector.
    function test_probeVector_verifiesUnderTheRealVerifier() public view {
        assertTrue(_rawVerify(SignatureVerify.PROBE_DIGEST));
        assertFalse(_rawVerify(SignatureVerify.PROBE_DIGEST ^ bytes32(uint256(1))));
    }

    /// @notice The probe's boundary, pinned so nobody mistakes it for a stronger
    ///         guarantee than it is: a verifier that answers the two probe questions
    ///         honestly and says "valid" to everything else passes, the slot installs,
    ///         and the P-256 factor is then forgeable by anyone — here a signature of
    ///         `(1, 2)` completes the quorum and moves the account.
    /// @dev This is not a defect the probe should close and cannot be closed by a
    ///      better vector; see docs/threat-model.md residual 8. A chain whose verifier
    ///      is adversarial owns every P-256 check the account makes, at signing time as
    ///      much as at installation. The test exists so the claim stays honest and so a
    ///      future change that pretends otherwise fails here.
    function test_selectiveVerifier_defeatsTheProbe_documentedLimitation() public {
        bytes32 negativeArm = keccak256(
            abi.encodePacked(
                SignatureVerify.PROBE_DIGEST ^ bytes32(uint256(1)),
                SignatureVerify.PROBE_R,
                SignatureVerify.PROBE_S,
                SignatureVerify.PROBE_QX,
                SignatureVerify.PROBE_QY
            )
        );
        vm.etch(address(0x100), address(new P256SelectiveVerifier(negativeArm)).code);

        // The probe is satisfied and the P-256 slot installs.
        _birthAccount();
        (uint8 verifierType,) = GlauxAccount(payable(account)).getSlot(1);
        assertEq(verifierType, GlauxStorage.VERIFIER_P256);

        // And the installed factor signs for anyone: no P-256 key involved.
        Counter counter = new Counter();
        Call[] memory calls = new Call[](1);
        calls[0] = Call(address(counter), 0, abi.encodeWithSignature("bump()"));
        bytes32 digest = _execDigest(calls);
        SlotSig[2] memory sigs;
        sigs[0] = SlotSig(0, _sig65(paperPk, digest));
        sigs[1] = SlotSig(1, abi.encode(uint256(1), uint256(2)));

        GlauxAccount(payable(account)).executeWithSigs(calls, FAR_FUTURE, sigs);

        assertEq(counter.n(), 1);
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
