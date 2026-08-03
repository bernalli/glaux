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
    InvalidSignature,
    AlreadyInitialized,
    NotInitialized,
    NotDuringBirth,
    InvalidImplementation,
    InvalidBirthSignature,
    DuplicateSlot,
    InvalidSlot,
    PossessionNotProven,
    InvalidVerifierType
} from "../src/GlauxStorage.sol";

contract NonInitializingAccount {
    function initializeAccount(bytes calldata) external {}
}

/// @notice Stands in for the logic of a wallet the account was delegated to BEFORE
///         moving to Glaux — any ordinary ERC-1967 proxy-pattern implementation
///         whose address is still sitting in the shared slot.
contract ForeignProxyLogic {
    function foreignSweep() external pure returns (bool) {
        return true;
    }
}

/// @notice An implementation that declares its own `transient` variable, which Solidity
///         places at transient slot 0 — the same slot a router guard would occupy,
///         since both run with `address(this)` set to the account. It refuses to
///         initialize if it observes that slot already set, so a colliding router
///         guard turns into a failed birth rather than a silent misread.
contract TransientProbeAccount {
    bool private transient ownFlag;

    function glauxCompatibilityId() external pure returns (bytes32) {
        return GlauxStorage.COMPAT_ID;
    }

    function initializeAccount(bytes calldata) external {
        require(!ownFlag, "router leaked its guard into the implementation's transient slot 0");
        GlauxStorage.layout().initialized = true;
    }
}

contract MarkerWithoutInitialization {
    function glauxCompatibilityId() external pure returns (bytes32) {
        return GlauxStorage.COMPAT_ID;
    }

    function initializeAccount(bytes calldata) external {}
}

contract BirthTest is GlauxFixture {
    function test_birth_initializes() public {
        _birthAccount();

        (uint8 vType, bytes memory data) = GlauxAccount(payable(account)).getSlot(0);
        assertEq(vType, GlauxStorage.VERIFIER_SECP256K1);
        assertEq(abi.decode(data, (address)), vm.addr(paperPk));
        assertEq(GlauxAccount(payable(account)).updateNonce(), 0);
        assertEq(GlauxAccount(payable(account)).execNonce(), 0);
        assertEq(GlauxAccount(payable(account)).ENTRYPOINT(), address(ep));
    }

    function test_birth_preservesSlotOrdering() public {
        _birthAccount();

        (uint8 paperType, bytes memory paperData) = GlauxAccount(payable(account)).getSlot(0);
        (uint8 deviceType, bytes memory deviceData) = GlauxAccount(payable(account)).getSlot(1);
        (uint8 cloudType, bytes memory cloudData) = GlauxAccount(payable(account)).getSlot(2);

        assertEq(paperType, GlauxStorage.VERIFIER_SECP256K1);
        assertEq(abi.decode(paperData, (address)), vm.addr(paperPk));
        assertEq(deviceType, GlauxStorage.VERIFIER_P256);
        (uint256 qx, uint256 qy) = abi.decode(deviceData, (uint256, uint256));
        assertEq(qx, DEVICE_QX);
        assertEq(qy, DEVICE_QY);
        assertEq(cloudType, GlauxStorage.VERIFIER_SECP256K1);
        assertEq(abi.decode(cloudData, (address)), vm.addr(cloudPk));
    }

    function test_birth_rejectsTwoSlotsWithIdenticalKey() public {
        vm.signAndAttachDelegation(address(router), birthPk);
        FactorSlot[3] memory duplicate = _slots();
        duplicate[2] = duplicate[0];
        bytes memory initData = _initDataFor(duplicate, [paperPk, DEVICE_P256_PK, paperPk]);
        bytes32 digest = _initDigest(address(impl), address(impl).codehash, initData);

        vm.expectRevert(DuplicateSlot.selector);
        GlauxDelegate(payable(account))
            .initialize(address(impl), address(impl).codehash, initData, _sig65(birthPk, digest));
    }

    function test_birth_rejectsAllSlotsWithIdenticalKey() public {
        vm.signAndAttachDelegation(address(router), birthPk);
        FactorSlot[3] memory duplicate = _slots();
        duplicate[1] = duplicate[0];
        duplicate[2] = duplicate[0];
        bytes memory initData = _initDataFor(duplicate, [paperPk, paperPk, paperPk]);
        bytes32 digest = _initDigest(address(impl), address(impl).codehash, initData);

        vm.expectRevert(DuplicateSlot.selector);
        GlauxDelegate(payable(account))
            .initialize(address(impl), address(impl).codehash, initData, _sig65(birthPk, digest));
    }

    function test_birth_withThreeDistinctKeysStillSucceeds() public {
        _birthAccount();

        (uint8 paperType, bytes memory paperData) = GlauxAccount(payable(account)).getSlot(0);
        (uint8 deviceType, bytes memory deviceData) = GlauxAccount(payable(account)).getSlot(1);
        (uint8 cloudType, bytes memory cloudData) = GlauxAccount(payable(account)).getSlot(2);
        assertFalse(paperType == deviceType && keccak256(paperData) == keccak256(deviceData));
        assertFalse(paperType == cloudType && keccak256(paperData) == keccak256(cloudData));
        assertFalse(deviceType == cloudType && keccak256(deviceData) == keccak256(cloudData));
    }

    function test_birth_anyoneCanSubmitSameBlob() public {
        vm.signAndAttachDelegation(address(router), birthPk);
        (bytes memory initData, bytes memory sig) = _initBlob();

        vm.prank(address(0xF20A7));
        GlauxDelegate(payable(account))
            .initialize(address(impl), address(impl).codehash, initData, sig);

        (uint8 vType,) = GlauxAccount(payable(account)).getSlot(1);
        assertEq(vType, GlauxStorage.VERIFIER_P256);
    }

    function test_birth_rejectsForgedBlob() public {
        vm.signAndAttachDelegation(address(router), birthPk);
        bytes memory initData = abi.encode(_slots(), _proofs());
        bytes32 digest = _initDigest(address(impl), address(impl).codehash, initData);

        vm.expectRevert(InvalidBirthSignature.selector);
        GlauxDelegate(payable(account))
            .initialize(address(impl), address(impl).codehash, initData, _sig65(0xE711, digest));
    }

    /// @notice An EIP-7702 delegated EOA reports the 23-byte delegation designator
    ///         as its code: EXTCODEHASH hashes the DESIGNATOR while DELEGATECALL
    ///         executes the TARGET's code. Binding the code hash would therefore
    ///         bind nothing — the identical designator can point at an address
    ///         holding different code on a different chain, which is precisely the
    ///         cross-chain substitution the binding exists to prevent.
    function test_birth_rejectsDelegatedEoaAsImplementation() public {
        uint256 decoyPk = 0xDEC0;
        address decoy = vm.addr(decoyPk);
        vm.signAndAttachDelegation(address(impl), decoyPk);

        // The decoy passes every other check the router performs: it has code,
        // that code hash is stable across chains, and the marker staticcall
        // resolves through the delegation to the real implementation.
        bytes memory decoyCode = decoy.code;
        assertEq(decoyCode.length, 23);
        assertEq(uint8(decoyCode[0]), 0xEF);
        assertEq(GlauxAccount(payable(decoy)).glauxCompatibilityId(), GlauxStorage.COMPAT_ID);

        vm.signAndAttachDelegation(address(router), birthPk);
        bytes memory initData = abi.encode(_slots(), _proofs());
        bytes32 digest = _initDigest(decoy, decoy.codehash, initData);

        vm.expectRevert(InvalidImplementation.selector);
        GlauxDelegate(payable(account))
            .initialize(decoy, decoy.codehash, initData, _sig65(birthPk, digest));
    }

    /// @notice Proves `expectedCodeHash` is cryptographically bound INTO the digest,
    ///         not merely compared at runtime: the blob is signed over a wrong hash
    ///         and submitted with the right one. Without the field in the digest
    ///         this would satisfy both the signature check and the hash comparison.
    function test_birth_rejectsSignatureBoundToADifferentCodeHash() public {
        vm.signAndAttachDelegation(address(router), birthPk);
        bytes memory initData = abi.encode(_slots(), _proofs());
        bytes32 digest = _initDigest(address(impl), bytes32(uint256(0xBAD)), initData);

        vm.expectRevert(InvalidBirthSignature.selector);
        GlauxDelegate(payable(account))
            .initialize(address(impl), address(impl).codehash, initData, _sig65(birthPk, digest));
    }

    /// @notice The threshold's real foundation: a slot's key must PROVE it exists.
    ///         ECDSA verifies by recovery, so for a digest known in advance an
    ///         adversary can choose a signature and derive the address it is valid
    ///         under — a well-formed slot whose private key never existed and which
    ///         only they can sign for. With two such slots they meet 2-of-3 alone,
    ///         holding no keys at all, while every slot looks distinct and
    ///         well-formed on chain and `DuplicateSlot()` never fires.
    ///
    ///         No signature-side check can catch this, because the forged signatures
    ///         are genuinely different from each other. It is closed at registration:
    ///         the challenge commits to the key material, so an address derived from
    ///         a chosen signature cannot satisfy the digest that commits to it.
    function test_birth_rejectsASlotWhoseKeyWasNeverPossessed() public {
        // Pick a signature first, then derive the address it is valid under — the
        // attacker never holds a private key for it.
        bytes32 anyDigest = keccak256("any digest at all");
        bytes32 r = bytes32(uint256(1));
        bytes32 s = bytes32(uint256(2));
        address forged = ecrecover(anyDigest, 27, r, s);
        assertTrue(forged != address(0));

        FactorSlot[3] memory slots = _slots();
        slots[2] = FactorSlot(GlauxStorage.VERIFIER_SECP256K1, abi.encode(forged));
        // Shape validation accepts it: a clean, non-zero, perfectly well-formed address.
        assertTrue(slots[2].data.length == 32);

        bytes[3] memory proofs;
        proofs[0] = _proofFor(0, slots[0], paperPk);
        proofs[1] = _proofFor(1, slots[1], DEVICE_P256_PK);
        // The best the attacker can offer for slot 2: the signature they started from.
        proofs[2] = abi.encodePacked(r, s, uint8(27));
        bytes memory initData = abi.encode(slots, proofs);

        vm.signAndAttachDelegation(address(router), birthPk);
        bytes32 digest = _initDigest(address(impl), address(impl).codehash, initData);

        vm.expectRevert(PossessionNotProven.selector);
        GlauxDelegate(payable(account))
            .initialize(address(impl), address(impl).codehash, initData, _sig65(birthPk, digest));
    }

    function test_birth_rejectsDifferentImplementationWithSameSignature() public {
        vm.signAndAttachDelegation(address(router), birthPk);
        (bytes memory initData, bytes memory sig) = _initBlob();
        GlauxAccount otherImpl = new GlauxAccount(address(0xE47));

        vm.expectRevert(InvalidBirthSignature.selector);
        GlauxDelegate(payable(account))
            .initialize(address(otherImpl), address(otherImpl).codehash, initData, sig);
    }

    function test_birth_rejectsMismatchedCodeHashForCompatibleImplementation() public {
        vm.signAndAttachDelegation(address(router), birthPk);
        bytes memory initData = abi.encode(_slots(), _proofs());
        bytes32 wrongCodeHash = bytes32(uint256(1));
        bytes32 digest = _initDigest(address(impl), wrongCodeHash, initData);

        vm.expectRevert(InvalidImplementation.selector);
        GlauxDelegate(payable(account))
            .initialize(address(impl), wrongCodeHash, initData, _sig65(birthPk, digest));
    }

    function test_birth_rejectsDifferentCompatibleCodeAtSignedHash() public {
        vm.signAndAttachDelegation(address(router), birthPk);
        GlauxAccount otherImpl = new GlauxAccount(address(0xE47));
        bytes memory initData = abi.encode(_slots(), _proofs());
        bytes32 signedCodeHash = address(impl).codehash;
        assertNotEq(address(otherImpl).codehash, signedCodeHash);
        bytes32 digest = _initDigest(address(otherImpl), signedCodeHash, initData);

        vm.expectRevert(InvalidImplementation.selector);
        GlauxDelegate(payable(account))
            .initialize(address(otherImpl), signedCodeHash, initData, _sig65(birthPk, digest));
    }

    function test_birth_rejectsImplementationWithoutCompatibilityMarker() public {
        vm.signAndAttachDelegation(address(router), birthPk);
        NonInitializingAccount noMarkerImplementation = new NonInitializingAccount();
        bytes memory initData = abi.encode(_slots(), _proofs());
        bytes32 codeHash = address(noMarkerImplementation).codehash;
        bytes32 digest = _initDigest(address(noMarkerImplementation), codeHash, initData);

        vm.expectRevert(InvalidImplementation.selector);
        GlauxDelegate(payable(account))
            .initialize(
                address(noMarkerImplementation), codeHash, initData, _sig65(birthPk, digest)
            );
    }

    function test_birthDigestRemainsChainAgnostic() public {
        vm.signAndAttachDelegation(address(router), birthPk);
        (bytes memory initData, bytes memory sig) = _initBlob();
        uint256 originalChainId = block.chainid;

        vm.chainId(originalChainId + 1);
        GlauxDelegate(payable(account))
            .initialize(address(impl), address(impl).codehash, initData, sig);
        vm.chainId(originalChainId);

        assertEq(GlauxAccount(payable(account)).updateNonce(), 0);
    }

    function test_birth_rejectsDifferentSlotsWithSameSignature() public {
        vm.signAndAttachDelegation(address(router), birthPk);
        (, bytes memory sig) = _initBlob();
        FactorSlot[3] memory changed = _slots();
        changed[0] = FactorSlot(GlauxStorage.VERIFIER_SECP256K1, abi.encode(address(0xBAD)));

        vm.expectRevert(InvalidBirthSignature.selector);
        GlauxDelegate(payable(account))
            .initialize(address(impl), address(impl).codehash, _initDataUnproven(changed), sig);
    }

    function test_birth_secondInitReverts() public {
        _birthAccount();
        (bytes memory initData, bytes memory sig) = _initBlob();

        vm.expectRevert(AlreadyInitialized.selector);
        GlauxDelegate(payable(account))
            .initialize(address(impl), address(impl).codehash, initData, sig);
    }

    function test_birth_noCodeImplementationRevertsAndOriginalBlobIsRetryable() public {
        vm.signAndAttachDelegation(address(router), birthPk);
        address futureImplementation = address(0xF00D);
        bytes memory initData = abi.encode(_slots(), _proofs());
        bytes32 expectedCodeHash = address(impl).codehash;
        bytes32 digest = _initDigest(futureImplementation, expectedCodeHash, initData);
        bytes memory sig = _sig65(birthPk, digest);

        vm.expectRevert(InvalidImplementation.selector);
        GlauxDelegate(payable(account))
            .initialize(futureImplementation, expectedCodeHash, initData, sig);

        assertEq(vm.load(account, GlauxStorage.IMPL_SLOT), bytes32(0));
        vm.expectRevert(NotInitialized.selector);
        GlauxAccount(payable(account)).updateNonce();

        vm.etch(futureImplementation, address(impl).code);
        GlauxDelegate(payable(account))
            .initialize(futureImplementation, expectedCodeHash, initData, sig);

        (uint8 vType,) = GlauxAccount(payable(account)).getSlot(0);
        assertEq(vType, GlauxStorage.VERIFIER_SECP256K1);
    }

    function test_birth_zeroImplementationReverts() public {
        vm.signAndAttachDelegation(address(router), birthPk);
        bytes memory initData = abi.encode(_slots(), _proofs());
        bytes32 digest = _initDigest(address(0), bytes32(0), initData);

        vm.expectRevert(InvalidImplementation.selector);
        GlauxDelegate(payable(account))
            .initialize(address(0), bytes32(0), initData, _sig65(birthPk, digest));
    }

    function test_birth_revertsWhenImplementationDoesNotSetInitialized() public {
        vm.signAndAttachDelegation(address(router), birthPk);
        MarkerWithoutInitialization nonInitializingImplementation =
            new MarkerWithoutInitialization();
        bytes memory initData = abi.encode(_slots(), _proofs());
        bytes32 digest = _initDigest(
            address(nonInitializingImplementation),
            address(nonInitializingImplementation).codehash,
            initData
        );

        vm.expectRevert(NotInitialized.selector);
        GlauxDelegate(payable(account))
            .initialize(
                address(nonInitializingImplementation),
                address(nonInitializingImplementation).codehash,
                initData,
                _sig65(birthPk, digest)
            );

        assertEq(vm.load(account, GlauxStorage.IMPL_SLOT), bytes32(0));
    }

    /// @notice H-1: an EOA whose EIP-7702 delegation points straight at the
    ///         implementation (skipping the router) never has the router's
    ///         `initialize` set `DELEGATE_BIRTH_GUARD_SLOT`, so it must not be able
    ///         to reach `initializeAccount` at all — even though, from fresh
    ///         storage, both `l.initialized == false` and `IMPL_SLOT == 0` look
    ///         exactly like an unborn Glaux account.
    function test_initializeAccountRevertsWhenNotDuringBirth() public {
        // EOA delegated straight to the implementation instead of the router.
        uint256 victimPk = 0xC0FFEE;
        address victim = vm.addr(victimPk);
        vm.signAndAttachDelegation(address(impl), victimPk);
        // Any initData at all — the guard fires before it is even decoded.
        vm.expectRevert(NotDuringBirth.selector);
        GlauxAccount(payable(victim)).initializeAccount(hex"");
    }

    function test_initializeAccountDirectlyOnImplementationReverts() public {
        vm.expectRevert(NotDuringBirth.selector);
        impl.initializeAccount(_initDataUnproven(_slots()));
    }

    function test_initializeAccountCannotBypassRouterBeforeBirth() public {
        vm.signAndAttachDelegation(address(router), birthPk);

        vm.expectRevert(NotInitialized.selector);
        GlauxAccount(payable(account)).initializeAccount(_initDataUnproven(_slots()));
    }

    function test_attackerCannotInitializeThroughAccountBeforeBirthWhenLogicExists() public {
        vm.signAndAttachDelegation(address(router), birthPk);
        FactorSlot[3] memory attackerSlots = _slots();
        attackerSlots[0] = FactorSlot(GlauxStorage.VERIFIER_SECP256K1, abi.encode(address(0xBAD)));

        vm.store(account, GlauxStorage.IMPL_SLOT, bytes32(uint256(uint160(address(impl)))));

        vm.prank(address(0xA77AC));
        vm.expectRevert(NotDuringBirth.selector);
        GlauxAccount(payable(account)).initializeAccount(_initDataUnproven(attackerSlots));
    }

    /// @notice An EIP-7702 re-delegation does NOT clear storage, so an EOA moving to
    ///         Glaux from any wallet built on the ordinary ERC-1967 proxy pattern
    ///         arrives with that shared slot already occupied. Glaux must not read a
    ///         slot it does not own: doing so would make birth revert
    ///         `AlreadyInitialized()` forever on that chain, with no birth key left
    ///         to retry and the funds unreachable.
    function test_birth_succeedsDespiteAForeignErc1967Pointer() public {
        vm.signAndAttachDelegation(address(router), birthPk);
        ForeignProxyLogic foreign = new ForeignProxyLogic();
        vm.store(
            account, GlauxStorage.ERC1967_IMPL_SLOT, bytes32(uint256(uint160(address(foreign))))
        );

        (bytes memory initData, bytes memory sig) = _initBlob();
        GlauxDelegate(payable(account))
            .initialize(address(impl), address(impl).codehash, initData, sig);

        assertEq(GlauxAccount(payable(account)).updateNonce(), 0);
        (uint8 vType,) = GlauxAccount(payable(account)).getSlot(1);
        assertEq(vType, GlauxStorage.VERIFIER_P256);
        assertEq(GlauxAccount(payable(account)).implementation(), address(impl));
        // And Glaux leaves the shared slot exactly as it found it. Writing it would
        // export this very hazard to whatever wallet the account is re-delegated to
        // next, which would read Glaux's implementation as its own.
        assertEq(
            address(uint160(uint256(vm.load(account, GlauxStorage.ERC1967_IMPL_SLOT)))),
            address(foreign)
        );
    }

    /// @notice The router's birth guard must not occupy transient slot 0. Solidity
    ///         assigns `transient` variables from slot 0 per contract, but the router
    ///         and the implementation both execute with `address(this)` set to the
    ///         account — so a plain `bool transient` in the router would be the same
    ///         location as the implementation's own first transient variable, and the
    ///         implementation would read the guard as its own state for the whole of
    ///         initialization. Namespacing the guard keeps the router out of a space
    ///         it does not own.
    function test_birth_guardDoesNotOccupyTheImplementationsTransientSlot() public {
        vm.signAndAttachDelegation(address(router), birthPk);
        TransientProbeAccount probe = new TransientProbeAccount();
        bytes memory initData = abi.encode(_slots(), _proofs());
        bytes32 digest = _initDigest(address(probe), address(probe).codehash, initData);

        GlauxDelegate(payable(account))
            .initialize(address(probe), address(probe).codehash, initData, _sig65(birthPk, digest));

        // Read the slot directly: the probe is a minimal mock without accessors.
        assertEq(
            address(uint160(uint256(vm.load(account, GlauxStorage.IMPL_SLOT)))), address(probe)
        );
    }

    /// @notice The router's fallback must never execute a pointer Glaux did not
    ///         write. Before birth there is no Glaux implementation, so a leftover
    ///         foreign one must be unreachable rather than delegatecalled with the
    ///         account's storage and balance.
    function test_foreignErc1967PointerIsNeverExecuted() public {
        vm.signAndAttachDelegation(address(router), birthPk);
        ForeignProxyLogic foreign = new ForeignProxyLogic();
        vm.store(
            account, GlauxStorage.ERC1967_IMPL_SLOT, bytes32(uint256(uint160(address(foreign))))
        );

        vm.expectRevert(NotInitialized.selector);
        ForeignProxyLogic(account).foreignSweep();
    }

    function test_initializeAccountDirectlyOnBornAccountReverts() public {
        _birthAccount();

        vm.expectRevert(NotDuringBirth.selector);
        GlauxAccount(payable(account)).initializeAccount(_initDataUnproven(_slots()));
    }

    function test_attackerCannotInitializeThroughAccountAfterBirth() public {
        _birthAccount();
        FactorSlot[3] memory attackerSlots = _slots();
        attackerSlots[0] = FactorSlot(GlauxStorage.VERIFIER_SECP256K1, abi.encode(address(0xBAD)));

        vm.prank(address(0xA77AC));
        vm.expectRevert(NotDuringBirth.selector);
        GlauxAccount(payable(account)).initializeAccount(_initDataUnproven(attackerSlots));

        (, bytes memory paperData) = GlauxAccount(payable(account)).getSlot(0);
        assertEq(abi.decode(paperData, (address)), vm.addr(paperPk));
    }

    function test_birth_rejectsInvalidSlotAndRollsBackImplementation() public {
        vm.signAndAttachDelegation(address(router), birthPk);
        FactorSlot[3] memory invalid = _slots();
        invalid[0] = FactorSlot(GlauxStorage.VERIFIER_SECP256K1, new bytes(31));
        bytes memory initData = _initDataUnproven(invalid);
        bytes32 digest = _initDigest(address(impl), address(impl).codehash, initData);

        vm.expectRevert(InvalidSlot.selector);
        GlauxDelegate(payable(account))
            .initialize(address(impl), address(impl).codehash, initData, _sig65(birthPk, digest));

        vm.expectRevert(NotInitialized.selector);
        GlauxAccount(payable(account)).updateNonce();
        (bytes memory validData, bytes memory validSig) = _initBlob();
        GlauxDelegate(payable(account))
            .initialize(address(impl), address(impl).codehash, validData, validSig);
    }

    function test_birth_rejectsOneMalformedSlot() public {
        vm.signAndAttachDelegation(address(router), birthPk);
        FactorSlot[3] memory invalid = _slots();
        invalid[0] = FactorSlot(GlauxStorage.VERIFIER_SECP256K1, abi.encode(address(0)));
        bytes memory initData = _initDataUnproven(invalid);
        bytes32 digest = _initDigest(address(impl), address(impl).codehash, initData);

        vm.expectRevert(InvalidSlot.selector);
        GlauxDelegate(payable(account))
            .initialize(address(impl), address(impl).codehash, initData, _sig65(birthPk, digest));
    }

    function test_birth_rejectsTwoMalformedSlots() public {
        vm.signAndAttachDelegation(address(router), birthPk);
        FactorSlot[3] memory invalid = _slots();
        invalid[0] = FactorSlot(GlauxStorage.VERIFIER_SECP256K1, abi.encode(address(0)));
        invalid[1] = FactorSlot(GlauxStorage.VERIFIER_P256, abi.encode(0, 0));
        bytes memory initData = _initDataUnproven(invalid);
        bytes32 digest = _initDigest(address(impl), address(impl).codehash, initData);

        vm.expectRevert(InvalidSlot.selector);
        GlauxDelegate(payable(account))
            .initialize(address(impl), address(impl).codehash, initData, _sig65(birthPk, digest));
    }

    function test_birth_rejectsInvalidVerifierType() public {
        vm.signAndAttachDelegation(address(router), birthPk);
        FactorSlot[3] memory invalid = _slots();
        invalid[1] = FactorSlot(0, abi.encode(DEVICE_QX, DEVICE_QY));
        // Slot 0 is valid and proven, so the run reaches slot 1 and fails on its
        // verifier type rather than on a missing proof.
        bytes memory initData = _initDataFor(invalid, [paperPk, DEVICE_P256_PK, cloudPk]);
        bytes32 digest = _initDigest(address(impl), address(impl).codehash, initData);

        vm.expectRevert(InvalidVerifierType.selector);
        GlauxDelegate(payable(account))
            .initialize(address(impl), address(impl).codehash, initData, _sig65(birthPk, digest));
    }

    function test_receive_beforeInit() public {
        vm.signAndAttachDelegation(address(router), birthPk);
        vm.deal(address(this), 1 ether);

        (bool ok,) = account.call{value: 0.5 ether}("");

        assertTrue(ok);
        assertEq(account.balance, 0.5 ether);
    }

    function test_fallback_beforeInit_reverts() public {
        vm.signAndAttachDelegation(address(router), birthPk);

        vm.expectRevert(NotInitialized.selector);
        GlauxAccount(payable(account)).updateNonce();
    }

    function test_fallbackSelectorLiteral_matchesNotInitialized() public pure {
        assertEq(bytes4(0x87138d5c), NotInitialized.selector);
    }

    function test_fallback_propagatesSuccessfulReturnData() public {
        _birthAccount();

        (bool ok, bytes memory ret) =
            account.staticcall(abi.encodeCall(GlauxAccount.updateNonce, ()));

        assertTrue(ok);
        assertEq(ret, abi.encode(uint64(0)));
    }

    function test_fallback_propagatesRevertData() public {
        _birthAccount();

        (bool ok, bytes memory ret) = account.call(abi.encodeCall(GlauxAccount.getSlot, (3)));

        assertFalse(ok);
        assertEq(ret, abi.encodeWithSelector(InvalidSlot.selector));
    }
}
