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
    InvalidBirthProof,
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
    /**
     * @dev Which address a given `(initData, salt, s)` actually recovers to.
     *      Roughly half of all candidate `r` values are not curve
     *      x-coordinates, and `ecrecover` answers zero for those — so a
     *      mismatch test that only asserts a revert cannot tell whether it
     *      exercised the "recovered is zero" branch or the "recovered is
     *      someone else" branch. The tests below use this to say which.
     */
    function _recoveredFor(bytes memory initData, bytes32 salt, uint256 s)
        internal
        view
        returns (address)
    {
        bytes32 digest = _initDigest(address(impl), address(impl).codehash, initData);
        return
            ecrecover(router.AUTH_MSG_HASH(), 27, keccak256(abi.encode(digest, salt)), bytes32(s));
    }

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
        FactorSlot[3] memory duplicate = _slots();
        duplicate[2] = duplicate[0];
        bytes memory initData = _initDataFor(duplicate, [paperPk, DEVICE_P256_PK, paperPk]);
        (address bornAt, bytes32 salt, uint256 s) =
            _craftRootlessBirth(address(impl), address(impl).codehash, initData);
        _attachDelegation(bornAt, address(router));

        vm.expectRevert(DuplicateSlot.selector);
        GlauxDelegate(payable(bornAt))
            .initialize(address(impl), address(impl).codehash, initData, salt, s);
    }

    function test_birth_rejectsAllSlotsWithIdenticalKey() public {
        FactorSlot[3] memory duplicate = _slots();
        duplicate[1] = duplicate[0];
        duplicate[2] = duplicate[0];
        bytes memory initData = _initDataFor(duplicate, [paperPk, paperPk, paperPk]);
        (address bornAt, bytes32 salt, uint256 s) =
            _craftRootlessBirth(address(impl), address(impl).codehash, initData);
        _attachDelegation(bornAt, address(router));

        vm.expectRevert(DuplicateSlot.selector);
        GlauxDelegate(payable(bornAt))
            .initialize(address(impl), address(impl).codehash, initData, salt, s);
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
        _attachDelegation(account, address(router));

        vm.prank(address(0xF20A7));
        GlauxDelegate(payable(account))
            .initialize(address(impl), address(impl).codehash, _initBlob(), accountSalt, accountS);

        (uint8 vType,) = GlauxAccount(payable(account)).getSlot(1);
        assertEq(vType, GlauxStorage.VERIFIER_P256);
    }

    /// @notice Isolates the `s` tag from the recovery check, which is harder than
    ///         it looks: altering `s` normally moves the recovered address too,
    ///         so a naive "flip the tag" test is refused for the wrong reason and
    ///         stays green even with the tag check deleted. This test instead
    ///         takes an UNTAGGED `s`, asks which address it recovers to, and
    ///         gives THAT address the delegation — so recovery succeeds and the
    ///         tag is the only thing left to refuse it. Deleting the tag check
    ///         turns this test red; nothing else in the suite does.
    function test_birth_rejectsAnUntaggedSignatureThatWouldOtherwiseRecover() public {
        bytes memory initData = _initBlob();
        bytes32 digest = _initDigest(address(impl), address(impl).codehash, initData);
        bytes32 salt = keccak256(abi.encode(digest, uint256(0)));
        bytes32 r = keccak256(abi.encode(digest, salt));

        // An `s` a real signer could have produced: no router tag, still below
        // n/2. Search for one that recovers, the same way crafting does.
        uint256 untagged;
        address recovers;
        for (uint256 i = 0; i < 256 && recovers == address(0); i++) {
            untagged = uint256(keccak256(abi.encode("untagged", i))) >> 2;
            recovers = ecrecover(router.AUTH_MSG_HASH(), 27, r, bytes32(untagged));
        }
        assertTrue(recovers != address(0), "need an s that recovers at all");
        assertTrue(bytes13(bytes32(untagged)) != router.ROOTLESS_S_PREFIX());
        _attachDelegation(recovers, address(router));

        // Recovery would succeed here — `recovers` IS `address(this)`. Only the
        // missing tag stands between this call and a born account.
        vm.expectRevert(InvalidBirthProof.selector);
        GlauxDelegate(payable(recovers))
            .initialize(address(impl), address(impl).codehash, initData, salt, untagged);
    }

    /// @notice A salt that does not produce THIS account's `r` recovers to some
    ///         other address, so the router refuses it. This is what makes the
    ///         account address a commitment to its own birth configuration
    ///         rather than a label attached to one.
    function test_birth_rejectsAProofCraftedForAnotherSalt() public {
        bytes memory initData = _initBlob();
        (address bornAt, bytes32 salt, uint256 s) =
            _craftRootlessBirth(address(impl), address(impl).codehash, initData);
        _attachDelegation(bornAt, address(router));

        // Deliberately find a wrong salt that still RECOVERS: otherwise this
        // would pass through the "not a curve point" branch and say nothing
        // about whether the address comparison is enforced at all.
        bytes32 wrongSalt;
        address recovers;
        for (uint256 i = 1; i < 256 && recovers == address(0); i++) {
            wrongSalt = keccak256(abi.encode("wrong salt", i));
            recovers = _recoveredFor(initData, wrongSalt, s);
        }
        assertTrue(recovers != address(0) && recovers != bornAt, "need a live but foreign recovery");

        vm.expectRevert(InvalidBirthProof.selector);
        GlauxDelegate(payable(bornAt))
            .initialize(address(impl), address(impl).codehash, initData, wrongSalt, s);
    }

    /// @notice The splice the old birth signature also prevented: two complete,
    ///         individually valid births, submitted as one — A's proof with B's
    ///         factor configuration. `r` commits to `initData`, so the pair
    ///         recovers to neither account.
    function test_birth_rejectsSplicingTwoValidBirthConfigurations() public {
        bytes memory initDataA = _initBlob();
        FactorSlot[3] memory otherSlots = _slots();
        otherSlots[0] = FactorSlot(GlauxStorage.VERIFIER_SECP256K1, abi.encode(vm.addr(0xAB01)));
        bytes memory initDataB =
            _initDataFor(otherSlots, [uint256(0xAB01), DEVICE_P256_PK, cloudPk]);

        (address bornA, bytes32 saltA, uint256 sA) =
            _craftRootlessBirth(address(impl), address(impl).codehash, initDataA);
        (address bornB,,) = _craftRootlessBirth(address(impl), address(impl).codehash, initDataB);
        assertNotEq(bornA, bornB, "two configurations must not share an address");
        _attachDelegation(bornA, address(router));

        vm.expectRevert(InvalidBirthProof.selector);
        GlauxDelegate(payable(bornA))
            .initialize(address(impl), address(impl).codehash, initDataB, saltA, sA);
    }

    /// @notice A valid proof is valid for exactly one address. Presented on any
    ///         other delegated account it recovers to the address it was crafted
    ///         for, which is not `address(this)`.
    function test_birth_rejectsAProofBelongingToAnotherAccount() public {
        bytes memory initData = _initBlob();
        (, bytes32 salt, uint256 s) =
            _craftRootlessBirth(address(impl), address(impl).codehash, initData);
        address bystander = address(0xB157A9DE2);
        _attachDelegation(bystander, address(router));

        vm.expectRevert(InvalidBirthProof.selector);
        GlauxDelegate(payable(bystander))
            .initialize(address(impl), address(impl).codehash, initData, salt, s);
    }

    /// @notice Pins `AUTH_MSG_HASH` against a vector derived OUTSIDE this
    ///         codebase, which is the only way this constant can be checked at
    ///         all: every other test in the suite derives its account by
    ///         reading the router's own getter, so a wrong constant would agree
    ///         with itself and stay green while real chains recovered a
    ///         different authority from the same tuple — the account would
    ///         simply never be delegated, and only a live chain would say so.
    /// @dev The expected value was produced independently: a real EIP-7702
    ///      authorization for this router was signed with a known key, and the
    ///      signer recovered from exactly this hash, matching. The RLP is
    ///      `0x05 ‖ 0xd7 ‖ 0x80 ‖ 0x94 ‖ address ‖ 0x80` — list header for 23
    ///      bytes, zero chain id, the 20-byte address, zero nonce.
    function test_authorizationMessageHashMatchesAnIndependentlyDerivedVector() public view {
        // Deliberately not a deployed router: `AUTH_MSG_HASH` is an immutable
        // baked in at construction, so a copy etched elsewhere would still
        // carry the hash of the address it was built at. The vector stands on
        // the address alone.
        address fixedRouter = address(0xC0DE);
        bytes32 expected = 0x83e3c8fb81cf4fca1e62dd0804462fc9361d1c5ad72c73498d70959f85d66564;

        assertEq(
            keccak256(abi.encodePacked(hex"05d78094", fixedRouter, hex"80")),
            expected,
            "EIP-7702 authorization preimage for chainId 0, nonce 0"
        );
        // And the shape the router itself builds, for its own address.
        assertEq(
            router.AUTH_MSG_HASH(),
            keccak256(abi.encodePacked(hex"05d78094", address(router), hex"80"))
        );
    }

    /// @notice Every rootless `s` must satisfy EIP-2's low-`s` rule, which
    ///         EIP-7702 imposes on the authorization tuple: a tuple above n/2
    ///         is invalid at consensus, so an account derived from one could
    ///         never be delegated no matter what this contract accepts.
    function test_craftedSignatureIsAlwaysBelowHalfOrder() public view {
        uint256 halfOrder = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;
        // The tag fixes the top 13 bytes, so the largest representable `s` is
        // that tag followed by all ones — checked directly rather than sampled.
        uint256 largestPossible =
            uint256(bytes32(router.ROOTLESS_S_PREFIX())) | ((uint256(1) << 152) - 1);
        assertLt(largestPossible, halfOrder);
        assertLt(accountS, halfOrder);
    }

    /// @notice The address is a pure function of the birth configuration: same
    ///         factors, same implementation, same code hash, same account —
    ///         every time, on every chain, with nobody's key involved.
    function test_birth_derivationIsDeterministic() public view {
        bytes memory initData = _initBlob();
        (address first, bytes32 saltFirst, uint256 sFirst) =
            _craftRootlessBirth(address(impl), address(impl).codehash, initData);
        (address second, bytes32 saltSecond, uint256 sSecond) =
            _craftRootlessBirth(address(impl), address(impl).codehash, initData);

        assertEq(first, second);
        assertEq(saltFirst, saltSecond);
        assertEq(sFirst, sSecond);
        assertEq(first, account, "the fixture's account is that same derivation");
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

        bytes memory initData = abi.encode(_slots(), _proofs());
        (address bornAt, bytes32 salt, uint256 s) =
            _craftRootlessBirth(decoy, decoy.codehash, initData);
        _attachDelegation(bornAt, address(router));

        vm.expectRevert(InvalidImplementation.selector);
        GlauxDelegate(payable(bornAt)).initialize(decoy, decoy.codehash, initData, salt, s);
    }

    /// @notice Proves `expectedCodeHash` is cryptographically bound INTO the digest,
    ///         not merely compared at runtime: the blob is signed over a wrong hash
    ///         and submitted with the right one. Without the field in the digest
    ///         this would satisfy both the signature check and the hash comparison.
    function test_birth_rejectsSignatureBoundToADifferentCodeHash() public {
        bytes memory initData = abi.encode(_slots(), _proofs());
        (address bornAt, bytes32 salt, uint256 s) =
            _craftRootlessBirth(address(impl), bytes32(uint256(0xBAD)), initData);
        _attachDelegation(bornAt, address(router));

        vm.expectRevert(InvalidBirthProof.selector);
        GlauxDelegate(payable(bornAt))
            .initialize(address(impl), address(impl).codehash, initData, salt, s);
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
        bytes32 forgedR = bytes32(uint256(1));
        bytes32 forgedS = bytes32(uint256(2));
        address forged = ecrecover(anyDigest, 27, forgedR, forgedS);
        assertTrue(forged != address(0));

        FactorSlot[3] memory slots = _slots();
        slots[2] = FactorSlot(GlauxStorage.VERIFIER_SECP256K1, abi.encode(forged));
        // Shape validation accepts it: a clean, non-zero, perfectly well-formed address.
        assertTrue(slots[2].data.length == 32);

        bytes[3] memory proofs;
        proofs[0] = _proofFor(0, slots[0], paperPk);
        proofs[1] = _proofFor(1, slots[1], DEVICE_P256_PK);
        // The best the attacker can offer for slot 2: the signature they started from.
        proofs[2] = abi.encodePacked(forgedR, forgedS, uint8(27));
        bytes memory initData = abi.encode(slots, proofs);

        (address bornAt, bytes32 salt, uint256 s) =
            _craftRootlessBirth(address(impl), address(impl).codehash, initData);
        _attachDelegation(bornAt, address(router));

        vm.expectRevert(PossessionNotProven.selector);
        GlauxDelegate(payable(bornAt))
            .initialize(address(impl), address(impl).codehash, initData, salt, s);
    }

    function test_birth_rejectsDifferentImplementationWithSameProof() public {
        _attachDelegation(account, address(router));
        GlauxAccount otherImpl = new GlauxAccount(address(0xE47));

        vm.expectRevert(InvalidBirthProof.selector);
        GlauxDelegate(payable(account))
            .initialize(
                address(otherImpl), address(otherImpl).codehash, _initBlob(), accountSalt, accountS
            );
    }

    function test_birth_rejectsMismatchedCodeHashForCompatibleImplementation() public {
        bytes memory initData = abi.encode(_slots(), _proofs());
        bytes32 wrongCodeHash = bytes32(uint256(1));
        (address bornAt, bytes32 salt, uint256 s) =
            _craftRootlessBirth(address(impl), wrongCodeHash, initData);
        _attachDelegation(bornAt, address(router));

        vm.expectRevert(InvalidImplementation.selector);
        GlauxDelegate(payable(bornAt)).initialize(address(impl), wrongCodeHash, initData, salt, s);
    }

    function test_birth_rejectsDifferentCompatibleCodeAtSignedHash() public {
        GlauxAccount otherImpl = new GlauxAccount(address(0xE47));
        bytes memory initData = abi.encode(_slots(), _proofs());
        bytes32 signedCodeHash = address(impl).codehash;
        assertNotEq(address(otherImpl).codehash, signedCodeHash);
        (address bornAt, bytes32 salt, uint256 s) =
            _craftRootlessBirth(address(otherImpl), signedCodeHash, initData);
        _attachDelegation(bornAt, address(router));

        vm.expectRevert(InvalidImplementation.selector);
        GlauxDelegate(payable(bornAt))
            .initialize(address(otherImpl), signedCodeHash, initData, salt, s);
    }

    function test_birth_rejectsImplementationWithoutCompatibilityMarker() public {
        NonInitializingAccount noMarkerImplementation = new NonInitializingAccount();
        bytes memory initData = abi.encode(_slots(), _proofs());
        bytes32 codeHash = address(noMarkerImplementation).codehash;
        (address bornAt, bytes32 salt, uint256 s) =
            _craftRootlessBirth(address(noMarkerImplementation), codeHash, initData);
        _attachDelegation(bornAt, address(router));

        vm.expectRevert(InvalidImplementation.selector);
        GlauxDelegate(payable(bornAt))
            .initialize(address(noMarkerImplementation), codeHash, initData, salt, s);
    }

    function test_birthDigestRemainsChainAgnostic() public {
        _attachDelegation(account, address(router));
        uint256 originalChainId = block.chainid;

        vm.chainId(originalChainId + 1);
        GlauxDelegate(payable(account))
            .initialize(address(impl), address(impl).codehash, _initBlob(), accountSalt, accountS);
        vm.chainId(originalChainId);

        assertEq(GlauxAccount(payable(account)).updateNonce(), 0);
    }

    function test_birth_rejectsDifferentSlotsWithSameProof() public {
        _attachDelegation(account, address(router));
        FactorSlot[3] memory changed = _slots();
        changed[0] = FactorSlot(GlauxStorage.VERIFIER_SECP256K1, abi.encode(address(0xBAD)));

        vm.expectRevert(InvalidBirthProof.selector);
        GlauxDelegate(payable(account))
            .initialize(
                address(impl),
                address(impl).codehash,
                _initDataUnproven(changed),
                accountSalt,
                accountS
            );
    }

    function test_birth_secondInitReverts() public {
        _birthAccount();

        vm.expectRevert(AlreadyInitialized.selector);
        GlauxDelegate(payable(account))
            .initialize(address(impl), address(impl).codehash, _initBlob(), accountSalt, accountS);
    }

    function test_birth_noCodeImplementationRevertsAndOriginalBlobIsRetryable() public {
        address futureImplementation = address(0xF00D);
        bytes memory initData = abi.encode(_slots(), _proofs());
        bytes32 expectedCodeHash = address(impl).codehash;
        (address bornAt, bytes32 salt, uint256 s) =
            _craftRootlessBirth(futureImplementation, expectedCodeHash, initData);
        _attachDelegation(bornAt, address(router));

        vm.expectRevert(InvalidImplementation.selector);
        GlauxDelegate(payable(bornAt))
            .initialize(futureImplementation, expectedCodeHash, initData, salt, s);

        assertEq(vm.load(bornAt, GlauxStorage.IMPL_SLOT), bytes32(0));
        vm.expectRevert(NotInitialized.selector);
        GlauxAccount(payable(bornAt)).updateNonce();

        vm.etch(futureImplementation, address(impl).code);
        GlauxDelegate(payable(bornAt))
            .initialize(futureImplementation, expectedCodeHash, initData, salt, s);

        (uint8 vType,) = GlauxAccount(payable(bornAt)).getSlot(0);
        assertEq(vType, GlauxStorage.VERIFIER_SECP256K1);
    }

    function test_birth_zeroImplementationReverts() public {
        bytes memory initData = abi.encode(_slots(), _proofs());
        (address bornAt, bytes32 salt, uint256 s) =
            _craftRootlessBirth(address(0), bytes32(0), initData);
        _attachDelegation(bornAt, address(router));

        vm.expectRevert(InvalidImplementation.selector);
        GlauxDelegate(payable(bornAt)).initialize(address(0), bytes32(0), initData, salt, s);
    }

    function test_birth_revertsWhenImplementationDoesNotSetInitialized() public {
        MarkerWithoutInitialization nonInitializingImplementation =
            new MarkerWithoutInitialization();
        bytes memory initData = abi.encode(_slots(), _proofs());
        (address bornAt, bytes32 salt, uint256 s) = _craftRootlessBirth(
            address(nonInitializingImplementation),
            address(nonInitializingImplementation).codehash,
            initData
        );
        _attachDelegation(bornAt, address(router));

        vm.expectRevert(NotInitialized.selector);
        GlauxDelegate(payable(bornAt))
            .initialize(
                address(nonInitializingImplementation),
                address(nonInitializingImplementation).codehash,
                initData,
                salt,
                s
            );

        assertEq(vm.load(bornAt, GlauxStorage.IMPL_SLOT), bytes32(0));
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
        _attachDelegation(account, address(router));

        vm.expectRevert(NotInitialized.selector);
        GlauxAccount(payable(account)).initializeAccount(_initDataUnproven(_slots()));
    }

    function test_attackerCannotInitializeThroughAccountBeforeBirthWhenLogicExists() public {
        _attachDelegation(account, address(router));
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
        ForeignProxyLogic foreign = new ForeignProxyLogic();
        vm.store(
            account, GlauxStorage.ERC1967_IMPL_SLOT, bytes32(uint256(uint160(address(foreign))))
        );

        _attachDelegation(account, address(router));
        GlauxDelegate(payable(account))
            .initialize(address(impl), address(impl).codehash, _initBlob(), accountSalt, accountS);

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
        TransientProbeAccount probe = new TransientProbeAccount();
        bytes memory initData = abi.encode(_slots(), _proofs());
        (address bornAt, bytes32 salt, uint256 s) =
            _craftRootlessBirth(address(probe), address(probe).codehash, initData);
        _attachDelegation(bornAt, address(router));

        GlauxDelegate(payable(bornAt))
            .initialize(address(probe), address(probe).codehash, initData, salt, s);

        // Read the slot directly: the probe is a minimal mock without accessors.
        assertEq(address(uint160(uint256(vm.load(bornAt, GlauxStorage.IMPL_SLOT)))), address(probe));
    }

    /// @notice The router's fallback must never execute a pointer Glaux did not
    ///         write. Before birth there is no Glaux implementation, so a leftover
    ///         foreign one must be unreachable rather than delegatecalled with the
    ///         account's storage and balance.
    function test_foreignErc1967PointerIsNeverExecuted() public {
        _attachDelegation(account, address(router));
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
        FactorSlot[3] memory invalid = _slots();
        invalid[0] = FactorSlot(GlauxStorage.VERIFIER_SECP256K1, new bytes(31));
        bytes memory initData = _initDataUnproven(invalid);
        (address bornAt, bytes32 salt, uint256 s) =
            _craftRootlessBirth(address(impl), address(impl).codehash, initData);
        _attachDelegation(bornAt, address(router));

        vm.expectRevert(InvalidSlot.selector);
        GlauxDelegate(payable(bornAt))
            .initialize(address(impl), address(impl).codehash, initData, salt, s);

        vm.expectRevert(NotInitialized.selector);
        GlauxAccount(payable(bornAt)).updateNonce();
        // The same address can still be born from ITS own valid configuration:
        // a failed birth writes nothing, so the derivation stays available.
        (address retryAt, bytes32 retrySalt, uint256 retryS) =
            _craftRootlessBirth(address(impl), address(impl).codehash, _initBlob());
        _attachDelegation(retryAt, address(router));
        GlauxDelegate(payable(retryAt))
            .initialize(address(impl), address(impl).codehash, _initBlob(), retrySalt, retryS);
    }

    function test_birth_rejectsOneMalformedSlot() public {
        FactorSlot[3] memory invalid = _slots();
        invalid[0] = FactorSlot(GlauxStorage.VERIFIER_SECP256K1, abi.encode(address(0)));
        bytes memory initData = _initDataUnproven(invalid);
        (address bornAt, bytes32 salt, uint256 s) =
            _craftRootlessBirth(address(impl), address(impl).codehash, initData);
        _attachDelegation(bornAt, address(router));

        vm.expectRevert(InvalidSlot.selector);
        GlauxDelegate(payable(bornAt))
            .initialize(address(impl), address(impl).codehash, initData, salt, s);
    }

    function test_birth_rejectsTwoMalformedSlots() public {
        FactorSlot[3] memory invalid = _slots();
        invalid[0] = FactorSlot(GlauxStorage.VERIFIER_SECP256K1, abi.encode(address(0)));
        invalid[1] = FactorSlot(GlauxStorage.VERIFIER_P256, abi.encode(0, 0));
        bytes memory initData = _initDataUnproven(invalid);
        (address bornAt, bytes32 salt, uint256 s) =
            _craftRootlessBirth(address(impl), address(impl).codehash, initData);
        _attachDelegation(bornAt, address(router));

        vm.expectRevert(InvalidSlot.selector);
        GlauxDelegate(payable(bornAt))
            .initialize(address(impl), address(impl).codehash, initData, salt, s);
    }

    function test_birth_rejectsInvalidVerifierType() public {
        FactorSlot[3] memory invalid = _slots();
        invalid[1] = FactorSlot(0, abi.encode(DEVICE_QX, DEVICE_QY));
        // Slot 0 is valid and proven, so the run reaches slot 1 and fails on its
        // verifier type rather than on a missing proof.
        bytes memory initData = _initDataFor(invalid, [paperPk, DEVICE_P256_PK, cloudPk]);
        (address bornAt, bytes32 salt, uint256 s) =
            _craftRootlessBirth(address(impl), address(impl).codehash, initData);
        _attachDelegation(bornAt, address(router));

        vm.expectRevert(InvalidVerifierType.selector);
        GlauxDelegate(payable(bornAt))
            .initialize(address(impl), address(impl).codehash, initData, salt, s);
    }

    function test_receive_beforeInit() public {
        _attachDelegation(account, address(router));
        vm.deal(address(this), 1 ether);

        (bool ok,) = account.call{value: 0.5 ether}("");

        assertTrue(ok);
        assertEq(account.balance, 0.5 ether);
    }

    function test_fallback_beforeInit_reverts() public {
        _attachDelegation(account, address(router));

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

    /// @notice Residual 17 no longer has a birth path to attack. It described an
    ///         EOA carrying storage from a previous delegate — an EIP-7702
    ///         re-delegation does not clear it — arriving at Glaux with
    ///         `IMPL_SLOT` already written, which bricked its birth forever.
    ///         Under rootless birth no key-bearing EOA can be born at all: the
    ///         account address IS the recovery of its own configuration's proof,
    ///         so an address someone holds a key for is an address that proof
    ///         never recovers to. The poisoning still lands, and birth still
    ///         refuses — but now for a reason no attacker can arrange, and one
    ///         that holds whether the storage was poisoned or pristine.
    function test_keyBearingEoaCannotBeBornAtAll() public {
        uint256 victimPk = 0x71C72;
        address victim = vm.addr(victimPk);
        PriorDelegate prior = new PriorDelegate();
        PoisonSink sink = new PoisonSink();

        vm.signAndAttachDelegation(address(prior), victimPk);
        PriorDelegate(victim)
            .poison(GlauxStorage.IMPL_SLOT, bytes32(uint256(uint160(address(sink)))));

        vm.signAndAttachDelegation(address(router), victimPk);
        // Two separate properties, and this half is the weaker one: the planted
        // pointer is checked BEFORE authentication, so this refusal would stand
        // even with every birth-proof check deleted. It is here to show the
        // poisoning still cannot produce a birth, not to pin the proof.
        vm.expectRevert(AlreadyInitialized.selector);
        GlauxDelegate(payable(victim))
            .initialize(address(impl), address(impl).codehash, _initBlob(), accountSalt, accountS);

        // The load-bearing half: an address with a key and PRISTINE storage,
        // where nothing but the proof stands in the way. It is refused because
        // the account's proof recovers to the account's own derived address,
        // which this one is not — the property that makes a key-bearing EOA
        // unbirthable in general, not just a poisoned one.
        address pristine = vm.addr(0x71C73);
        vm.signAndAttachDelegation(address(router), 0x71C73);
        assertEq(vm.load(pristine, GlauxStorage.IMPL_SLOT), bytes32(0), "storage must be untouched");
        assertEq(
            _recoveredFor(_initBlob(), accountSalt, accountS),
            account,
            "proof recovers elsewhere, nonzero"
        );
        assertNotEq(account, pristine);

        vm.expectRevert(InvalidBirthProof.selector);
        GlauxDelegate(payable(pristine))
            .initialize(address(impl), address(impl).codehash, _initBlob(), accountSalt, accountS);

        // The planted code remains reachable on the poisoned victim, which is
        // why such an address must never be presented as a Glaux account: it is
        // not one, and no birth made it one.
        PoisonSink(victim).ping();
        assertEq(
            vm.load(victim, bytes32(uint256(0xC0FFEE))), bytes32(uint256(1)), "planted code ran"
        );
    }

    /// @notice Residual 17, second outcome: the prior delegate plants a FULL Glaux
    ///         `Layout` — `initialized = true`, `IMPL_SLOT` pointing at the real
    ///         implementation, and all three factor slots holding attacker-controlled
    ///         secp256k1 addresses — before the EOA ever signs a Glaux birth blob. The
    ///         account never goes through `initialize`, yet the moment it delegates to
    ///         the router it reads as a fully born Glaux account whose 2-of-3 quorum
    ///         the attacker alone satisfies, and can drain funds sent to it.
    function test_residual17_plantedFullStateMakesAccountAttackerOwned() public {
        uint256 victimPk = 0x71C72;
        uint256 aPk0 = 0xA11CE0;
        uint256 aPk1 = 0xA11CE1;
        uint256 aPk2 = 0xA11CE2;
        address victim = vm.addr(victimPk);
        PriorDelegate prior = new PriorDelegate();

        vm.signAndAttachDelegation(address(prior), victimPk);
        PriorDelegate(victim)
            .poison(GlauxStorage.IMPL_SLOT, bytes32(uint256(uint160(address(impl)))));
        PriorDelegate(victim).poison(GlauxStorage.SLOT, bytes32(uint256(1))); // initialized = true
        uint256[3] memory pks = [aPk0, aPk1, aPk2];
        for (uint256 i = 0; i < 3; i++) {
            bytes32 base = bytes32(uint256(GlauxStorage.SLOT) + 1 + i * 2);
            PriorDelegate(victim).poison(base, bytes32(uint256(GlauxStorage.VERIFIER_SECP256K1)));
            PriorDelegate(victim).poison(bytes32(uint256(base) + 1), bytes32(uint256(32 * 2 + 1)));
            PriorDelegate(victim)
                .poison(
                    keccak256(abi.encode(bytes32(uint256(base) + 1))),
                    bytes32(uint256(uint160(vm.addr(pks[i]))))
                );
        }

        vm.signAndAttachDelegation(address(router), victimPk);
        vm.deal(victim, 5 ether);
        assertEq(GlauxAccount(payable(victim)).implementation(), address(impl));
        (uint8 t0, bytes memory d0) = GlauxAccount(payable(victim)).getSlot(0);
        assertEq(t0, GlauxStorage.VERIFIER_SECP256K1);
        assertEq(abi.decode(d0, (address)), vm.addr(aPk0));

        address attacker = address(0xBADBAD);
        Call[] memory calls = new Call[](1);
        calls[0] = Call(attacker, 5 ether, "");
        bytes32 d = GlauxStorage.eip191(
            victim,
            keccak256(
                abi.encode(
                    GlauxStorage.EXEC_DOMAIN,
                    block.chainid,
                    victim,
                    uint64(0),
                    keccak256(abi.encode(calls)),
                    FAR_FUTURE
                )
            )
        );
        SlotSig[2] memory sigs;
        sigs[0] = SlotSig(0, _sig65(aPk0, d));
        sigs[1] = SlotSig(1, _sig65(aPk1, d));

        vm.prank(attacker);
        GlauxAccount(payable(victim)).executeWithSigs(calls, FAR_FUTURE, sigs);

        assertEq(attacker.balance, 5 ether);
    }
}

/// @notice Stands in for a wallet the account was delegated to BEFORE moving to
///         Glaux, used by the residual-17 regression tests to write arbitrary
///         storage into the victim EOA's account storage ahead of birth — exactly
///         what an EIP-7702 re-delegation does not clear.
contract PriorDelegate {
    function poison(bytes32 slot, bytes32 value) external {
        assembly {
            sstore(slot, value)
        }
    }
}

/// @notice Minimal implementation planted at a pre-poisoned `IMPL_SLOT`, used to
///         prove the router's fallback executes whatever that slot points at.
contract PoisonSink {
    function ping() external {
        assembly {
            sstore(0xC0FFEE, 1)
        }
    }
}
