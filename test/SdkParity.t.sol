// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {GlauxFixture} from "./GlauxFixture.sol";
import {GlauxDelegate} from "../src/GlauxDelegate.sol";
import {GlauxAccount} from "../src/GlauxAccount.sol";
import {GlauxStorage, Call, FactorSlot, SlotSig} from "../src/GlauxStorage.sol";
import {SignatureVerify} from "../src/lib/SignatureVerify.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";

/// @notice Pins the digest/encoding vectors the TypeScript SDK asserts itself against
///         (sdk/test/parity.test.ts).
/// @dev Targeted prerequisite: run `forge build` before
///      `GLAUX_WRITE_SDK_PARITY_FIXTURE=true forge test --match-contract SdkParity`.
///      GlauxFixture etches the P-256 test oracle from the build artifact; this suite
///      reports that missing prerequisite explicitly before calling the shared fixture.
///      Every vector that production computes internally is signed and accepted by its
///      real production path below. The emitted formula is therefore only a candidate:
///      a layout drift in GlauxDelegate or GlauxAccount makes this test revert.
contract SdkParityTest is GlauxFixture {
    string internal constant FIXTURE = "test/fixtures/sdk_parity.json";
    string internal constant P256_ARTIFACT = "out/P256Verifier.sol/P256Verifier.json";

    // Fixed inputs, chosen once and frozen: changing any of them moves the committed
    // fixture and is a deliberate act, not a side effect of re-running the generator.
    bytes32 internal constant EIP191_STRUCT_HASH = keccak256("sdk-parity-eip191-sample-v1");
    bytes32 internal constant USEROP_HASH = keccak256("sdk-parity-userop-hash-v1");
    bytes32 internal constant MSG_HASH = keccak256("sdk-parity-msg-hash-v1");
    uint48 internal constant VALID_UNTIL = 0xffffffff;
    address internal constant EXEC_CALL_TO = address(0xCA11);
    uint256 internal constant EXEC_CALL_VALUE = 1 ether;
    bytes internal constant EXEC_CALL_DATA = hex"12345678";

    // These are emitted for the SDK's live verifier probe. They are mirrored
    // below through SignatureVerify.p256VerifierAvailable(): an empty verifier
    // plus exact-call mocks makes this test fail if the contract vector or its
    // flipped negative arm ever differs from the emitted fixture.
    bytes32 internal constant P256_PROBE_DIGEST =
        0x867725ff3c347f7537e90a9166778796299dcc35b965e51a431e53a9d4b2b5a4;
    uint256 internal constant P256_PROBE_R =
        0x980d841a72d73ef73cfd9baadc862485aecac52b199bbd3df24e834f737ed46c;
    uint256 internal constant P256_PROBE_S =
        0x4ac2a1c22aa9ff18958b5d11775f7dced116f8f5a6c95f2d859bf6f0035df385;
    uint256 internal constant P256_PROBE_QX =
        0x6e116efa770f5c5455124d86df9b00525dab28db280c3c8f33bb64c0ef313489;
    uint256 internal constant P256_PROBE_QY =
        0x8961e3da77e0f8d247f099835070289b64906c509ec256eec976858516ae8d81;

    struct Vectors {
        FactorSlot[3] slots;
        bytes registrationData;
        bytes32 registrationDigest;
        bytes initData;
        bytes32 expectedCodeHash;
        bytes32 initDigest;
        bytes initSignature;
        Call[] calls;
        bytes32 execDigest;
        SlotSig[2] execSigs;
        bytes32 userOpDigest;
        bytes p256SlotSig;
        SlotSig[2] userOpSigs;
        bytes encodedUserOpSignature;
        bytes32 msgDigest;
        bytes msgSignature;
    }

    function setUp() public override {
        assertTrue(
            vm.exists(P256_ARTIFACT),
            "SdkParity requires `forge build` first: missing P256Verifier artifact in out/"
        );
        super.setUp();
        // block.chainid feeds EXEC_DOMAIN and MSG_DOMAIN digests directly: pin it so
        // the fixture does not silently move if a Foundry default ever changes.
        vm.chainId(31337);
    }

    function _entry(string memory key, bytes32 value) internal pure returns (string memory) {
        return string.concat("\"", key, "\": \"", vm.toString(value), "\"");
    }

    function _entry(string memory key, address value) internal pure returns (string memory) {
        return string.concat("\"", key, "\": \"", vm.toString(value), "\"");
    }

    function _entry(string memory key, bytes memory value) internal pure returns (string memory) {
        return string.concat("\"", key, "\": \"", vm.toString(value), "\"");
    }

    function _numEntry(string memory key, uint256 value) internal pure returns (string memory) {
        return string.concat("\"", key, "\": ", vm.toString(value));
    }

    /// @dev The account's own domain constants, not retyped keccak calls.
    function _domainsJson() internal pure returns (string memory) {
        return string.concat(
            "{\n      ",
            _entry("INIT", GlauxStorage.INIT_DOMAIN),
            ",\n      ",
            _entry("UPDATE", GlauxStorage.UPDATE_DOMAIN),
            ",\n      ",
            _entry("EXEC", GlauxStorage.EXEC_DOMAIN),
            ",\n      ",
            _entry("USEROP", GlauxStorage.USEROP_DOMAIN),
            ",\n      ",
            _entry("REG", GlauxStorage.REG_DOMAIN),
            ",\n      ",
            _entry("MSG", GlauxStorage.MSG_DOMAIN),
            "\n    }"
        );
    }

    /// @dev GlauxStorage.eip191 itself, the wrapper every digest below is built on.
    function _eip191SampleJson() internal view returns (string memory) {
        bytes32 digest = GlauxStorage.eip191(account, EIP191_STRUCT_HASH);
        return string.concat(
            "{\n      ",
            _entry("validator", account),
            ",\n      ",
            _entry("structHash", EIP191_STRUCT_HASH),
            ",\n      ",
            _entry("digest", digest),
            "\n    }"
        );
    }

    function _registrationDigestJson(Vectors memory v) internal pure returns (string memory) {
        return string.concat(
            "{\n      ",
            _numEntry("index", 1),
            ",\n      ",
            _numEntry("verifierType", GlauxStorage.VERIFIER_P256),
            ",\n      ",
            _entry("qx", bytes32(DEVICE_QX)),
            ",\n      ",
            _entry("qy", bytes32(DEVICE_QY)),
            ",\n      ",
            _entry("data", v.registrationData),
            ",\n      ",
            _entry("digest", v.registrationDigest),
            "\n    }"
        );
    }

    function _initDigestJson(Vectors memory v) internal view returns (string memory) {
        return string.concat(
            "{\n      ",
            _entry("router", address(router)),
            ",\n      ",
            _entry("implementation", address(impl)),
            ",\n      ",
            _entry("expectedCodeHash", v.expectedCodeHash),
            ",\n      ",
            _entry("initData", v.initData),
            ",\n      ",
            _entry("digest", v.initDigest),
            "\n    }"
        );
    }

    function _execDigestJson(Vectors memory v) internal view returns (string memory) {
        bytes32 callsHash = keccak256(abi.encode(v.calls));
        return string.concat(
            "{\n      ",
            _entry("account", account),
            ",\n      ",
            _numEntry("chainId", block.chainid),
            ",\n      ",
            _numEntry("nonce", 0),
            ",\n      ",
            _numEntry("validUntil", VALID_UNTIL),
            ",\n      \"call\": {",
            _entry("to", EXEC_CALL_TO),
            ", ",
            _numEntry("value", EXEC_CALL_VALUE),
            ", ",
            _entry("data", EXEC_CALL_DATA),
            "},\n      ",
            _entry("callsHash", callsHash),
            ",\n      ",
            _entry("digest", v.execDigest),
            "\n    }"
        );
    }

    function _userOpDigestJson(Vectors memory v) internal view returns (string memory) {
        return string.concat(
            "{\n      ",
            _entry("account", account),
            ",\n      ",
            _entry("userOpHash", USEROP_HASH),
            ",\n      ",
            _numEntry("validUntil", VALID_UNTIL),
            ",\n      ",
            _entry("digest", v.userOpDigest),
            "\n    }"
        );
    }

    function _msgDigestJson(Vectors memory v) internal view returns (string memory) {
        return string.concat(
            "{\n      ",
            _entry("account", account),
            ",\n      ",
            _numEntry("chainId", block.chainid),
            ",\n      ",
            _entry("hash", MSG_HASH),
            ",\n      ",
            _numEntry("validUntil", VALID_UNTIL),
            ",\n      ",
            _entry("digest", v.msgDigest),
            "\n    }"
        );
    }

    function _encodedSlotSigP256Json(Vectors memory v) internal pure returns (string memory) {
        (bytes32 r, bytes32 s) = abi.decode(v.p256SlotSig, (bytes32, bytes32));
        return string.concat(
            "{\n      ",
            _numEntry("slotIndex", 1),
            ",\n      ",
            _entry("qx", bytes32(DEVICE_QX)),
            ",\n      ",
            _entry("qy", bytes32(DEVICE_QY)),
            ",\n      ",
            _entry("digest", v.userOpDigest),
            ",\n      ",
            _entry("r", r),
            ",\n      ",
            _entry("s", s),
            ",\n      ",
            _entry("encoded", v.p256SlotSig),
            "\n    }"
        );
    }

    function _encodedUserOpSignatureJson(Vectors memory v) internal pure returns (string memory) {
        return string.concat(
            "{\n      ",
            _entry("userOpHash", USEROP_HASH),
            ",\n      ",
            _numEntry("validUntil", VALID_UNTIL),
            ",\n      \"sigs\": [\n        {",
            _numEntry("slotIndex", v.userOpSigs[0].slotIndex),
            ", ",
            _entry("signature", v.userOpSigs[0].signature),
            "},\n        {",
            _numEntry("slotIndex", v.userOpSigs[1].slotIndex),
            ", ",
            _entry("signature", v.userOpSigs[1].signature),
            "}\n      ],\n      ",
            _entry("encoded", v.encodedUserOpSignature),
            "\n    }"
        );
    }

    function _p256ProbeJson() internal pure returns (string memory) {
        string memory json = string.concat("{\n      ", _entry("digest", P256_PROBE_DIGEST));
        json = string.concat(json, ",\n      ", _entry("r", bytes32(P256_PROBE_R)));
        json = string.concat(json, ",\n      ", _entry("s", bytes32(P256_PROBE_S)));
        json = string.concat(json, ",\n      ", _entry("qx", bytes32(P256_PROBE_QX)));
        json = string.concat(json, ",\n      ", _entry("qy", bytes32(P256_PROBE_QY)));
        return string.concat(
            json,
            ",\n      ",
            _entry("flippedDigest", P256_PROBE_DIGEST ^ bytes32(uint256(1))),
            "\n    }"
        );
    }

    function _vectors() internal view returns (Vectors memory v) {
        v.slots = _slots();
        v.registrationData = v.slots[1].data;
        v.registrationDigest = _regDigest(1, v.slots[1].verifierType, v.registrationData);

        bytes[3] memory proofs;
        proofs[0] = _sig65(paperPk, _regDigest(0, v.slots[0].verifierType, v.slots[0].data));
        proofs[1] = _sigP256(DEVICE_P256_PK, v.registrationDigest);
        proofs[2] = _sig65(cloudPk, _regDigest(2, v.slots[2].verifierType, v.slots[2].data));
        v.initData = abi.encode(v.slots, proofs);
        v.expectedCodeHash = address(impl).codehash;
        v.initDigest = _initDigest(address(impl), v.expectedCodeHash, v.initData);
        v.initSignature = _sig65(birthPk, v.initDigest);

        v.calls = new Call[](1);
        v.calls[0] = Call({to: EXEC_CALL_TO, value: EXEC_CALL_VALUE, data: EXEC_CALL_DATA});
        v.execDigest = _execDigestAtNonce(v.calls, 0, VALID_UNTIL);
        v.execSigs = _twoSigs(v.execDigest);

        v.userOpDigest = _userOpDigest(USEROP_HASH, VALID_UNTIL);
        v.p256SlotSig = _sigP256(DEVICE_P256_PK, v.userOpDigest);
        v.userOpSigs[0] = SlotSig(0, _sig65(paperPk, v.userOpDigest));
        v.userOpSigs[1] = SlotSig(1, v.p256SlotSig);
        v.encodedUserOpSignature = abi.encode(VALID_UNTIL, v.userOpSigs);

        v.msgDigest = _msgDigest(MSG_HASH, VALID_UNTIL);
        v.msgSignature = abi.encode(VALID_UNTIL, _twoSigs(v.msgDigest));
    }

    /// @dev Proves the emitted initData, initDigest, and registrationDigest through
    ///      GlauxDelegate.initialize -> GlauxAccount.initializeAccount.
    function _proveBirth(Vectors memory v) internal {
        vm.signAndAttachDelegation(address(router), birthPk);
        GlauxDelegate(payable(account))
            .initialize(address(impl), v.expectedCodeHash, v.initData, v.initSignature);

        GlauxAccount a = GlauxAccount(payable(account));
        for (uint8 i = 0; i < 3; i++) {
            (uint8 verifierType, bytes memory data) = a.getSlot(i);
            assertEq(verifierType, v.slots[i].verifierType, "born slot verifier type");
            assertEq(data, v.slots[i].data, "born slot key data");
        }
    }

    /// @dev Proves the emitted calls and execDigest through executeWithSigs.
    function _proveExecution(Vectors memory v) internal {
        uint256 beforeBalance = EXEC_CALL_TO.balance;
        vm.deal(account, EXEC_CALL_VALUE);
        GlauxAccount(payable(account)).executeWithSigs(v.calls, VALID_UNTIL, v.execSigs);
        assertEq(EXEC_CALL_TO.balance, beforeBalance + EXEC_CALL_VALUE, "emitted call executed");
        assertEq(GlauxAccount(payable(account)).execNonce(), 1, "exec nonce advanced");
    }

    /// @dev Proves the emitted userOpDigest, encoded P-256 slot signature, and full
    ///      user-operation signature through the EntryPoint-authenticated path.
    function _proveUserOp(Vectors memory v) internal {
        PackedUserOperation memory op;
        op.sender = account;
        op.signature = v.encodedUserOpSignature;
        vm.prank(address(ep));
        uint256 validationData = GlauxAccount(payable(account)).validateUserOp(op, USEROP_HASH, 0);
        assertEq(validationData, uint256(VALID_UNTIL) << 160, "user operation accepted");
    }

    /// @dev Proves the emitted msgDigest through ERC-1271's real verification path.
    function _proveMessage(Vectors memory v) internal view {
        assertEq(
            GlauxAccount(payable(account)).isValidSignature(MSG_HASH, v.msgSignature),
            IERC1271.isValidSignature.selector,
            "message signature accepted"
        );
    }

    function _json(Vectors memory v) internal view returns (string memory) {
        string memory json = string.concat("{\n  ", _entry("router", address(router)));
        json = string.concat(json, ",\n  ", _entry("implementation", address(impl)));
        json = string.concat(json, ",\n  ", _entry("account", account));
        json = string.concat(json, ",\n  \"domains\": ", _domainsJson());
        json = string.concat(json, ",\n  \"eip191Sample\": ", _eip191SampleJson());
        json = string.concat(json, ",\n  \"registrationDigest\": ", _registrationDigestJson(v));
        json = string.concat(json, ",\n  \"p256Probe\": ", _p256ProbeJson());
        json = string.concat(json, ",\n  \"initDigest\": ", _initDigestJson(v));
        json = string.concat(json, ",\n  \"execDigest\": ", _execDigestJson(v));
        json = string.concat(json, ",\n  \"userOpDigest\": ", _userOpDigestJson(v));
        json = string.concat(json, ",\n  \"msgDigest\": ", _msgDigestJson(v));
        json = string.concat(json, ",\n  \"encodedSlotSigP256\": ", _encodedSlotSigP256Json(v));
        json = string.concat(
            json, ",\n  \"encodedUserOpSignature\": ", _encodedUserOpSignatureJson(v)
        );
        return string.concat(json, "\n}\n");
    }

    /// @dev Run with GLAUX_WRITE_SDK_PARITY_FIXTURE=true to (re)generate the
    ///      committed fixture after any digest- or encoding-affecting change.
    function test_writeFixtureWhenAsked() public {
        if (!vm.envOr("GLAUX_WRITE_SDK_PARITY_FIXTURE", false)) return;

        Vectors memory v = _vectors();
        _proveBirth(v);
        _proveExecution(v);
        _proveUserOp(v);
        _proveMessage(v);
        vm.writeFile(FIXTURE, _json(v));
    }

    /// @dev The internal SignatureVerify constants have no getter. Exact calldata
    ///      mocks against empty code prove this emitted vector is the one the
    ///      contract itself asks, including the digest^1 negative arm.
    function test_p256ProbeFixtureMatchesSignatureVerify() public {
        bytes memory positive = abi.encodePacked(
            P256_PROBE_DIGEST, P256_PROBE_R, P256_PROBE_S, P256_PROBE_QX, P256_PROBE_QY
        );
        bytes memory negative = abi.encodePacked(
            P256_PROBE_DIGEST ^ bytes32(uint256(1)),
            P256_PROBE_R,
            P256_PROBE_S,
            P256_PROBE_QX,
            P256_PROBE_QY
        );
        vm.etch(address(0x100), hex"");
        vm.mockCall(address(0x100), positive, abi.encode(uint256(1)));
        vm.mockCall(address(0x100), negative, abi.encode(uint256(0)));
        assertTrue(
            SignatureVerify.p256VerifierAvailable(), "emitted P-256 probe differs from contract"
        );
    }
}
