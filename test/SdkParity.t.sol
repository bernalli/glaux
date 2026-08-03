// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {GlauxFixture} from "./GlauxFixture.sol";
import {GlauxStorage, Call, SlotSig} from "../src/GlauxStorage.sol";

/// @notice Pins the digest/encoding vectors the TypeScript SDK asserts itself against
///         (sdk/test/parity.test.ts). Every value below comes from a REAL contract
///         code path or a GlauxFixture helper the rest of the Solidity suite already
///         relies on for the exact same computation — `GlauxStorage.eip191`, the
///         domain constants, and the abi.encode layouts `_requirePossession`,
///         `executeWithSigs`, `validateUserOp` and `isValidSignature` use — never
///         hand-recomputed here, so a drift in either language turns this fixture
///         red instead of silently diverging. Companion of
///         `test/StorageParity.t.sol`, same serialization idiom (manual
///         `vm.toString` + `vm.writeFile`, gated behind an env var). Each section is
///         built in its own function: one function assembling every field at once
///         overflows the EVM stack (16 local slots) at solc's default optimizer
///         profile, and `test/**` is pinned off `via_ir` (foundry.toml
///         compilation_restrictions).
contract SdkParityTest is GlauxFixture {
    string internal constant FIXTURE = "test/fixtures/sdk_parity.json";

    // Fixed inputs, chosen once and frozen: changing any of them moves the committed
    // fixture and is a deliberate act, not a side effect of re-running the generator.
    bytes32 internal constant EIP191_STRUCT_HASH = keccak256("sdk-parity-eip191-sample-v1");
    bytes32 internal constant USEROP_HASH = keccak256("sdk-parity-userop-hash-v1");
    bytes32 internal constant MSG_HASH = keccak256("sdk-parity-msg-hash-v1");
    // A round timestamp far in the future (~2106), distinct from GlauxFixture's
    // FAR_FUTURE (type(uint48).max): pins one concrete, human-legible deadline value
    // shared by every digest below instead of the sentinel "never expires" constant.
    uint48 internal constant VALID_UNTIL = 0xffffffff;
    address internal constant EXEC_CALL_TO = address(0xCA11);
    uint256 internal constant EXEC_CALL_VALUE = 1 ether;
    bytes internal constant EXEC_CALL_DATA = hex"12345678";

    function setUp() public override {
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

    /// @dev index 1 (device slot), verifierType 2 (P-256), the fixed device qx/qy
    ///      from P256Fixture via GlauxFixture. Same formula
    ///      GlauxAccount._requirePossession computes (GlauxFixture._regDigest
    ///      mirrors it literally).
    function _registrationDigestJson() internal pure returns (string memory) {
        uint8 index = 1;
        uint8 verifierType = GlauxStorage.VERIFIER_P256;
        bytes memory data = abi.encode(DEVICE_QX, DEVICE_QY);
        bytes32 digest = _regDigest(index, verifierType, data);
        return string.concat(
            "{\n      ",
            _numEntry("index", index),
            ",\n      ",
            _numEntry("verifierType", verifierType),
            ",\n      ",
            _entry("qx", bytes32(DEVICE_QX)),
            ",\n      ",
            _entry("qy", bytes32(DEVICE_QY)),
            ",\n      ",
            _entry("data", data),
            ",\n      ",
            _entry("digest", digest),
            "\n    }"
        );
    }

    /// @dev The three canonical anvil factor slots from GlauxFixture, encoded and
    ///      digested exactly as GlauxDelegate.initialize / birth.py's
    ///      build_init_digest do.
    function _initDigestJson() internal view returns (string memory) {
        bytes memory initData = abi.encode(_slots(), _proofs());
        bytes32 expectedCodeHash = address(impl).codehash;
        bytes32 digest = _initDigest(address(impl), expectedCodeHash, initData);
        return string.concat(
            "{\n      ",
            _entry("router", address(router)),
            ",\n      ",
            _entry("implementation", address(impl)),
            ",\n      ",
            _entry("expectedCodeHash", expectedCodeHash),
            ",\n      ",
            _entry("initData", initData),
            ",\n      ",
            _entry("digest", digest),
            "\n    }"
        );
    }

    /// @dev Fixed account, nonce 0 (no execution has happened), one Call, validUntil
    ///      0xffffffff. Same formula GlauxAccount.executeWithSigs computes
    ///      (GlauxFixture._execDigestAtNonce mirrors it literally).
    function _execDigestJson() internal view returns (string memory) {
        Call[] memory calls = new Call[](1);
        calls[0] = Call({to: EXEC_CALL_TO, value: EXEC_CALL_VALUE, data: EXEC_CALL_DATA});
        bytes32 callsHash = keccak256(abi.encode(calls));
        bytes32 digest = _execDigestAtNonce(calls, 0, VALID_UNTIL);
        return string.concat(
            "{\n      ",
            _entry("account", account),
            ",\n      ",
            _numEntry("chainId", block.chainid),
            ",\n      ",
            _numEntry("nonce", uint256(0)),
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
            _entry("digest", digest),
            "\n    }"
        );
    }

    /// @dev Fixed userOpHash, shared VALID_UNTIL. Same formula
    ///      GlauxAccount.validateUserOp computes (GlauxFixture._userOpDigest mirrors
    ///      it literally). Returns the digest too, reused by the encoded-signature
    ///      sections below.
    function _userOpDigestJson() internal view returns (string memory json, bytes32 digest) {
        digest = _userOpDigest(USEROP_HASH, VALID_UNTIL);
        json = string.concat(
            "{\n      ",
            _entry("account", account),
            ",\n      ",
            _entry("userOpHash", USEROP_HASH),
            ",\n      ",
            _numEntry("validUntil", VALID_UNTIL),
            ",\n      ",
            _entry("digest", digest),
            "\n    }"
        );
    }

    /// @dev Fixed hash, shared VALID_UNTIL. Same formula
    ///      GlauxAccount.isValidSignature computes (GlauxFixture._msgDigest mirrors
    ///      it literally).
    function _msgDigestJson() internal view returns (string memory) {
        bytes32 digest = _msgDigest(MSG_HASH, VALID_UNTIL);
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
            _entry("digest", digest),
            "\n    }"
        );
    }

    /// @dev The device (P-256) factor signing `userOpDigest` above, abi-encoded as
    ///      `(uint256 r, uint256 s)` — the exact layout SignatureVerify._verifyP256
    ///      decodes (GlauxFixture._sigP256 mirrors it literally).
    function _encodedSlotSigP256Json(bytes32 userOpDigestValue)
        internal
        pure
        returns (string memory)
    {
        (bytes32 r, bytes32 s) = vm.signP256(DEVICE_P256_PK, userOpDigestValue);
        bytes memory encoded = abi.encode(uint256(r), uint256(s));
        return string.concat(
            "{\n      ",
            _numEntry("slotIndex", uint256(1)),
            ",\n      ",
            _entry("qx", bytes32(DEVICE_QX)),
            ",\n      ",
            _entry("qy", bytes32(DEVICE_QY)),
            ",\n      ",
            _entry("digest", userOpDigestValue),
            ",\n      ",
            _entry("r", r),
            ",\n      ",
            _entry("s", s),
            ",\n      ",
            _entry("encoded", encoded),
            "\n    }"
        );
    }

    /// @dev `abi.encode(validUntil, SlotSig[2])`, the exact wire format
    ///      GlauxAccount.decodeSlotSigs decodes userOp.signature (and ERC-1271
    ///      `signature`) as. Paper (slot 0) + cloud (slot 2) sign, per
    ///      GlauxFixture._twoSigs.
    function _encodedUserOpSignatureJson(bytes32 userOpDigestValue)
        internal
        view
        returns (string memory)
    {
        SlotSig[2] memory twoSigs = _twoSigs(userOpDigestValue);
        bytes memory encoded = abi.encode(VALID_UNTIL, twoSigs);
        return string.concat(
            "{\n      ",
            _entry("userOpHash", USEROP_HASH),
            ",\n      ",
            _numEntry("validUntil", VALID_UNTIL),
            ",\n      \"sigs\": [\n        {",
            _numEntry("slotIndex", twoSigs[0].slotIndex),
            ", ",
            _entry("signature", twoSigs[0].signature),
            "},\n        {",
            _numEntry("slotIndex", twoSigs[1].slotIndex),
            ", ",
            _entry("signature", twoSigs[1].signature),
            "}\n      ],\n      ",
            _entry("encoded", encoded),
            "\n    }"
        );
    }

    /// @dev Run with GLAUX_WRITE_SDK_PARITY_FIXTURE=true to (re)generate the
    ///      committed fixture after any digest- or encoding-affecting change.
    function test_writeFixtureWhenAsked() public {
        if (!vm.envOr("GLAUX_WRITE_SDK_PARITY_FIXTURE", false)) return;

        (string memory userOpDigest, bytes32 userOpDigestValue) = _userOpDigestJson();
        string memory json = string.concat(
            "{\n  ",
            _entry("router", address(router)),
            ",\n  ",
            _entry("implementation", address(impl)),
            ",\n  ",
            _entry("account", account),
            ",\n  \"domains\": ",
            _domainsJson(),
            ",\n  \"eip191Sample\": ",
            _eip191SampleJson(),
            ",\n  \"registrationDigest\": ",
            _registrationDigestJson(),
            ",\n  \"initDigest\": ",
            _initDigestJson(),
            ",\n  \"execDigest\": ",
            _execDigestJson(),
            ",\n  \"userOpDigest\": ",
            userOpDigest,
            ",\n  \"msgDigest\": ",
            _msgDigestJson(),
            ",\n  \"encodedSlotSigP256\": ",
            _encodedSlotSigP256Json(userOpDigestValue),
            ",\n  \"encodedUserOpSignature\": ",
            _encodedUserOpSignatureJson(userOpDigestValue),
            "\n}\n"
        );
        vm.writeFile(FIXTURE, json);
    }
}
