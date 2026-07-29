// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import "forge-std/Test.sol";
import {GlauxDelegate} from "../src/GlauxDelegate.sol";
import {GlauxAccount} from "../src/GlauxAccount.sol";
import {GlauxStorage, FactorSlot, SlotSig, Update, Call} from "../src/GlauxStorage.sol";
import {P256_PK, P256_QX, P256_QY} from "./P256Fixture.sol";
import {EntryPoint} from "account-abstraction/core/EntryPoint.sol";

abstract contract GlauxFixture is Test {
    GlauxDelegate internal router;
    GlauxAccount internal impl;
    EntryPoint internal ep;

    uint256 internal birthPk = 0xB112;
    address internal account;

    uint256 internal paperPk = 0x9A9E5;
    uint256 internal cloudPk = 0xC10D;
    uint256 internal constant DEVICE_P256_PK = P256_PK;
    uint256 internal constant DEVICE_QX = P256_QX;
    uint256 internal constant DEVICE_QY = P256_QY;

    function setUp() public virtual {
        _etchP256();
        ep = new EntryPoint();
        impl = new GlauxAccount(address(ep));
        router = new GlauxDelegate();
        account = vm.addr(birthPk);
    }

    function _slots() internal view returns (FactorSlot[3] memory slots) {
        slots[0] = FactorSlot(GlauxStorage.VERIFIER_SECP256K1, abi.encode(vm.addr(paperPk)));
        slots[1] = FactorSlot(GlauxStorage.VERIFIER_P256, abi.encode(DEVICE_QX, DEVICE_QY));
        slots[2] = FactorSlot(GlauxStorage.VERIFIER_SECP256K1, abi.encode(vm.addr(cloudPk)));
    }

    /// @notice The digest a candidate key must sign to prove it exists before being
    ///         installed into a slot. Commits to the key material itself, so an
    ///         address derived from a chosen signature cannot satisfy it.
    function _regDigest(uint8 index, uint8 verifierType, bytes memory data)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(GlauxStorage.REG_DOMAIN, index, verifierType, keccak256(data)));
    }

    function _sigP256(uint256 privateKey, bytes32 digest) internal pure returns (bytes memory) {
        (bytes32 r, bytes32 s) = vm.signP256(privateKey, digest);
        return abi.encode(uint256(r), uint256(s));
    }

    /// @notice Possession proofs for the reference `_slots()` configuration.
    function _proofs() internal view returns (bytes[3] memory proofs) {
        FactorSlot[3] memory s = _slots();
        proofs[0] = _sig65(paperPk, _regDigest(0, s[0].verifierType, s[0].data));
        proofs[1] = _sigP256(DEVICE_P256_PK, _regDigest(1, s[1].verifierType, s[1].data));
        proofs[2] = _sig65(cloudPk, _regDigest(2, s[2].verifierType, s[2].data));
    }

    function _defaultKeys() internal pure returns (uint256[3] memory keys) {
        keys = [uint256(0x9A9E5), DEVICE_P256_PK, uint256(0xC10D)];
    }

    function _proofFor(uint8 index, FactorSlot memory s, uint256 key)
        internal
        pure
        returns (bytes memory)
    {
        bytes32 d = _regDigest(index, s.verifierType, s.data);
        if (s.verifierType == GlauxStorage.VERIFIER_P256) return _sigP256(key, d);
        return _sig65(key, d);
    }

    /// @notice initData for an arbitrary slot set, with a real possession proof per
    ///         slot produced by the matching key.
    function _initDataFor(FactorSlot[3] memory slots, uint256[3] memory keys)
        internal
        pure
        returns (bytes memory)
    {
        bytes[3] memory proofs;
        for (uint8 i = 0; i < 3; i++) {
            proofs[i] = _proofFor(i, slots[i], keys[i]);
        }
        return abi.encode(slots, proofs);
    }

    /// @notice initData carrying NO possession proofs — for cases that must be
    ///         rejected earlier than the possession check (malformed key material,
    ///         invalid verifier type), so the test pins the reason it claims.
    function _initDataUnproven(FactorSlot[3] memory slots) internal pure returns (bytes memory) {
        bytes[3] memory proofs;
        return abi.encode(slots, proofs);
    }

    function _initBlob() internal view returns (bytes memory initData, bytes memory sig) {
        initData = abi.encode(_slots(), _proofs());
        bytes32 digest = _initDigest(address(impl), address(impl).codehash, initData);
        sig = _sig65(birthPk, digest);
    }

    function _initDigest(address implementation, bytes32 expectedCodeHash, bytes memory initData)
        internal
        view
        returns (bytes32)
    {
        return GlauxStorage.eip191(
            address(router),
            keccak256(
                abi.encode(
                    GlauxStorage.INIT_DOMAIN, implementation, expectedCodeHash, keccak256(initData)
                )
            )
        );
    }

    /// @notice A SetSlot payload with a real possession proof for a P-256 key.
    function _setSlotPayloadP256(uint8 index, uint256 privateKey)
        internal
        pure
        returns (bytes memory)
    {
        (uint256 qx, uint256 qy) = vm.publicKeyP256(privateKey);
        bytes memory data = abi.encode(qx, qy);
        bytes memory proof =
            _sigP256(privateKey, _regDigest(index, GlauxStorage.VERIFIER_P256, data));
        return abi.encode(index, GlauxStorage.VERIFIER_P256, data, proof);
    }

    /// @notice A SetSlot payload with a real possession proof for a secp256k1 key.
    function _setSlotPayload(uint8 index, uint256 privateKey) internal pure returns (bytes memory) {
        bytes memory data = abi.encode(vm.addr(privateKey));
        bytes memory proof =
            _sig65(privateKey, _regDigest(index, GlauxStorage.VERIFIER_SECP256K1, data));
        return abi.encode(index, GlauxStorage.VERIFIER_SECP256K1, data, proof);
    }

    function _birthAccount() internal {
        vm.signAndAttachDelegation(address(router), birthPk);
        (bytes memory initData, bytes memory sig) = _initBlob();
        GlauxDelegate(payable(account))
            .initialize(address(impl), address(impl).codehash, initData, sig);
    }

    function _sig65(uint256 privateKey, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function _etchP256() internal {
        vm.etch(address(0x100), vm.getDeployedCode("P256Verifier.sol:P256Verifier"));
    }

    function _updateDigest(Update memory u) internal view returns (bytes32) {
        return GlauxStorage.eip191(
            account,
            keccak256(
                abi.encode(
                    GlauxStorage.UPDATE_DOMAIN, account, u.nonce, u.action, keccak256(u.payload)
                )
            )
        );
    }

    function _twoSigs(bytes32 digest) internal view returns (SlotSig[2] memory sigs) {
        sigs[0] = SlotSig(0, _sig65(paperPk, digest)); // F2 paper
        sigs[1] = SlotSig(2, _sig65(cloudPk, digest)); // F3 cloud
    }

    function _implementationPayload(address implementation) internal view returns (bytes memory) {
        return abi.encode(implementation, implementation.codehash);
    }

    function _execDigest(Call[] memory calls) internal view returns (bytes32) {
        return _execDigestAtNonce(calls, GlauxAccount(payable(account)).execNonce());
    }

    function _execDigestAtNonce(Call[] memory calls, uint64 nonce) internal view returns (bytes32) {
        return GlauxStorage.eip191(
            account,
            keccak256(
                abi.encode(
                    GlauxStorage.EXEC_DOMAIN,
                    block.chainid,
                    account,
                    nonce,
                    keccak256(abi.encode(calls))
                )
            )
        );
    }
}
