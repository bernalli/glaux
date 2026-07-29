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

    function _initBlob() internal view returns (bytes memory initData, bytes memory sig) {
        initData = abi.encode(_slots());
        bytes32 digest = _initDigest(address(impl), address(impl).codehash, initData);
        sig = _sig65(birthPk, digest);
    }

    function _initDigest(address implementation, bytes32 expectedCodeHash, bytes memory initData)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                GlauxStorage.INIT_DOMAIN, implementation, expectedCodeHash, keccak256(initData)
            )
        );
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
        return keccak256(
            abi.encode(GlauxStorage.UPDATE_DOMAIN, account, u.nonce, u.action, keccak256(u.payload))
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
        return keccak256(
            abi.encode(
                GlauxStorage.EXEC_DOMAIN,
                block.chainid,
                account,
                nonce,
                keccak256(abi.encode(calls))
            )
        );
    }
}
