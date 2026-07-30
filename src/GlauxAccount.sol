// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {
    GlauxStorage,
    FactorSlot,
    SlotSig,
    Update,
    Call,
    AlreadyInitialized,
    NotInitialized,
    BadUpdateNonce,
    CallFailed,
    InvalidAction,
    InvalidImplementation,
    InvalidSignature,
    InvalidSlot,
    PossessionNotProven,
    P256VerifierUnavailable,
    ProbeKeyNotInstallable,
    InvalidVerifierType,
    DuplicateSlot,
    NotEntryPoint,
    ZeroEntryPoint,
    ReentrantCall,
    OperationExpired,
    UpdateApplied,
    Executed
} from "./GlauxStorage.sol";
import {SignatureVerify} from "./lib/SignatureVerify.sol";
import {ImplementationCheck} from "./lib/ImplementationCheck.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {IERC721Receiver} from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import {IERC1155Receiver} from "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";

/// @notice Glaux account logic. Reached only by delegatecall from GlauxDelegate.
contract GlauxAccount is IERC721Receiver, IERC1155Receiver {
    // Two 65-byte secp256k1 signatures encode as SlotSig[2] in 480 bytes, and the
    // deadline the factors signed rides in front of them. 576 bytes leaves room for the
    // added words plus one trailing one, while still bounding the self-call copy.
    uint256 internal constant MAX_USEROP_SIGNATURE_LENGTH = 576;

    address public immutable ENTRYPOINT;
    bool private transient executing;

    /// @dev Implementations are deployed at a deterministic CREATE2 address and are
    ///      immutable, so a wrong EntryPoint would be permanent at the canonical
    ///      address: reject the obvious deployment mistake at construction time.
    constructor(address entryPoint) {
        if (entryPoint == address(0)) revert ZeroEntryPoint();
        ENTRYPOINT = entryPoint;
        GlauxStorage.layout().initialized = true;
    }

    function initializeAccount(bytes calldata initData) external {
        GlauxStorage.Layout storage l = GlauxStorage.layout();
        if (l.initialized) revert AlreadyInitialized();
        bytes32 implementationSlot = GlauxStorage.IMPL_SLOT;
        address installed;
        assembly {
            installed := sload(implementationSlot)
        }
        if (installed != address(0)) revert AlreadyInitialized();
        (FactorSlot[3] memory slots, bytes[3] memory proofs) =
            abi.decode(initData, (FactorSlot[3], bytes[3]));
        for (uint8 i = 0; i < 3; i++) {
            _validateSlot(slots[i]);
            _requirePossession(i, slots[i], proofs[i]);
        }
        for (uint256 i = 0; i < 3; i++) {
            for (uint256 j = i + 1; j < 3; j++) {
                if (_isDuplicateSlot(slots[i], slots[j])) revert DuplicateSlot();
            }
        }
        for (uint256 i = 0; i < 3; i++) {
            l.slots[i] = slots[i];
        }
        l.initialized = true;
    }

    /// @dev The single choke point for installing a slot: birth and rotation both
    ///      reach it, so the two cannot drift apart — a divergence would be a hole in
    ///      whichever of them checks less.
    /// @dev The verifier probe runs only for P-256, and only after the cheap local
    ///      checks: a chain that cannot verify P-256 is not the reason a malformed key
    ///      is refused. Deliberately no probe for secp256k1 — `ecrecover` is in the
    ///      protocol on every EVM chain — so rotating a factor AWAY from P-256 stays
    ///      possible exactly where it is most needed, on the chain that lacks the
    ///      verifier.
    function _validateSlot(FactorSlot memory s) internal view {
        if (
            s.verifierType != GlauxStorage.VERIFIER_SECP256K1
                && s.verifierType != GlauxStorage.VERIFIER_P256
        ) {
            revert InvalidVerifierType();
        }
        if (!SignatureVerify.isValidKey(s.verifierType, s.data)) revert InvalidSlot();
        if (s.verifierType == GlauxStorage.VERIFIER_P256) {
            // The probe vector's private key is public, so its public key is nobody's
            // factor. A possession proof does not catch this: anyone can produce one.
            if (SignatureVerify.isProbeKey(s.data)) revert ProbeKeyNotInstallable();
            if (!SignatureVerify.p256VerifierAvailable()) revert P256VerifierUnavailable();
        }
    }

    /// @dev A slot's key must prove it EXISTS before it is installed. Shape checks
    ///      cannot do this: ECDSA verifies by recovery, so an adversary can pick a
    ///      signature first and derive the address it is valid under, yielding a
    ///      well-formed slot whose private key never existed and which only they can
    ///      sign for — enough, with two such slots, to meet the 2-of-3 threshold with
    ///      no keys at all. The challenge commits to the key material itself, so
    ///      deriving a key from a signature no longer helps: an attacker would need a
    ///      signature valid under a key that a digest committing to that same key
    ///      recovers to, which is a hash preimage search rather than a curve
    ///      computation.
    /// @dev Deliberately binds neither a chain id nor the account address. The proof
    ///      rides inside the birth blob and the update payload, both of which replay
    ///      on every chain; and a factor must be able to produce its proof BEFORE the
    ///      account exists — the paper factor is generated on an air-gapped machine
    ///      and never comes back online. That makes a proof a portable, reusable
    ///      artifact per key, which is harmless: it authorizes nothing. Installing
    ///      someone else's proven public key into your own account grants you no
    ///      ability to sign with it.
    /// @dev No EIP-191 prefix here for the same reason — there is no validator to
    ///      bind, and a possession proof confers no authority, so raw-hash exposure
    ///      buys an attacker nothing.
    function _requirePossession(uint8 index, FactorSlot memory s, bytes memory proof)
        internal
        view
    {
        bytes32 digest = keccak256(
            abi.encode(GlauxStorage.REG_DOMAIN, index, s.verifierType, keccak256(s.data))
        );
        if (!SignatureVerify.verify(s.verifierType, s.data, digest, proof)) {
            revert PossessionNotProven();
        }
    }

    function _isDuplicateSlot(FactorSlot memory a, FactorSlot memory b)
        internal
        pure
        returns (bool)
    {
        return a.verifierType == b.verifierType && keccak256(a.data) == keccak256(b.data);
    }

    function getSlot(uint8 index) external view returns (uint8, bytes memory) {
        if (index > 2) revert InvalidSlot();
        FactorSlot storage s = GlauxStorage.layout().slots[index];
        return (s.verifierType, s.data);
    }

    function updateNonce() external view returns (uint64) {
        return GlauxStorage.layout().updateNonce;
    }

    function execNonce() external view returns (uint64) {
        return GlauxStorage.layout().execNonce;
    }

    function glauxCompatibilityId() external pure returns (bytes32) {
        return GlauxStorage.COMPAT_ID;
    }

    /// @notice The installed implementation. Read this rather than the ERC-1967 slot:
    ///         Glaux deliberately does not write that shared slot, because an
    ///         EIP-7702 account can be re-delegated and a value left behind there
    ///         would be read as its own by whatever wallet comes next.
    function implementation() external view returns (address impl) {
        bytes32 slot = GlauxStorage.IMPL_SLOT;
        assembly {
            impl := sload(slot)
        }
    }

    function applyUpdate(Update calldata u, SlotSig[2] calldata sigs) external {
        GlauxStorage.Layout storage l = GlauxStorage.layout();
        if (!l.initialized) revert NotInitialized();
        if (u.nonce != l.updateNonce + 1) revert BadUpdateNonce(l.updateNonce + 1, u.nonce);
        bytes32 digest = GlauxStorage.eip191(
            address(this),
            keccak256(
                abi.encode(
                    GlauxStorage.UPDATE_DOMAIN,
                    address(this),
                    u.nonce,
                    u.action,
                    keccak256(u.payload)
                )
            )
        );
        _requireTwoSigs(digest, [sigs[0], sigs[1]]);
        l.updateNonce = u.nonce;

        if (u.action == GlauxStorage.ACTION_SET_SLOT) {
            (uint8 index, uint8 verifierType, bytes memory data, bytes memory proof) =
                abi.decode(u.payload, (uint8, uint8, bytes, bytes));
            if (index > 2) revert InvalidSlot();
            FactorSlot memory s = FactorSlot(verifierType, data);
            _validateSlot(s);
            _requirePossession(index, s, proof);
            for (uint8 i = 0; i < 3; i++) {
                if (i != index && _isDuplicateSlot(s, l.slots[i])) revert DuplicateSlot();
            }
            l.slots[index] = s;
        } else if (u.action == GlauxStorage.ACTION_SET_IMPLEMENTATION) {
            (address newImplementation, bytes32 expectedCodeHash) =
                abi.decode(u.payload, (address, bytes32));
            if (!ImplementationCheck.isInstallable(newImplementation, expectedCodeHash)) {
                revert InvalidImplementation();
            }
            bytes32 slot = GlauxStorage.IMPL_SLOT;
            assembly {
                sstore(slot, newImplementation)
            }
        } else {
            revert InvalidAction();
        }
        emit UpdateApplied(u.nonce, u.action);
    }

    function executeWithSigs(Call[] calldata calls, uint48 validUntil, SlotSig[2] calldata sigs)
        external
        payable
    {
        GlauxStorage.Layout storage l = GlauxStorage.layout();
        if (!l.initialized) revert NotInitialized();
        // Before the signature work: an operation that is dead on arrival should cost a
        // comparison, not two curve operations. `validUntil` is inside the digest below,
        // so a submitter cannot widen the window it was handed — changing the value
        // invalidates the signatures. Zero is a deadline in the past like any other; it
        // is never a licence to run forever.
        if (block.timestamp > validUntil) revert OperationExpired(validUntil, block.timestamp);
        bytes32 digest = GlauxStorage.eip191(
            address(this),
            keccak256(
                abi.encode(
                    GlauxStorage.EXEC_DOMAIN,
                    block.chainid,
                    address(this),
                    l.execNonce,
                    keccak256(abi.encode(calls)),
                    validUntil
                )
            )
        );
        _requireTwoSigs(digest, [sigs[0], sigs[1]]);
        uint64 nonce = l.execNonce + 1;
        l.execNonce = nonce;
        _execute(calls);
        emit Executed(nonce, calls.length);
    }

    /// @notice ERC-4337 entry point validation hook. Only ENTRYPOINT may call this.
    /// @dev userOp.signature is attacker-controlled and may be malformed; decoding is
    ///      done through a try/catch so garbage bytes yield SIG_VALIDATION_FAILED (1)
    ///      instead of a revert, which would be a worse failure mode for the bundler.
    /// @dev The deadline travels in the signature blob rather than in the operation,
    ///      because `userOpHash` is the EntryPoint's construction and cannot carry a
    ///      Glaux field. The factors therefore sign over `(userOpHash, validUntil)`: a
    ///      bundler that rewrites the window invalidates the signatures it was handed.
    ///      Enforcement is left to the EntryPoint, which is the point of reporting a
    ///      window at all — it drops an expired operation before execution rather than
    ///      landing a reverting one.
    /// @dev `validUntil == 0` is refused. The EntryPoint reads a zero as "no expiry",
    ///      so passing it through would reintroduce exactly the unbounded operation
    ///      this path is meant to stop; on the direct path zero is simply a deadline in
    ///      the past, and the two must not disagree about what zero means.
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external returns (uint256 validationData) {
        if (msg.sender != ENTRYPOINT) revert NotEntryPoint();
        (bool decoded, uint48 validUntil, SlotSig[2] memory sigs) = _tryDecodeSigs(userOp.signature);
        bytes32 digest = GlauxStorage.eip191(
            address(this), keccak256(abi.encode(GlauxStorage.USEROP_DOMAIN, userOpHash, validUntil))
        );
        validationData = (decoded && validUntil != 0 && _checkTwoSigs(digest, sigs))
            ? uint256(validUntil) << 160
            : 1;
        if (missingAccountFunds > 0) {
            (bool ok,) = msg.sender.call{value: missingAccountFunds}("");
            ok; // EntryPoint verifies the deposit; a failed prefund fails the op there
        }
    }

    /// @notice ERC-4337 execution hook, reached only from the EntryPoint after
    ///         validateUserOp succeeded. The EntryPoint owns replay protection through
    ///         its own per-account nonce, so this path does not touch execNonce.
    function executeFromEntryPoint(Call[] calldata calls) external {
        if (msg.sender != ENTRYPOINT) revert NotEntryPoint();
        _execute(calls);
        emit Executed(GlauxStorage.layout().execNonce, calls.length);
    }

    function _tryDecodeSigs(bytes calldata signature)
        internal
        view
        returns (bool ok, uint48 validUntil, SlotSig[2] memory sigs)
    {
        if (signature.length > MAX_USEROP_SIGNATURE_LENGTH) {
            return (false, 0, sigs);
        }
        try this.decodeSlotSigs(signature) returns (uint48 until, SlotSig[2] memory decoded) {
            return (true, until, decoded);
        } catch {
            return (false, 0, sigs);
        }
    }

    /// @notice Pure decode helper, external so `_tryDecodeSigs` can call it through a
    ///         try/catch and turn a malformed signature into a bool instead of a revert.
    function decodeSlotSigs(bytes calldata signature)
        external
        pure
        returns (uint48, SlotSig[2] memory)
    {
        return abi.decode(signature, (uint48, SlotSig[2]));
    }

    /// @dev Slither flags three patterns here that are the account's whole purpose:
    ///      `arbitrary-send-eth` — a smart account exists to send value to
    ///      destinations its owners chose, and every destination, value and calldata
    ///      below is bound into the digest the 2-of-3 quorum signed;
    ///      `calls-loop` — batching is a feature, and a failed call reverts the batch
    ///      rather than being skipped;
    ///      `reentrancy-eth` — the state written after the calls IS the reentrancy
    ///      guard being released; the flag is set before the loop and any re-entry
    ///      reverts `ReentrantCall()`.
    // slither-disable-next-line arbitrary-send-eth,calls-loop,reentrancy-eth
    function _execute(Call[] memory calls) internal {
        if (executing) revert ReentrantCall();
        executing = true;
        for (uint256 i = 0; i < calls.length; i++) {
            (bool ok, bytes memory ret) = calls[i].to.call{value: calls[i].value}(calls[i].data);
            if (!ok) revert CallFailed(i, ret);
        }
        executing = false;
    }

    /// @dev True when both signatures carry the same `(r, s)`. Both supported
    ///      encodings put `r || s` in the leading 64 bytes — secp256k1 is
    ///      `r || s || v` (65) and P-256 is `r || s` (64) — so comparing that
    ///      prefix catches the shared-signature case for either verifier, and
    ///      across them. Anything shorter than 64 bytes is malformed and will be
    ///      rejected by the verifier anyway.
    function _sameRS(bytes memory a, bytes memory b) internal pure returns (bool) {
        if (a.length < 64 || b.length < 64) return false;
        bytes32 ar;
        bytes32 as_;
        bytes32 br;
        bytes32 bs;
        assembly {
            ar := mload(add(a, 0x20))
            as_ := mload(add(a, 0x40))
            br := mload(add(b, 0x20))
            bs := mload(add(b, 0x40))
        }
        return ar == br && as_ == bs;
    }

    function _requireTwoSigs(bytes32 digest, SlotSig[2] memory sigs) internal view {
        if (!_checkTwoSigs(digest, sigs)) revert InvalidSignature();
    }

    function _checkTwoSigs(bytes32 digest, SlotSig[2] memory sigs) internal view returns (bool) {
        if (sigs[0].slotIndex > 2 || sigs[1].slotIndex > 2) return false;
        if (sigs[0].slotIndex == sigs[1].slotIndex) return false;
        // Distinct slots are not yet distinct CREDENTIALS. For a fixed digest,
        // one ECDSA signature (r, s) verifies against more than one public key --
        // for secp256k1, flipping `v` recovers a second, different address that
        // needs no private key at all. If both ended up registered, a single
        // keypair would satisfy the 2-of-3 threshold while every slot looked
        // distinct and well-formed. Two independent signers cannot collide on
        // (r, s) over the same digest, so requiring them to differ costs nothing.
        //
        // This closes signature REUSE only. The wider class — manufacturing a
        // signature and registering the address it recovers to, which yields two
        // different (r, s) — is closed at registration by `_requirePossession`.
        // With that in place this check is defence in depth rather than the
        // load-bearing control, and it costs nothing to keep.
        if (_sameRS(sigs[0].signature, sigs[1].signature)) return false;
        GlauxStorage.Layout storage l = GlauxStorage.layout();
        if (!l.initialized) return false;
        FactorSlot storage a = l.slots[sigs[0].slotIndex];
        FactorSlot storage b = l.slots[sigs[1].slotIndex];
        return SignatureVerify.verify(a.verifierType, a.data, digest, sigs[0].signature)
            && SignatureVerify.verify(b.verifierType, b.data, digest, sigs[1].signature);
    }

    /// @notice Checked-transfer hooks. Unconditional accept: which assets arrive is
    ///         not an authorization question, and taking the reentrancy guard here
    ///         would make receiving-while-executing impossible — the common case is
    ///         this account moving a token in a batch and the token calling back in.
    function onERC721Received(address, address, uint256, bytes calldata)
        external
        pure
        returns (bytes4)
    {
        return IERC721Receiver.onERC721Received.selector;
    }

    function onERC1155Received(address, address, uint256, uint256, bytes calldata)
        external
        pure
        returns (bytes4)
    {
        return IERC1155Receiver.onERC1155Received.selector;
    }

    function onERC1155BatchReceived(
        address,
        address,
        uint256[] calldata,
        uint256[] calldata,
        bytes calldata
    ) external pure returns (bytes4) {
        return IERC1155Receiver.onERC1155BatchReceived.selector;
    }

    /// @notice ERC-165. Advertises ERC-1271 too: not required by the standard, but
    ///         some integrations probe for it and advertising costs nothing.
    ///         (0x1626ba7e is a literal until the interface arrives with
    ///         `isValidSignature` itself.)
    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == type(IERC165).interfaceId
            || interfaceId == type(IERC721Receiver).interfaceId
            || interfaceId == type(IERC1155Receiver).interfaceId
            || interfaceId == bytes4(0x1626ba7e);
    }
}
