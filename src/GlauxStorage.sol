// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

struct FactorSlot {
    uint8 verifierType; // 1 = secp256k1, 2 = P-256 raw. 0 = invalid forever.
    bytes data; // type 1: abi.encode(address). type 2: abi.encode(uint256 qx, uint256 qy).
}

struct SlotSig {
    uint8 slotIndex; // 0..2
    bytes signature; // type 1: 65-byte r||s||v. type 2: abi.encode(uint256 r, uint256 s).
}

struct Update {
    uint64 nonce; // strictly monotonic per account, starts at 1 (init is 0)
    uint8 action; // 0 = SetSlot, 1 = SetImplementation
    bytes payload;
}

struct Call {
    address to;
    uint256 value;
    bytes data;
}

library GlauxStorage {
    // keccak256("glaux.account.v1.storage")
    bytes32 internal constant SLOT = keccak256("glaux.account.v1.storage");
    /// @dev The AUTHORITATIVE implementation pointer. Deliberately namespaced and
    ///      NOT the ERC-1967 slot: an EIP-7702 re-delegation does not clear storage,
    ///      so an EOA migrating to Glaux from any wallet built on the ordinary
    ///      ERC-1967 proxy pattern arrives with that shared slot already occupied.
    ///      Reading a slot Glaux does not own would let a stale foreign pointer both
    ///      block birth forever and be executed by the router's own fallback.
    bytes32 internal constant IMPL_SLOT = keccak256("glaux.account.v1.implementation");
    /// @dev TRANSIENT slot reserved by the immutable router for its birth guard, and
    ///      declared here so the reservation is visible to every implementation.
    ///      Solidity assigns `transient` variables sequentially from slot 0 per
    ///      contract, but the router and the implementation both execute with
    ///      `address(this)` set to the account — so the router's guard and an
    ///      implementation's first transient variable would occupy the same location.
    ///      Namespacing it keeps the router out of a space it does not own, exactly as
    ///      IMPL_SLOT does for persistent storage.
    bytes32 internal constant DELEGATE_BIRTH_GUARD_SLOT =
        keccak256("glaux.delegate.v1.initializing");
    /// @dev ERC-1967: bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1).
    ///      Declared to name what Glaux deliberately does NOT touch. It is never read
    ///      and never written: an EIP-7702 account can be re-delegated at any time, so
    ///      a value Glaux left in this shared slot would be picked up as its own by
    ///      whatever wallet the account moves to next — the same hazard, pointed
    ///      outward. Tooling should call `GlauxAccount.implementation()` instead.
    bytes32 internal constant ERC1967_IMPL_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    bytes32 internal constant INIT_DOMAIN = keccak256("GLAUX_INIT_V1");
    bytes32 internal constant UPDATE_DOMAIN = keccak256("GLAUX_UPDATE_V1");
    bytes32 internal constant EXEC_DOMAIN = keccak256("GLAUX_EXEC_V1");
    /// @dev Domain for the ERC-4337 path. The EntryPoint computes `userOpHash` and it
    ///      cannot carry a Glaux field, so the deadline the factors agree to has to be
    ///      signed alongside it — see `GlauxAccount.validateUserOp`.
    bytes32 internal constant USEROP_DOMAIN = keccak256("GLAUX_USEROP_V1");
    /// @dev Domain for the possession proof a key must produce before it can be
    ///      installed into a factor slot. See `GlauxAccount._requirePossession`.
    bytes32 internal constant REG_DOMAIN = keccak256("GLAUX_REG_V1");
    /// @dev Domain for ERC-1271 message signatures. The only Glaux digest that binds
    ///      `block.chainid`: birth and update blobs must replay on every chain, but a
    ///      message signature is consumed by a protocol that already lives at one
    ///      address on one chain — and the account holds the SAME address everywhere,
    ///      so an unbound signature would authorize the identical action on every
    ///      chain at once. See `GlauxAccount.isValidSignature`.
    bytes32 internal constant MSG_DOMAIN = keccak256("GLAUX_MSG_V1");

    /// @notice Wraps a structured hash as EIP-191 version `0x00` signed data:
    ///         `0x19 ‖ 0x00 ‖ validator ‖ structHash`.
    /// @dev Two reasons this exists. It makes a Glaux digest unreachable through
    ///      raw-hash signing APIs (`eth_sign` and friends): without the prefix, any
    ///      factor key that can be induced to sign a bare 32-byte value produces a
    ///      valid Glaux signature, which matters most on the migration path where a
    ///      birth key is a long-lived user key. And it binds the validating contract
    ///      into every digest. Version `0x00` is used deliberately over EIP-712:
    ///      it carries no `chainId` field, so birth and update blobs keep replaying
    ///      on every chain, which is the whole design.
    function eip191(address validator, bytes32 structHash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(hex"19", hex"00", validator, structHash));
    }
    bytes32 internal constant COMPAT_ID = keccak256("GLAUX_ACCOUNT_V1");

    uint8 internal constant VERIFIER_SECP256K1 = 1;
    uint8 internal constant VERIFIER_P256 = 2;
    uint8 internal constant ACTION_SET_SLOT = 0;
    uint8 internal constant ACTION_SET_IMPLEMENTATION = 1;

    struct Layout {
        bool initialized;
        uint64 updateNonce;
        uint64 execNonce;
        FactorSlot[3] slots;
    }

    function layout() internal pure returns (Layout storage l) {
        bytes32 slot = SLOT;
        assembly {
            l.slot := slot
        }
    }
}

error AlreadyInitialized();
error NotInitialized();
error InvalidImplementation();
error InvalidBirthSignature();
error BadUpdateNonce(uint64 expected, uint64 got);
error DuplicateSlot();
error InvalidSignature();
error InvalidSlot();
error PossessionNotProven();
error P256VerifierUnavailable();
error ProbeKeyNotInstallable();
error InvalidVerifierType();
error InvalidAction();
error NotEntryPoint();
error ZeroEntryPoint();
error ReentrantCall();
error OperationExpired(uint48 validUntil, uint256 blockTimestamp);
error CallFailed(uint256 index, bytes revertData);

event Initialized(address implementation);
event UpdateApplied(uint64 nonce, uint8 action);
event Executed(uint64 execNonce, uint256 numCalls);
