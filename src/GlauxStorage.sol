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
    // ERC-1967: bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1).
    // Written as a MIRROR for explorer tooling only; never read as authoritative.
    bytes32 internal constant ERC1967_IMPL_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    bytes32 internal constant INIT_DOMAIN = keccak256("GLAUX_INIT_V1");
    bytes32 internal constant UPDATE_DOMAIN = keccak256("GLAUX_UPDATE_V1");
    bytes32 internal constant EXEC_DOMAIN = keccak256("GLAUX_EXEC_V1");
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
error InvalidVerifierType();
error InvalidAction();
error NotEntryPoint();
error ZeroEntryPoint();
error ReentrantCall();
error CallFailed(uint256 index, bytes revertData);

event Initialized(address implementation);
event UpdateApplied(uint64 nonce, uint8 action);
event Executed(uint64 execNonce, uint256 numCalls);
