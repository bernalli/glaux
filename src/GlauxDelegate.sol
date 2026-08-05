// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {
    GlauxStorage,
    AlreadyInitialized,
    NotInitialized,
    InvalidImplementation,
    InvalidBirthProof,
    ReentrantCall,
    Initialized
} from "./GlauxStorage.sol";
import {ImplementationCheck} from "./lib/ImplementationCheck.sol";

/// @notice Immutable EIP-7702 delegation target. Frozen forever: keep minimal.
/// @dev Aderyn reports an Ether lock here. Under delegation `receive()` runs with
///      `address(this)` set to the ACCOUNT, so ETH accrues to the account and is
///      spendable through the 2-of-3 path; dropping it would send plain transfers
///      into `fallback()` on a 2300-gas stipend. Only ETH sent directly to the
///      router's own address is stuck, and a withdraw function on a contract that
///      is frozen forever would be the worse trade. See docs/static-analysis.md.
// aderyn-fp-next-line
contract GlauxDelegate {
    /// @dev The router's own address, captured at construction — inside `initialize`
    ///      `address(this)` is the ACCOUNT, because the router is reached through the
    ///      account's EIP-7702 delegation. Deterministic deployment puts the same
    ///      value on every chain, so binding it costs nothing in replayability.
    address private immutable SELF = address(this);

    /// @dev The 13-byte tag every rootless `s` carries. It is NOT what makes
    ///      birth safe — recomputing `r` and requiring the recovery to be this
    ///      account is — and it should not be read as such: with `r` fixed to a
    ///      hash, landing on a chosen address by varying `s` is a 2^160 search
    ///      either way. What the tag adds is that rootlessness is observable
    ///      from the tuple ALONE, by anyone who never saw the birth
    ///      configuration: no real signer can place 13 chosen bytes in `s`
    ///      (~2^103 work), so a tagged authorization cannot have come from a
    ///      key. It also keeps `s` below `secp256k1n/2` for every tail, which
    ///      EIP-2 requires of the tuple.
    bytes13 public constant ROOTLESS_S_PREFIX = 0x476c6175785f524f4f544c4553;

    /// @dev The recovery id every crafted authorization uses. Not an argument:
    ///      whenever `r` is a valid curve x-coordinate, 27 recovers an address,
    ///      and when it is not, no `v` does — so the caller has nothing to
    ///      choose here, and an immutable contract is better off without an
    ///      input it would only have to validate.
    uint8 private constant ROOTLESS_V = 27;

    /// @dev `keccak256(0x05 ‖ rlp([chainId 0, SELF, nonce 0]))`: the message an
    ///      EIP-7702 authorization tuple naming this router is signed over.
    ///      Fixed at construction because the router's own address is inside
    ///      it. `0x05d78094` is the magic byte, the 23-byte list header, the
    ///      zero chain id and the 20-byte address prefix; the trailing `0x80`
    ///      is the zero nonce. Verified against a real signed authorization,
    ///      not derived on paper.
    bytes32 public immutable AUTH_MSG_HASH;

    constructor() {
        AUTH_MSG_HASH = keccak256(abi.encodePacked(hex"05d78094", address(this), hex"80"));
    }

    /// @notice One-time initialization, authenticated by the account's own
    ///         delegation tuple rather than by a key.
    /// @dev No birth key exists, and none ever did. The authorization that put
    ///      this router at `address(this)` carries an `r` that is a hash
    ///      commitment to exactly this birth configuration and an `s` bearing a
    ///      fixed 13-byte tag: recomputing `r` here and recovering the signer
    ///      proves the account address was DERIVED from the configuration
    ///      instead of chosen. Producing such a signature with a real key would
    ///      require a nonce `k` with `x(kG) = r`, which is the discrete-log
    ///      problem — so there is no private key for this address to survive
    ///      birth, be stolen, or bypass the 2-of-3 threshold later.
    /// @dev The digest still contains no chain-id: the same blob replays on
    ///      every chain, and submitting stays permissionless.
    /// @param salt The crafting nonce that made `r` land on the curve; it binds
    ///        nothing on its own, and is only an argument because `r` is not
    ///        recoverable from the account address alone.
    /// @param s The crafted `s` word of the authorization signature.
    function initialize(
        address implementation,
        bytes32 expectedCodeHash,
        bytes calldata initData,
        bytes32 salt,
        uint256 s
    ) external {
        // Guards the window in which the untrusted initializer runs. The pointer is
        // only written after the delegatecall returns, so without this a re-entrant
        // `initialize` would still see an unset pointer and could splice two
        // independently signed birth blobs — implementation from one, factor
        // configuration from the other. The shipped implementation happens to prevent
        // that by setting `initialized` before returning, but that is a convention of
        // replaceable code and this contract is permanent.
        //
        // Held in a NAMESPACED transient slot: Solidity would place a `transient`
        // state variable at transient slot 0, which the implementation's own first
        // transient variable also occupies, since both run with `address(this)` set
        // to the account. The router must not squat a slot it does not own.
        bytes32 guard = GlauxStorage.DELEGATE_BIRTH_GUARD_SLOT;
        uint256 busy;
        assembly {
            busy := tload(guard)
        }
        if (busy != 0) revert ReentrantCall();
        assembly {
            tstore(guard, 1)
        }

        bytes32 slot = GlauxStorage.IMPL_SLOT;
        address current;
        assembly {
            current := sload(slot)
        }
        if (current != address(0)) revert AlreadyInitialized();

        bytes32 digest = GlauxStorage.eip191(
            SELF,
            keccak256(
                abi.encode(
                    GlauxStorage.INIT_DOMAIN, implementation, expectedCodeHash, keccak256(initData)
                )
            )
        );
        // `r` is recomputed here, never accepted: that is what ties the account
        // address to THIS implementation, code hash and factor set. A caller
        // who alters any of them changes the digest, hence `r`, hence the
        // address the signature recovers to — which is no longer this account.
        if (bytes13(bytes32(s)) != ROOTLESS_S_PREFIX) revert InvalidBirthProof();
        address recovered =
            ecrecover(AUTH_MSG_HASH, ROOTLESS_V, keccak256(abi.encode(digest, salt)), bytes32(s));
        if (recovered == address(0) || recovered != address(this)) revert InvalidBirthProof();

        if (!ImplementationCheck.isInstallable(implementation, expectedCodeHash)) {
            revert InvalidImplementation();
        }

        // Delegatecall to a signed target is what a proxy IS. The function id is a
        // hardcoded literal, not input; the target is bound by the birth proof
        // and by the code-hash and marker checks immediately above.
        // slither-disable-next-line controlled-delegatecall
        (bool ok, bytes memory ret) = implementation.delegatecall(
            abi.encodeWithSignature("initializeAccount(bytes)", initData)
        );
        if (!ok) {
            assembly {
                revert(add(ret, 0x20), mload(ret))
            }
        }
        if (!GlauxStorage.layout().initialized) revert NotInitialized();
        assembly {
            sstore(slot, implementation)
            tstore(guard, 0)
        }
        emit Initialized(implementation);
    }

    fallback() external payable {
        bytes32 slot = GlauxStorage.IMPL_SLOT;
        assembly {
            let impl := sload(slot)
            if iszero(impl) {
                mstore(0x00, 0x87138d5c)
                revert(0x1c, 0x04)
            }
            calldatacopy(0, 0, calldatasize())
            let ok := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch ok
            case 0 { revert(0, returndatasize()) }
            // Forwarding the delegatecall's raw returndata and halting IS the proxy
            // idiom; "nothing executes after it" is the intended semantics, and
            // there is nothing after it. High-level Solidity cannot express this
            // without corrupting the returned data.
            // aderyn-fp-next-line
            default { return(0, returndatasize()) }
        }
    }

    receive() external payable {}
}
