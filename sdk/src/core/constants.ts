import { concat, keccak256, stringToBytes, type Address, type Hex } from "viem";

/** Immutable half of the Glaux EIP-7702 delegation: the router target. */
export const ROUTER: Address = "0x3ccF1cc0F702C084B31e691e057d8742ADF35790";

/** Post-audit implementation address behind the router. */
export const IMPL: Address = "0x21b5D576AB4188Ee06DD866b6Fd4a23085A73f5d";

/** Runtime-code hash of the canonical implementation at {@link IMPL}. */
export const IMPL_CODE_HASH: Hex = "0xb32d638ed9bd6329b5b2f27e9dcaa3a9fc65f396315f67eef276cd6f89ac9106";

/**
 * The 13-byte tag every rootless authorization's `s` carries, mirroring
 * `GlauxDelegate.ROOTLESS_S_PREFIX`. Its leading byte keeps `s` below
 * `secp256k1n/2` for any tail, which EIP-7702 requires of the tuple.
 */
export const ROOTLESS_S_PREFIX = 0x476c6175785f524f4f544c4553n;

/**
 * `keccak256(0x05 ‖ rlp([chainId 0, ROUTER, nonce 0]))` — the message an
 * EIP-7702 authorization naming the canonical router is signed over, and the
 * hash a crafted proof must recover the account from. The RLP of that tuple is
 * `0xd7 0x80 0x94 ‖ address ‖ 0x80`: list header for 23 bytes, zero chain id,
 * the 20-byte address, zero nonce.
 */
export const AUTH_MSG_HASH: Hex = keccak256(concat(["0x05d78094", ROUTER, "0x80"]));

/** Canonical CREATE2 deployer used for deterministic deployment. */
export const CREATE2_DEPLOYER: Address = "0x4e59b44847b379578588920cA78FbF26c0B4956C";

/** ERC-4337 EntryPoint v0.7. */
export const ENTRYPOINT: Address = "0x0000000071727De22E5E9d8BAf0edAc6f37da032";

/** CREATE2 salt: keccak256("glaux.v1"). */
export const SALT: Hex = keccak256(stringToBytes("glaux.v1"));

/**
 * Domain separators, mirroring the `bytes32` constants in
 * `src/GlauxStorage.sol` (keccak256 of the literal tag strings).
 */
export const DOMAINS = {
  INIT: keccak256(stringToBytes("GLAUX_INIT_V1")),
  UPDATE: keccak256(stringToBytes("GLAUX_UPDATE_V1")),
  EXEC: keccak256(stringToBytes("GLAUX_EXEC_V1")),
  USEROP: keccak256(stringToBytes("GLAUX_USEROP_V1")),
  REG: keccak256(stringToBytes("GLAUX_REG_V1")),
  MSG: keccak256(stringToBytes("GLAUX_MSG_V1")),
} as const satisfies Record<string, Hex>;

/**
 * EIP-7702 delegation designator: `0xef0100` concatenated with the router
 * address that the delegated EOA points at.
 */
export function designator(): Hex {
  return concat(["0xef0100", ROUTER]).toLowerCase() as Hex;
}
