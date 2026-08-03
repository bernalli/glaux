import { concat, keccak256, stringToBytes, type Address, type Hex } from "viem";

/** Immutable half of the Glaux EIP-7702 delegation: the router target. */
export const ROUTER: Address = "0xB8270e4B9aaeA6933716409Bb648FB3Cda3CCbE9";

/** Post-audit implementation address behind the router. */
export const IMPL: Address = "0x21b5D576AB4188Ee06DD866b6Fd4a23085A73f5d";

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
