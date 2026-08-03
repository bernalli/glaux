import { concat, keccak256, type Address, type Hex } from "viem";

export { DOMAINS } from "./constants.js";

/**
 * EIP-191 personal-sign-style digest used by Glaux's v0 signature scheme:
 * `keccak256(0x19 || 0x00 || validator || structHash)`.
 */
export function eip191v0(validator: Address, structHash: Hex): Hex {
  return keccak256(concat(["0x1900", validator, structHash]));
}
