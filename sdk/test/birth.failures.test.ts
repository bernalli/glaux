import { describe, expect, it } from "vitest";
import type { Address, Hex, PublicClient } from "viem";
import { preflightFreshAccount } from "../src/birth/preflight.js";
import { submitBirth } from "../src/birth/submit.js";
import { IMPL_CODE_HASH } from "../src/core/constants.js";
import type { BirthBlob } from "../src/core/types.js";
import {
  BirthGasEstimationError,
  BirthPreflightReadError,
  ChainIdMismatchError,
  InvalidBirthBlobError,
} from "../src/errors.js";

const ACCOUNT = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266" as Address;
const ZERO_WORD = `0x${"00".repeat(32)}` as Hex;
const RELAYER = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" as Hex;

const BLOB: BirthBlob = {
  account: ACCOUNT,
  router: "0xB8270e4B9aaeA6933716409Bb648FB3Cda3CCbE9",
  implementation: "0x21b5D576AB4188Ee06DD866b6Fd4a23085A73f5d",
  expectedCodeHash: IMPL_CODE_HASH,
  authorization: {
    chainId: 0,
    address: "0xB8270e4B9aaeA6933716409Bb648FB3Cda3CCbE9",
    nonce: 0,
    yParity: 0,
    r: "0xd85ba67a8ce9cd387b44acf700176415ced15a38159594775e25cbcbfb46a0be",
    s: "0x195da6c632682dc5cbefb7b35315f857e347708a97f2d85ebba264969783728e",
  },
  initData: "0x",
  birthSig: "0x",
};

describe("birth preflight unread RPC responses", () => {
  it.each([undefined, null, "0x0"])("fails closed for a %p code response", async (response) => {
    const client = {
      request: async () => response,
    } as unknown as PublicClient;

    await expect(preflightFreshAccount(client, ACCOUNT)).rejects.toMatchObject({
      name: "BirthPreflightReadError",
      target: "code",
    } satisfies Partial<BirthPreflightReadError>);
  });

  it.each(Array.from({ length: 8 }, (_, index) => index))(
    "fails closed when storage read %i is undefined",
    async (unreadRead) => {
      let storageReads = 0;
      const client = {
        request: async ({ method }: { method: string }) =>
          method === "eth_getCode" ? "0x" : storageReads++ === unreadRead ? undefined : ZERO_WORD,
      } as unknown as PublicClient;

      await expect(preflightFreshAccount(client, ACCOUNT)).rejects.toMatchObject({
        name: "BirthPreflightReadError",
        target: "storage",
      } satisfies Partial<BirthPreflightReadError>);
    },
  );

  it.each([null, "0x"])("fails closed for a malformed storage response %p", async (response) => {
    const client = {
      request: async ({ method }: { method: string }) => (method === "eth_getCode" ? "0x" : response),
    } as unknown as PublicClient;

    await expect(preflightFreshAccount(client, ACCOUNT)).rejects.toMatchObject({
      name: "BirthPreflightReadError",
      target: "storage",
    } satisfies Partial<BirthPreflightReadError>);
  });
});

it("refuses to broadcast when authorization-aware gas estimation fails", async () => {
  const client = {
    request: async ({ method }: { method: string }) => (method === "eth_getCode" ? "0x" : ZERO_WORD),
    getChainId: async () => 31337,
    getTransactionCount: async () => 0,
    getBlock: async () => ({ baseFeePerGas: 1n }),
    getGasPrice: async () => 1n,
    estimateMaxPriorityFeePerGas: async () => 1n,
    estimateGas: async (request: { authorizationList?: readonly unknown[] }) => {
      expect(request.authorizationList).toHaveLength(1);
      throw new Error("node refuses pre-delegation estimate");
    },
  } as unknown as PublicClient;

  await expect(submitBirth(client, RELAYER, BLOB, 31337)).rejects.toThrow(BirthGasEstimationError);
});

it("refuses a submit endpoint that disagrees with the caller-selected chain before any other birth action", async () => {
  let otherAction = false;
  const client = {
    getChainId: async () => 31338,
    request: async () => {
      otherAction = true;
      return "0x";
    },
  } as unknown as PublicClient;

  await expect(submitBirth(client, RELAYER, BLOB, 31337)).rejects.toBeInstanceOf(ChainIdMismatchError);
  expect(otherAction).toBe(false);
});

it("rejects an authorization whose recovered signer is not blob.account before preflight", async () => {
  let preflightRead = false;
  const client = {
    getChainId: async () => 31337,
    request: async () => {
      preflightRead = true;
      return "0x";
    },
  } as unknown as PublicClient;

  await expect(
    submitBirth(client, RELAYER, { ...BLOB, account: "0x1111111111111111111111111111111111111111" }, 31337),
  ).rejects.toMatchObject({
    name: "InvalidBirthBlobError",
    field: "authorization signer",
  } satisfies Partial<InvalidBirthBlobError>);
  expect(preflightRead).toBe(false);
});

it("rejects a chain-specific authorization before preflight", async () => {
  let preflightRead = false;
  const client = {
    getChainId: async () => 31337,
    request: async () => {
      preflightRead = true;
      return "0x";
    },
  } as unknown as PublicClient;

  await expect(
    submitBirth(
      client,
      RELAYER,
      { ...BLOB, authorization: { ...BLOB.authorization, chainId: 31337 } },
      31337,
    ),
  ).rejects.toMatchObject({
    name: "InvalidBirthBlobError",
    field: "authorization chain id",
  } satisfies Partial<InvalidBirthBlobError>);
  expect(preflightRead).toBe(false);
});
