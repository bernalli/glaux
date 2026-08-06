import { describe, expect, it } from "vitest";
import type { Address, Hex, PublicClient } from "viem";
import { signAuthorization } from "viem/accounts";
import { recoverAuthorizationAddress } from "viem/utils";
import { craftRootlessAuthorization } from "../src/birth/blob.js";
import { preflightFreshAccount } from "../src/birth/preflight.js";
import { submitBirth } from "../src/birth/submit.js";
import { IMPL, IMPL_CODE_HASH, ROUTER } from "../src/core/constants.js";
import { initDigest } from "../src/core/digests.js";
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

/**
 * A blob that is internally COHERENT: the account, salt and authorization are
 * the real derivation for this init data. A hand-written one is now refused
 * before any RPC call — `submitBirth` re-runs the router's authentication
 * locally — so a stale literal here would test the refusal instead of whatever
 * each case is about.
 */
const CRAFTED = craftRootlessAuthorization(initDigest(ROUTER, IMPL, IMPL_CODE_HASH, "0x"));

const BLOB: BirthBlob = {
  account: CRAFTED.account,
  router: ROUTER,
  implementation: IMPL,
  expectedCodeHash: IMPL_CODE_HASH,
  authorization: {
    chainId: 0,
    address: ROUTER,
    nonce: 0,
    yParity: CRAFTED.yParity,
    r: CRAFTED.r,
    s: CRAFTED.s,
  },
  initData: "0x",
  salt: CRAFTED.salt,
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

it("rejects an authorization whose nonce is not zero before preflight", async () => {
  // A retained birth blob is replayable on every chain not yet reached only
  // while its authorization names nonce 0: EIP-7702 checks the tuple's nonce
  // against the authority's CURRENT account nonce, and a crafted authority can
  // never send a transaction of its own, so its nonce is 0 wherever the blob
  // has not landed and 1 wherever it has. A tuple naming N > 0 is usable
  // nowhere. The canonical builder writes 0 (`src/birth/blob.ts`); an imported
  // blob has to be checked.
  const signed = await signAuthorization({
    privateKey: RELAYER,
    address: BLOB.router,
    chainId: 0,
    nonce: 7,
  });
  const { yParity } = signed;
  if (yParity === undefined) throw new Error("viem returned an unsigned authorization");
  const authorization = {
    chainId: signed.chainId,
    address: BLOB.router,
    nonce: signed.nonce,
    yParity,
    r: signed.r,
    s: signed.s,
  };
  // The tuple is well formed and recovers cleanly -- canonical router as
  // target, chain id 0 -- so the nonce is what refuses it. It recovers to an
  // ordinary key's address rather than to `BLOB.account`, and deliberately so:
  // the nonce gate runs before the authority is compared to the blob's
  // account, which is what this test pins.
  expect(await recoverAuthorizationAddress({ authorization })).toBe(ACCOUNT);

  let preflightRead = false;
  const client = {
    getChainId: async () => 31337,
    request: async () => {
      preflightRead = true;
      return "0x";
    },
  } as unknown as PublicClient;

  await expect(submitBirth(client, RELAYER, { ...BLOB, authorization }, 31337)).rejects.toMatchObject({
    name: "InvalidBirthBlobError",
    field: "authorization nonce",
  } satisfies Partial<InvalidBirthBlobError>);
  expect(preflightRead).toBe(false);
});

/**
 * The three checks below are the router's own authentication, re-run locally.
 * Without them a blob that is merely self-consistent — its `account` really is
 * what its tuple recovers to — passes every earlier check, is broadcast, and
 * installs an EIP-7702 designator on an address the router then refuses. That
 * address has no key, so nothing can ever be corrected there.
 */
it("rejects an authorization whose r does not bind the initialization fields", async () => {
  let preflightRead = false;
  const client = {
    getChainId: async () => 31337,
    request: async () => {
      preflightRead = true;
      return "0x";
    },
  } as unknown as PublicClient;

  // A complete, internally coherent proof — crafted for a DIFFERENT init data.
  // Presented against this blob's fields it stays self-consistent (it recovers
  // to the account it names), so only recomputing r from the configuration
  // catches it. This is the realistic shape: a tuple valid for one birth,
  // submitted for another.
  const foreign = craftRootlessAuthorization(initDigest(ROUTER, IMPL, IMPL_CODE_HASH, "0xdead"));
  await expect(
    submitBirth(
      client,
      RELAYER,
      {
        ...BLOB,
        account: foreign.account,
        authorization: { ...BLOB.authorization, r: foreign.r, s: foreign.s, yParity: foreign.yParity },
      },
      31337,
    ),
  ).rejects.toMatchObject({
    name: "InvalidBirthBlobError",
    field: "authorization r",
  } satisfies Partial<InvalidBirthBlobError>);
  expect(preflightRead).toBe(false);
});

it("rejects an authorization with parity 1, which the router can never accept", async () => {
  let preflightRead = false;
  const client = {
    getChainId: async () => 31337,
    request: async () => {
      preflightRead = true;
      return "0x";
    },
  } as unknown as PublicClient;

  // `GlauxDelegate.initialize` recovers with a fixed v = 27. A parity-1 tuple
  // is a real tuple for a real address — just never the one the router derives.
  const parityOne = { ...BLOB.authorization, yParity: 1 };
  const account = await recoverAuthorizationAddress({ authorization: parityOne });
  await expect(
    submitBirth(client, RELAYER, { ...BLOB, account, authorization: parityOne }, 31337),
  ).rejects.toMatchObject({
    name: "InvalidBirthBlobError",
    field: "authorization parity",
  } satisfies Partial<InvalidBirthBlobError>);
  expect(preflightRead).toBe(false);
});

it("rejects a tuple whose s carries no rootless tag", async () => {
  let preflightRead = false;
  const client = {
    getChainId: async () => 31337,
    request: async () => {
      preflightRead = true;
      return "0x";
    },
  } as unknown as PublicClient;

  // Same r, so the binding check passes and this isolates the tag alone: strip
  // the 13-byte marker and keep the tail. Whatever that recovers to becomes the
  // account, so the blob stays self-consistent — which is the point. Only the
  // tag distinguishes a crafted tuple from one a key could have produced.
  const untagged = `0x00${BLOB.authorization.s.slice(4)}` as Hex;
  const authorization = { ...BLOB.authorization, s: untagged };
  const account = await recoverAuthorizationAddress({ authorization });
  await expect(
    submitBirth(client, RELAYER, { ...BLOB, account, authorization }, 31337),
  ).rejects.toMatchObject({
    name: "InvalidBirthBlobError",
    field: "authorization rootless proof",
  } satisfies Partial<InvalidBirthBlobError>);
  expect(preflightRead).toBe(false);
});
