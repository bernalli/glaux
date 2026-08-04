import { describe, expect, it } from "vitest";
import { type Hex, toHex } from "viem";
import { buildBirthBlob } from "../src/birth/blob.js";
import {
  DuplicateBirthSlotError,
  InvalidBirthSlotError,
  InvalidBirthVerifierTypeError,
  ProbeKeyNotInstallableError,
} from "../src/errors.js";
import { LocalP256Signer } from "../src/signers/p256.js";
import { LocalSecp256k1Signer } from "../src/signers/secp256k1.js";
import type { Signer } from "../src/signers/signer.js";
import fixtures from "../../test/fixtures/sdk_parity.json" with { type: "json" };

const PAPER_PK: Hex = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const CLOUD_PK: Hex = "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a";
const DEVICE_PK: Hex = "0x7459e13afd9158a379ee75ca9e80a328916dba1473c863f800f51ee5f46eb3ab";
const NEVER_CONTACTED_RPC = "http://127.0.0.1:1";

function factors(): [LocalSecp256k1Signer, LocalP256Signer, LocalSecp256k1Signer] {
  return [new LocalSecp256k1Signer(PAPER_PK), new LocalP256Signer(DEVICE_PK), new LocalSecp256k1Signer(CLOUD_PK)];
}

describe("buildBirthBlob local contract preconditions", () => {
  it("rejects duplicate slots before contacting an RPC or generating a birth artifact", async () => {
    const [paper, device] = factors();
    await expect(buildBirthBlob({ factors: [paper, device, paper], chainRpc: NEVER_CONTACTED_RPC })).rejects.toBeInstanceOf(
      DuplicateBirthSlotError,
    );
  });

  it("rejects key material that SignatureVerify.isValidKey will reject", async () => {
    const [, device, cloud] = factors();
    const invalid: Signer = {
      verifierType: 1,
      keyData: () => toHex(0n, { size: 32 }),
      sign: async () => "0x" as Hex,
    };
    await expect(buildBirthBlob({ factors: [invalid, device, cloud], chainRpc: NEVER_CONTACTED_RPC })).rejects.toBeInstanceOf(
      InvalidBirthSlotError,
    );
  });

  it("rejects the public P-256 verifier probe key before a signer is asked to sign", async () => {
    const [paper, , cloud] = factors();
    let signingRequested = false;
    const probe: Signer = {
      verifierType: 2,
      keyData: () =>
        `0x${(fixtures.p256Probe.qx as Hex).slice(2)}${(fixtures.p256Probe.qy as Hex).slice(2)}` as Hex,
      sign: async () => {
        signingRequested = true;
        return "0x" as Hex;
      },
    };
    await expect(buildBirthBlob({ factors: [paper, probe, cloud], chainRpc: NEVER_CONTACTED_RPC })).rejects.toBeInstanceOf(
      ProbeKeyNotInstallableError,
    );
    expect(signingRequested).toBe(false);
  });

  it("rejects an unsupported verifier type before a birth key exists", async () => {
    const [, device, cloud] = factors();
    const unsupported = {
      verifierType: 99,
      keyData: () => toHex(1n, { size: 32 }),
      sign: async () => "0x" as Hex,
    } as unknown as Signer;
    await expect(buildBirthBlob({ factors: [unsupported, device, cloud], chainRpc: NEVER_CONTACTED_RPC })).rejects.toBeInstanceOf(
      InvalidBirthVerifierTypeError,
    );
  });
});
