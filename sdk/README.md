# @glaux/sdk

TypeScript client SDK for the Glaux EIP-7702 smart account: birth, direct
execution, self-funded ERC-4337, ERC-7677 gas sponsorship, chain-eligibility
checks, and cross-chain reconciliation. It is the executable counterpart of
[`docs/client-guidance.md`](../docs/client-guidance.md), the normative
integration document — read that alongside this file before wiring the SDK
into a wallet.

> **Status: unaudited reference implementation.** Nothing in this repository
> has been audited. **Do not use with real funds.**

This package is not yet published (`"private": true` in `package.json`); it
is consumed from within this repository via relative imports (see the
Quickstart). Node.js >= 20.19.

## Two facts to read before anything else

### The frozen-funds hazard — `checkChain` is a safety gate, not a nicety

Glaux's account address is an ordinary EOA that has been delegated via
EIP-7702 to the Glaux router; the private key that produced that delegation
(the "birth key") is discarded the moment birth succeeds. That address is
identical on every EVM chain by construction — nothing about Glaux prevents
someone from sending funds to it on a chain where the account has never been
born.

If that happens, the funds are **frozen**: there is no key left to move
them, and the account cannot execute anything until it is born on that exact
chain. Birth itself needs two things the chain must already support — EIP-7702
(the delegation itself) and a working P-256 verifier at `0x100`
(RIP-7212/EIP-7951, the primary factor) — and neither can be worked around
client-side. On a chain missing either one, the funds stay frozen until the
chain upgrades, on a timeline the integrator does not control.

`checkChain` (`src/eligibility/verdict.ts`) is the SDK's single answer to
"is it safe to show this address as a receive address on this chain right
now?". Call it — read-only, no relayer, no gas — before ever displaying a
Glaux account address to a user on a chain that has not already been
confirmed born:

```ts
const result = await checkChain(client, account);
// result.verdict is "born" | "eligible" | "ineligible"
```

`"born"` and `"eligible"` both mean it is safe to receive. `"ineligible"`
names exactly which probe failed (`result.reasons`) and must block the
receive flow, not just log a warning.

### Signer compatibility — Secure Enclave yes, browser WebAuthn passkeys no

Glaux's primary factor (F1) is a **raw-digest P-256 signer**: it signs the
bare 32-byte digest the contract computes, directly, through a native
platform crypto API. Apple's Secure Enclave (and the Android/Windows
hardware-backed equivalents `docs/client-guidance.md` §F1 describes) fit
this shape exactly — `LocalP256Signer` (`src/signers/p256.ts`) is the
software stand-in this SDK ships for tests, and a production integration
replaces it with a hardware-backed implementation of the same `Signer`
interface.

**A standard browser WebAuthn passkey does NOT fit this shape and cannot be
used as F1 today.** A WebAuthn authenticator never signs an arbitrary
digest — it signs `authenticatorData || SHA-256(clientDataJSON)`, an
envelope that only carries the Glaux digest indirectly, inside the challenge
field. `SignatureVerify`'s raw P-256 verification cannot succeed against
that envelope. Supporting WebAuthn passkeys as a factor would need a new
on-chain verifier type that reconstructs and checks the envelope — additive,
and explicitly out of scope here (see `docs/client-guidance.md`'s "WebAuthn
as a future verifier type").

## Quickstart: birth an account on a local anvil

Prerequisite: an anvil pinned to `--hardfork prague` (needed for EIP-7702;
predates the P-256 precompile, so it must be etched — see
[`docs/deployments.md`](../docs/deployments.md) for why), with the contracts
deployed at their canonical addresses and a P-256 oracle etched at `0x100`.
The e2e tests reuse the same setup via `sdk/test/helpers/{anvil,deploy}.ts`;
this is the shell-level equivalent:

```bash
anvil --hardfork prague &
forge script script/Deploy.s.sol:Deploy \
  --rpc-url http://127.0.0.1:8545 \
  --private-key <funded local key> --broadcast
cast rpc anvil_setCode 0x0000000071727De22E5E9d8BAf0edAc6f37da032 \
  "$(jq -r .deployedBytecode.object out/EntryPoint.sol/EntryPoint.json)" \
  --rpc-url http://127.0.0.1:8545
cast rpc anvil_setCode 0x0000000000000000000000000000000000000100 \
  "$(jq -r .deployedBytecode.object out/P256VerifierOracle.sol/P256VerifierOracle.json)" \
  --rpc-url http://127.0.0.1:8545
```

The SDK part — checked eligibility, then birth (verified against the setup
above; see this task's report for the transcript):

```ts
import { createPublicClient, http } from "viem";
import { checkChain } from "@glaux/sdk/eligibility/verdict";
import { LocalSecp256k1Signer } from "@glaux/sdk/signers/secp256k1";
import { LocalP256Signer } from "@glaux/sdk/signers/p256";
import { buildBirthBlob } from "@glaux/sdk/birth/blob";
import { preflightFreshAccount } from "@glaux/sdk/birth/preflight";
import { submitBirth } from "@glaux/sdk/birth/submit";

const rpc = "http://127.0.0.1:8545";
const client = createPublicClient({ transport: http(rpc) });

// SAFETY GATE — see above. Never show a receive address before this.
const eligibility = await checkChain(client);
if (eligibility.verdict === "ineligible") throw new Error(eligibility.reasons.join("; "));

const paper = new LocalSecp256k1Signer(paperPrivateKey);
const device = new LocalP256Signer(devicePrivateKey); // Secure Enclave-backed in production
const cloud = new LocalSecp256k1Signer(cloudPrivateKey);

const blob = await buildBirthBlob({ factors: [paper, device, cloud], chainRpc: rpc });
await preflightFreshAccount(client, blob.account); // refuses to re-birth an occupied address
const result = await submitBirth(client, relayerPrivateKey, blob);

console.log("born account:", result.account);
```

`@glaux/sdk/...` above stands for this package's compiled `dist/` (or `src/`
under a TS-aware loader) once it is consumed from outside this repository;
inside this repo, import the relative `.js`/`.ts` paths shown in
`sdk/test/*.test.ts` (e.g. `../src/eligibility/verdict.js`).

## Module map

| Module | What it does |
|---|---|
| `core/constants.ts` | Canonical addresses (`ROUTER`, `IMPL`, `ENTRYPOINT`, `CREATE2_DEPLOYER`), the CREATE2 `SALT`, domain separators, and `designator()` (the EIP-7702 `0xef0100‖router` bytecode). |
| `core/digests.ts` | Every EIP-191-wrapped digest the contract verifies: registration (possession proof), init (birth), execution, ERC-4337 user operation, and arbitrary-message digests. |
| `core/encoding.ts` | ABI encodes the wire blobs the contract expects: init data, a single `SlotSig`, and the ERC-4337 signature blob (`validUntil` + two `SlotSig`s). |
| `core/types.ts` | Shared value types: `FactorSlot`, `SlotSig`, `Call`, `BirthBlob`, and the two verifier-type constants. |
| `signers/signer.ts` | The pluggable `Signer` interface every factor implements, plus `registrationProof` (the possession-proof signer). |
| `signers/p256.ts`, `signers/secp256k1.ts` | Local (software) reference implementations of `Signer` for P-256 and secp256k1 — for tests and development; production factors implement the same interface against hardware. |
| `birth/blob.ts` | Builds a `BirthBlob`: the EIP-7702 authorization, init data, and birth signature for a set of three factors. |
| `birth/preflight.ts` | `preflightFreshAccount` — refuses to attempt a birth against an address that already carries Glaux state. |
| `birth/submit.ts` | `submitBirth` — sends the birth blob's authorization + `initializeAccount` call and confirms a real (non-reverted) success. |
| `eligibility/probes.ts`, `eligibility/verdict.ts` | The individual live probes (P-256, EIP-7702, deployment, account-born) and `checkChain`, which combines them into the `"born" \| "eligible" \| "ineligible"` verdict — see the frozen-funds section above. |
| `execute/direct.ts` | The always-available path: sign and submit a 2-of-3 `executeWithSigs` batch through an ordinary relayer, no EntryPoint involved. |
| `execute/userop.ts` | The self-funded ERC-4337 path: build, sign, and submit a `PackedUserOperation` against EntryPoint v0.7 (`handleOps`, no bundler), including the exact `getUserOpHash` replication. |
| `gas/erc7677.ts` | ERC-7677 paymaster-web-service client (`pm_getPaymasterStubData`/`pm_getPaymasterData`) and the RPC-shape conversion a UserOperation needs to speak it. |
| `gas/policy.ts` | `GasPolicy` — the sponsored → self-funded → self-relay fallback ladder, with every degradation reported as an explicit event, never silent. |
| `reconcile/reconcile.ts` | Cross-chain reconciliation: raw storage first, the account's own getters only as a cross-check — the TypeScript port of `scripts/reconcile.py`, same verdict semantics. |
| `errors.ts` | Every typed error the modules above throw, one per distinct failure mode — never a generic `Error`. |

## The bundler limitation (Alto 0.0.20, discovered in Task 11)

Glaux's primary signer is P-256, verified on-chain via a `STATICCALL` to
`0x100`. [`@pimlico/alto`](https://github.com/pimlicolabs/alto) 0.0.20's
safe-mode validation tracer allowlists only precompiles `0x01` through
`0x09`; it can therefore classify the call to `0x100` as a call to an
undeployed contract and reject the UserOperation, **even on a chain that
genuinely supports RIP-7212/EIP-7951**. This is a limitation of that Alto
version's tracer allowlist, not an ERC-7562 storage/opcode-access violation
by Glaux — see `sdk/test/helpers/alto.ts`'s doc comment for the full
derivation, including why this repo's own bundler e2e test runs Alto with
`--safe-mode false` instead (that flag also means the e2e suite does not
itself exercise ERC-7562 enforcement; it proves EntryPoint simulation, fee
handling, bundling, and inclusion, and nothing more).

**Before relying on the P-256 factor through ERC-4337 in production,
integrators must verify directly against their own bundler** that it
accepts `0x0100` as a precompile under its own safe-validation rules on the
target chain. The direct-execution path (`execute/direct.ts`) does not go
through a bundler at all and is unaffected.

## Environment variables

| Variable | Read by | Purpose |
|---|---|---|
| `GLAUX_PAYMASTER_URL` | `gas/erc7677.ts` (`paymasterClientFromEnv`) | ERC-7677 paymaster-web-service endpoint. Unset or blank means "no provider configured" — `GasPolicy` falls back to self-funded ERC-4337, not an error. |
| `GLAUX_ALTO` | `test/bundler.e2e.test.ts` | Set to `1` to opt into the real-Alto-bundler e2e suite; skipped by default so the ordinary test run needs neither the `@pimlico/alto` binary nor its startup time. |
| `GLAUX_RPC_SEPOLIA`, `GLAUX_RPC_BASE_SEPOLIA` | operator scripts / manual `checkChain` runs (not read by any SDK module directly) | Public RPC endpoints for the measured chain-eligibility checks below — the same convention `test/P256ForkProbe.t.sol` and `docs/deployments.md` use for `GLAUX_RPC_*`. |

No default endpoint or key for any of the above is ever committed to this
repository.

## Measured chain eligibility

`checkChain` run read-only against public Sepolia and Base Sepolia RPCs —
no transaction was sent; every probe below is an `eth_call`,
`eth_getCode`, or `eth_estimateGas`.

**Method:**

```bash
export GLAUX_RPC_SEPOLIA=<a Sepolia RPC endpoint>
export GLAUX_RPC_BASE_SEPOLIA=<a Base Sepolia RPC endpoint>
cd sdk && npm run build
node -e '
import("viem").then(async ({ createPublicClient, http }) => {
  const { checkChain } = await import("./dist/eligibility/verdict.js");
  for (const [name, url] of [
    ["Sepolia", process.env.GLAUX_RPC_SEPOLIA],
    ["Base Sepolia", process.env.GLAUX_RPC_BASE_SEPOLIA],
  ]) {
    const client = createPublicClient({ transport: http(url) });
    console.log(name, await checkChain(client));
  }
});
'
```

**Measured 2026-08-03** (endpoints: `ethereum-sepolia-rpc.publicnode.com`,
`base-sepolia-rpc.publicnode.com`):

| Chain | Verdict | p256 | eip7702 | create2Deployer | entryPoint | routerDeployed | implDeployed |
|---|---|---|---|---|---|---|---|
| Sepolia (11155111) | `ineligible` | true | true | true | true | true | **false** |
| Base Sepolia (84532) | `ineligible` | true | true | true | true | true | **false** |

Both chains fail on exactly one probe, for exactly one reason: **the
testnet redeploy to the post-audit implementation
(`0x21b5D576AB4188Ee06DD866b6Fd4a23085A73f5d`, `IMPL` in
`core/constants.ts`) has not happened yet.** It is blocked on a funded
`GLAUX_RELAYER_KEY` — see `docs/deployments.md`'s superseded notice. What is
actually deployed on both public testnets right now is the **old**,
pre-audit implementation at `0x927ed5700518a8A053367da1EaFDFBdE061E73F2`
(confirmed live via `eth_getCode` on both chains on the measurement date);
`checkChain` correctly reports it as absent because it checks the current
`IMPL` constant, not any address that once was canonical. Every other probe
— P-256 availability, EIP-7702 authorization pricing, the CREATE2 deployer,
the ERC-4337 EntryPoint, and the router (`GlauxDelegate`, unchanged by the
audit fixes) — passes on both networks. This table will flip to `eligible`
as soon as the redeploy in `docs/deployments.md` lands; re-run the command
above afterward rather than trusting this snapshot indefinitely.

## Testing

```bash
npm run typecheck   # tsc, no emit
npm test            # vitest — unit + e2e against locally spawned anvil/Alto
```

Some suites are skipped by default and opt in via environment variables
(`GLAUX_ALTO=1` for the real-bundler e2e — see above); everything else runs
with no network access and no funded key.
