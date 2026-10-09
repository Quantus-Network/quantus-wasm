# @quantus-network/wasm

Quantus account derivation and **ML-DSA-87** / **ML-DSA-65** transaction signing for JavaScript/TypeScript.

This package is **compiled to WebAssembly from the Quantus chain's own crypto crates** — addresses come from `qp-poseidon-core` (Poseidon2 over Goldilocks) and signatures from `qp-rusty-crystals-dilithium` (ML-DSA-87 and ML-DSA-65), the exact code the runtime uses. Nothing about address derivation or extrinsic encoding is re-implemented in JS, so there is no second implementation to drift out of sync with the chain.

- `account(seed, opts?)` → ML-DSA keypair → Poseidon `AccountId32` → SS58 address (prefix `189`).
- `signTransfer(seed, params)` → a signed **v4 extrinsic**, ready for `author_submitExtrinsic`.
- `signCall(seed, call, params)` → sign **any** call (build it with polkadot.js, sign it here).
- BIP39 mnemonic helpers using the canonical Quantus HD path.
- Every function takes an optional `scheme`: `"ml-dsa-87"` (default) or `"ml-dsa-65"`.
- Every signature is **hedged** (FIPS 204 randomized mode), so two signings of the same inputs never share an extrinsic hash. See [Mortality, reaping and replay](#mortality-reaping-and-replay).

## Install

```bash
npm install @quantus-network/wasm
```

Requires Node.js >= 18. The package ships prebuilt wasm (nodejs target) plus TypeScript types.

## Quick start

```ts
import { account, signTransfer } from "@quantus-network/wasm";

// 32-byte seed (e.g. from your KMS / secure storage).
const seed = new Uint8Array(32); // ...fill with real entropy

const acct = account(seed);
console.log(acct.address); // qz... (SS58, prefix 189)

const extrinsicHex =
  "0x" +
  Buffer.from(
    signTransfer(seed, {
      recipient: "qzk1Nxai3dZD9Cn5kwGcgL6mKxsfxwqdis7kDQJ52aJS2vSn7",
      amount: 1_000_000_000_000n, // plancks
      nonce: 0, // system_accountNextIndex(acct.address)
      period: 64, // mortal era: valid for 64 blocks from blockNumber
      blockNumber: 123456, // chain_getHeader().number (current best block)
      blockHash: "0x...", // hash of that header
      genesisHash: "0x...", // chain_getBlockHash(0)
      specVersion: 100, // state_getRuntimeVersion()
      transactionVersion: 1,
    })
  ).toString("hex");

// await rpc("author_submitExtrinsic", [extrinsicHex]);
```

The transfer is a `balances.transfer_keep_alive` unless you pass `keepAlive: false`.

## Mortality, reaping and replay

Two properties of the chain interact badly if a signer is careless, and this package's defaults are chosen around them:

- **Reaping resets the nonce.** When an account's free balance drops below the existential deposit (0.001 QTC) the account is deleted, nonce included. The next deposit recreates it with nonce 0. `signTransfer` therefore builds `balances.transfer_keep_alive`, which fails instead of reaping the sender; pass `keepAlive: false` only when emptying the account is the intent.
- **An immortal extrinsic never expires.** If the sender was reaped and re-funded, an immortal extrinsic signed earlier with nonce 0 is valid again, bytes unchanged, and anyone who saw it can resubmit it. Always sign **mortal** extrinsics: pass `period` (64 to 256 blocks is typical) plus the current best block's `blockNumber` and `blockHash`. Mortality bounds the replay window; keeping the account alive closes it.
- **Hedged signatures keep extrinsic hashes unique.** Without hedging, ML-DSA is deterministic: re-signing the same call with the same nonce after a reap would produce byte-identical extrinsics, and indexers that key on the extrinsic hash would see a duplicate. Every signature from this package mixes in 32 bytes of fresh platform randomness, so no two signed extrinsics are ever byte-identical. Note that hedging does not protect against replay of an *existing* extrinsic; only mortality and keep-alive do.

Omitting `period` signs an immortal extrinsic and logs a one-time warning; pass `period: 0` to opt into immortal explicitly and silence it.

## Signature schemes

The runtime accepts two signature schemes (`DilithiumSignatureScheme`), and this package supports both. Pass `scheme` in the options/params object of any function; omit it for ML-DSA-87, so existing code keeps working unchanged.

| `scheme` | Public key | Secret key | Signature | Wire variant | Runtime |
|---|---|---|---|---|---|
| `"ml-dsa-87"` (default) | 2592 bytes | 4896 bytes | 4627 bytes | `Dilithium87` = 0 | all |
| `"ml-dsa-65"` | 1952 bytes | 4032 bytes | 3309 bytes | `Dilithium65` = 1 | spec 139 and later |

Both schemes derive the account id the same way (Poseidon hash of the public key) and sign under the same `QUANTUS_EXTRINSIC` context. The same seed gives a different account per scheme. For mnemonics, the default `addressIndex` is `0` for ML-DSA-87 and `1` for ML-DSA-65, matching the Quantus wallets (`quantus wallet import --scheme ml-dsa-65`), so the two schemes never derive from the same entropy.

```ts
const a = account(seed, { scheme: "ml-dsa-65" });
const xt = signTransfer(seed, { scheme: "ml-dsa-65", recipient, amount, nonce, genesisHash, specVersion, transactionVersion });
const b = accountFromMnemonic(mnemonic, { scheme: "ml-dsa-65" }); // m/44'/189189'/0'/0'/1'
```

## API

### `account(seed: Uint8Array, opts?: { scheme?: Scheme }): QuantusAccount`

Derives the keypair and address from a 32-byte seed.

```ts
type Scheme = "ml-dsa-87" | "ml-dsa-65";

interface QuantusAccount {
  scheme: Scheme;        // scheme of the key
  publicKey: Uint8Array; // ML-DSA-87: 2592 bytes, ML-DSA-65: 1952 bytes
  secretKey: Uint8Array; // ML-DSA-87: 4896 bytes, ML-DSA-65: 4032 bytes
  accountId: Uint8Array; // 32-byte Poseidon AccountId32
  address: string;       // SS58, Quantus prefix (189)
}
```

### `signTransfer(seed: Uint8Array, params: TransferParams): Uint8Array`

Builds and signs a v4 extrinsic for a balances or assets transfer. Returns the SCALE-encoded bytes (prefix with `0x` for `author_submitExtrinsic`). All chain context is supplied by the caller, so signing is fully offline.

```ts
interface TransferParams {
  scheme?: Scheme;      // signing key scheme; default "ml-dsa-87"
  recipient: string | Uint8Array; // SS58, 0x-hex 32-byte id, or raw 32 bytes
  amount: bigint | string | number; // plancks (u128)
  keepAlive?: boolean;  // default true => balances.transfer_keep_alive; false => transfer_allow_death
  assetId?: number;     // set => assets.transfer (keepAlive is ignored); the assets pallet is not currently on mainnet
  nonce: number | bigint;
  tip?: bigint | string | number; // default 0
  period?: number | bigint; // mortal era length in blocks; 0 => immortal (omitted => immortal + warning)
  blockNumber?: number | bigint; // current best block (required for mortal eras)
  genesisHash: string | Uint8Array;
  blockHash?: string | Uint8Array; // hash of blockNumber; required when period > 0
  specVersion: number;
  transactionVersion: number;
}
```

Notes:
- **Mortal eras are the expected mode.** Pass `period` plus the current best block's `blockNumber` and `blockHash`; the extrinsic is valid for `period` blocks from there. (For periods above 4096, `blockNumber` must be a multiple of `period / 4096`; the signer rejects other anchors.)
- **Immortal** requires an explicit `period: 0`; omitting `period` also signs immortal but logs a one-time warning. See [Mortality, reaping and replay](#mortality-reaping-and-replay).
- Hashes accept either `0x`-hex strings or raw `Uint8Array`. Amounts accept `bigint` (recommended), decimal strings, or safe integers.

### `signCall(seed: Uint8Array, call: Call, params: CallParams): Uint8Array`

Signs an **already-encoded `RuntimeCall`**, returning the SCALE-encoded v4 extrinsic. This is the generic primitive behind `signTransfer`: encode the call with polkadot.js (whose codec handles the call fine — only the 7219-byte Dilithium *signature* exceeds its limits), then sign it here.

Encode the **call** directly via the registry — do **not** build a `SubmittableExtrinsic` (e.g. `api.tx.balances.transferKeepAlive(...)`), as that forces polkadot.js to instantiate the oversized signature type and throws:

```ts
import { ApiPromise } from "@polkadot/api";
import { signCall } from "@quantus-network/wasm";

const api = await ApiPromise.create({ provider });
const call = api.registry
  .createType("Call", {
    callIndex: api.tx.balances.transferKeepAlive.callIndex,
    args: { dest, value },
  })
  .toHex();

const header = await api.rpc.chain.getHeader();
const extrinsic = signCall(seed, call, {
  nonce: 0,
  period: 64,
  blockNumber: header.number.toNumber(),
  blockHash: header.hash.toHex(),
  genesisHash: api.genesisHash.toHex(),
  specVersion: api.runtimeVersion.specVersion.toNumber(),
  transactionVersion: api.runtimeVersion.transactionVersion.toNumber(),
});

// Submit via raw JSON-RPC; the signed extrinsic is too large for api.rpc to re-decode:
// await rpc("author_submitExtrinsic", ["0x" + Buffer.from(extrinsic).toString("hex")]);
```

The `call` is a `0x`-hex string or `Uint8Array`. `CallParams` is the chain context shared by every signed extrinsic — i.e. `TransferParams` minus the call-specific `recipient`/`amount`/`assetId` (in fact `TransferParams extends CallParams`):

```ts
type Call = Uint8Array | string; // SCALE-encoded RuntimeCall

interface CallParams {
  scheme?: Scheme;      // signing key scheme; default "ml-dsa-87"
  nonce: number | bigint;
  tip?: bigint | string | number; // default 0
  period?: number | bigint; // mortal era length in blocks; 0 => immortal (omitted => immortal + warning)
  blockNumber?: number | bigint; // current best block (required for mortal eras)
  genesisHash: string | Uint8Array;
  blockHash?: string | Uint8Array; // hash of blockNumber; required when period > 0
  specVersion: number;
  transactionVersion: number;
}
```

The same notes about mortal/immortal eras and hash/amount input formats apply. Prefer `transfer_keep_alive` over `transfer_allow_death` when encoding balance transfers yourself, for the reasons in [Mortality, reaping and replay](#mortality-reaping-and-replay).

### `accountFromMnemonic(mnemonic: string, opts?: MnemonicOptions): QuantusAccount`

Derives an account from a BIP39 mnemonic using the Quantus HD path `m/44'/189189'/<account>'/<change>'/<addressIndex>'`. Produces the same addresses as the Quantus wallets.

```ts
interface MnemonicOptions {
  scheme?: Scheme;       // default "ml-dsa-87"
  account?: number;      // default 0
  change?: number;       // default 0
  addressIndex?: number; // default 0 for ml-dsa-87, 1 for ml-dsa-65
  passphrase?: string;   // optional BIP39 passphrase
}
```

When `scheme` is given in both the options and the params, the options win: they select the key.

### `signTransferFromMnemonic(mnemonic, params, opts?): Uint8Array`

Same as `signTransfer`, but keyed from a mnemonic at the given HD indices.

### `signCallFromMnemonic(mnemonic, call, params, opts?): Uint8Array`

Same as `signCall`, but keyed from a mnemonic at the given HD indices.

### `mnemonicToSeed(mnemonic: string, passphrase?: string): Uint8Array`

Returns the 64-byte BIP39 seed. Use the first 32 bytes with `account` / `signTransfer` to bridge to the seed-based API.

## Trust & verification

Correctness is validated byte-for-byte against the canonical chain crates and frozen golden vectors (see `src/ext.rs` and `test/smoke.test.js`):

- **Addresses** match `qp-dilithium-crypto`'s `IdentifyAccount`, and reproduce known chain-spec mnemonic vectors.
- **`Era`** encoding matches `sp-runtime::generic::Era`.
- **Signatures** (ML-DSA-87 and ML-DSA-65) are hedged with 32 bytes of fresh platform randomness per signature and bound to the FIPS 204 context `QUANTUS_EXTRINSIC` (the runtime's `signing_context::EXTRINSIC`). The tests drive the same signing path without hedging to compare it byte-for-byte against `sp_core::Pair::sign` from `qp-dilithium-crypto` and against frozen golden vectors, check that hedged signatures differ while leaving every other extrinsic byte unchanged, and verify hedged extrinsics through the runtime's `Verify` impl after decoding the signature field. A signature under any other context (including none) is rejected on chain.
- **Transaction extensions** match the runtime's `TxExtension` (CheckMortality, CheckNonce, ChargeTransactionPayment, CheckMetadataHash, and the custom Reversible/Wormhole extensions, which contribute no signed bytes).

## Examples

A runnable script exercising every documented function (offline):

```bash
npm run build
npm run example
```

See [`examples/usage.js`](examples/usage.js).

### CLI wallet

[`examples/wallet.mjs`](examples/wallet.mjs) is a minimal command-line wallet
that talks to a live node. It uses polkadot.js only for connecting, reading
storage (balance/nonce), and SCALE-encoding the call; this package produces the
post-quantum signature, and the signed extrinsic is submitted via raw
`author_submitExtrinsic` (it is too large for polkadot.js to re-decode).

```bash
export MNEMONIC="your twelve or twenty-four word phrase"

npm run wallet -- address
npm run wallet -- balance                 # balance of your own account
npm run wallet -- balance <address>       # balance of any address
npm run wallet -- send --to <address> --amount 1000000000000
```

The endpoint defaults to `https://a1-planck.quantus.cat`; override it with
`--rpc <url>` or the `QUANTUS_RPC` env var. Pass `--account N` to use a
different HD account index.

## Build from source

Requires the Rust toolchain, the `wasm32-unknown-unknown` target, and [`wasm-pack`](https://rustwasm.github.io/wasm-pack/).

```bash
npm install
npm run build   # wasm-pack (nodejs target) -> tsc
npm test        # cargo test + JS golden vectors
```

## Publishing

Published from CI via npm [Trusted Publishing](https://docs.npmjs.com/trusted-publishers) (OIDC) — no token or secret required. Cut a release with `scripts/create-release.sh <patch|minor|major|x.y.z>` (see [`CREATE_RELEASE.md`](CREATE_RELEASE.md)); publishing a GitHub Release triggers the `publish` workflow, which builds, tests, and runs `npm publish` with automatic provenance.

## License

MIT
