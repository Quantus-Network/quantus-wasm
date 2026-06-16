# @quantus/wasm

Quantus account derivation and **ML-DSA-87** transaction signing for JavaScript/TypeScript.

This package is **compiled to WebAssembly from the Quantus chain's own crypto crates** — addresses come from `qp-poseidon-core` (Poseidon2 over Goldilocks) and signatures from `qp-rusty-crystals-dilithium` (ML-DSA-87), the exact code the runtime uses. Nothing about address derivation or extrinsic encoding is re-implemented in JS, so there is no second implementation to drift out of sync with the chain.

- `account(seed)` → ML-DSA-87 keypair → Poseidon `AccountId32` → SS58 address (prefix `189`).
- `signTransfer(seed, params)` → a signed **v4 extrinsic**, ready for `author_submitExtrinsic`.
- `signCall(seed, call, params)` → sign **any** call (build it with polkadot.js, sign it here).
- BIP39 mnemonic helpers using the canonical Quantus HD path.

## Install

```bash
npm install @quantus/wasm
```

Requires Node.js >= 18. The package ships prebuilt wasm (nodejs target) plus TypeScript types.

## Quick start

```ts
import { account, signTransfer } from "@quantus/wasm";

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
      nonce: 0,
      genesisHash: "0x...", // chain.getBlockHash(0)
      specVersion: 100, // state.getRuntimeVersion()
      transactionVersion: 1,
    })
  ).toString("hex");

// await rpc("author_submitExtrinsic", [extrinsicHex]);
```

## API

### `account(seed: Uint8Array): QuantusAccount`

Derives the keypair and address from a 32-byte seed.

```ts
interface QuantusAccount {
  publicKey: Uint8Array; // ML-DSA-87 public key (2592 bytes)
  secretKey: Uint8Array; // ML-DSA-87 secret key (4896 bytes)
  accountId: Uint8Array; // 32-byte Poseidon AccountId32
  address: string;       // SS58, Quantus prefix (189)
}
```

### `signTransfer(seed: Uint8Array, params: TransferParams): Uint8Array`

Builds and signs a v4 extrinsic for a balances or assets transfer. Returns the SCALE-encoded bytes (prefix with `0x` for `author_submitExtrinsic`). All chain context is supplied by the caller, so signing is fully offline.

```ts
interface TransferParams {
  recipient: string | Uint8Array; // SS58, 0x-hex 32-byte id, or raw 32 bytes
  amount: bigint | string | number; // plancks (u128)
  assetId?: number;     // set => assets.transfer; omitted => balances.transfer_allow_death
  nonce: number | bigint;
  tip?: bigint | string | number; // default 0
  period?: number | bigint; // mortal era length in blocks; 0/omitted => immortal
  blockNumber?: number | bigint; // era anchor block (required for mortal eras)
  genesisHash: string | Uint8Array;
  blockHash?: string | Uint8Array; // required when period > 0
  specVersion: number;
  transactionVersion: number;
}
```

Notes:
- **Immortal by default.** Omit `period` for an immortal transaction; the era checkpoint is the genesis hash.
- **Mortal eras** require `period`, `blockNumber`, and `blockHash`, where `blockHash` is the hash of `blockNumber` and `blockNumber` is an era boundary for the period.
- Hashes accept either `0x`-hex strings or raw `Uint8Array`. Amounts accept `bigint` (recommended), decimal strings, or safe integers.

### `signCall(seed: Uint8Array, call: Call, params: CallParams): Uint8Array`

Signs an **already-encoded `RuntimeCall`**, returning the SCALE-encoded v4 extrinsic. This is the generic primitive behind `signTransfer`: build any call with polkadot.js (whose codec handles the call fine — only the 7219-byte Dilithium *signature* exceeds its limits), then sign it here.

```ts
import { ApiPromise } from "@polkadot/api";
import { signCall } from "@quantus/wasm";

const api = await ApiPromise.create({ provider });
const call = api.tx.balances.transferAllowDeath(dest, value).method.toHex();

const extrinsic = signCall(seed, call, {
  nonce: 0,
  genesisHash: api.genesisHash.toHex(),
  specVersion: api.runtimeVersion.specVersion.toNumber(),
  transactionVersion: api.runtimeVersion.transactionVersion.toNumber(),
});
```

`call` is a `0x`-hex string or `Uint8Array` (e.g. `tx.method.toHex()` / `tx.method.toU8a()`). `CallParams` is exactly `TransferParams` without the `recipient`/`amount`/`assetId` fields (`nonce`, `tip?`, `period?`, `blockNumber?`, `genesisHash`, `blockHash?`, `specVersion`, `transactionVersion`).

### `accountFromMnemonic(mnemonic: string, opts?: MnemonicOptions): QuantusAccount`

Derives an account from a BIP39 mnemonic using the Quantus HD path `m/44'/189189'/<account>'/<change>'/<addressIndex>'`. Produces the same addresses as the Quantus wallets.

```ts
interface MnemonicOptions {
  account?: number;      // default 0
  change?: number;       // default 0
  addressIndex?: number; // default 0
  passphrase?: string;   // optional BIP39 passphrase
}
```

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
- **Signatures** are deterministic ML-DSA-87, frozen as golden vectors and verified under the canonical crate.
- **Transaction extensions** match the runtime's `TxExtension` (CheckMortality, CheckNonce, ChargeTransactionPayment, CheckMetadataHash, and the custom Reversible/Wormhole extensions, which contribute no signed bytes).

## Example

A runnable script exercising every documented function:

```bash
npm run build
npm run example
```

See [`examples/usage.js`](examples/usage.js).

## Build from source

Requires the Rust toolchain, the `wasm32-unknown-unknown` target, and [`wasm-pack`](https://rustwasm.github.io/wasm-pack/).

```bash
npm install
npm run build   # wasm-pack (nodejs target) -> tsc
npm test        # cargo test + JS golden vectors
```

## Publishing

Published from CI. Tag a GitHub Release (e.g. `v0.1.0`) and the `publish` workflow builds, tests, and runs `npm publish --provenance`. A repo secret `NPM_TOKEN` (npm automation token for the `@quantus` org) is required.

## License

MIT
