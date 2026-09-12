# @quantus-network/wormhole

Quantus wormhole for Node.js: deposit keys, proving for all three proof layers on every CPU core, local verification, and the unsigned settlement extrinsics. A native addon (napi-rs) built from the chain's own circuit crates, pinned to the versions the runtime verifies against, with the verifier artifacts the runtime embeds compiled in.

Signing lives in [`@quantus-network/wasm`](https://www.npmjs.com/package/@quantus-network/wasm); the two packages are independent.

## Overview

The wormhole moves QTC privately. You deposit to an unspendable address derived from a secret (`H(H("wormhole" || secret))`); the runtime records every native credit as a leaf in a ZK Merkle tree. To exit, you prove in zero knowledge that you know the secret behind a recorded deposit and submit the proof, and the runtime mints the amount (minus a 4 bps volume fee) to the exit accounts you chose. Nothing links the deposit to the exit.

| Layer | Proof | Inputs | Outputs | Who |
|---|---|---|---|---|
| 0 | leaf | 1 deposit | 2 exit slots | wallet |
| 1 | private batch | 7 leaf proofs (padded with dummies) | 14 exit slots, 7 nullifiers | wallet |
| 2 | public batch | 53 private batches (padded) | 742 exit slots, 371 nullifiers | aggregator / miner |

Only layers 1 and 2 settle on chain, through the unsigned, fee-free calls `wormhole.verify_private_batch` and `wormhole.verify_public_batch`. Value pools across the 7 leaves of a private batch: `sum(outputs) * 10000 <= sum(inputs) * (10000 - 4)`, with amounts in units of 0.01 QTC.

## The native addon

Proving is heavy (a public batch needs about 7 GB), so it runs natively.

**Install:**

```bash
npm install @quantus-network/wormhole
```

npm pulls the prebuilt binary for your platform as an optional dependency (`@quantus-network/wormhole-<platform>`). Prebuilt: Linux x64 (glibc and musl), Linux arm64 (glibc), macOS arm64 and x64. Node 18 or newer. ESM; from CommonJS use `await import("@quantus-network/wormhole")`.

**Use:**

```ts
import * as wh from "@quantus-network/wormhole";
await wh.init();                 // loads the binary, one proving thread per core
await wh.init({ threads: 4 });   // or cap the pool (first call wins)
```

- If there is no binary for the platform, `init()` rejects with `no native binary for <platform>-<arch>`; see below for building from source.
- `proveLeaf`, `aggregatePrivateBatch` and `aggregatePublicBatch` return promises and run on a libuv thread, fanning out over the rayon pool, so a server's event loop stays responsive. Everything else is synchronous and fast (verification of any layer takes milliseconds).
- Memory: a private batch peaks around 2 GB, a public batch around 8 GB. Run layer-2 aggregation on a machine with 16 GB.
- Timing on a 10-core laptop: leaf proof under 0.2 s, private batch 3 to 5 s, public batch 20 to 30 s (each aggregation builds its circuit first; the batch sizes are fixed by the chain, 7 and 53).
- The package must match the chain's circuit version: it pins the circuit crates the runtime verifies against, and gets a release when the runtime moves to new circuits. Mismatched proofs fail verification on chain with `ProofVerificationFailed`.

**No prebuilt binary for your platform?** Build from source: install Rust (stable), clone [quantus-wasm](https://github.com/Quantus-Network/quantus-wasm), run `npm install && npm run build:native`. That compiles `wormhole/native` with `napi build --platform --release` (a few minutes: the build script also generates the circuit verifier artifacts and proves the layer-2 padding batch) and its TypeScript. Then `npm install <path-to-clone>/wormhole/native` in your project.

**Troubleshooting**

| Symptom | Cause |
|---|---|
| `no native binary for <platform>-<arch>` | No prebuilt binary for this platform, or optional dependencies were skipped (`npm install --no-optional`, or a lockfile from another platform). Reinstall with optional dependencies, or build from source. |
| `thread pool: The global thread pool has already been initialized` | `init({ threads })` called twice with different values in one process; the first call sets the pool. |
| `... is not canonically encoded` / `above the 512 KiB cap` | The proof bytes were altered or truncated; the runtime applies the same rules. |
| Proving is slow | Check `threadCount()`; containers often expose fewer cores than the host. |

```ts
import * as wh from "@quantus-network/wormhole";

await wh.init(); // one proving thread per core

// 1. Deposit: any transfer to this address is recorded as a ZK-tree leaf.
const key = wh.wormholeFromMnemonic(mnemonic); // or wh.wormholeAddress(secret)
// ... signTransfer(seed, { recipient: key.address, ... }) from @quantus-network/wasm.
//     The NativeTransferred event carries transfer_count and leaf_index.

// 2. Fetch the Merkle proof and header from the same block.
const merkle = await rpc("zkTree_getMerkleProof", [leafIndex, blockHash]);
const leaf = wh.decodeZkLeaf(merkle.leaf_data);
const path = wh.merklePositions(merkle.siblings, merkle.leaf_hash); // path.root must equal merkle.root

// 3. Prove (layer 0), aggregate (layer 1), submit.
const input = wh.quantize(leaf.amount);
const { proof, nullifier } = await wh.proveLeaf({
  secret: key.secret, transferCount: leaf.transferCount, inputAmount: input,
  blockHash, blockNumber, parentHash, stateRoot, extrinsicsRoot, digest, // from chain_getHeader
  zkTreeRoot: merkle.root, sortedSiblings: path.sortedSiblings, positions: path.positions,
  exitAccount1: destination, outputAmount1: wh.outputAfterFee(input),
});
const batch = await wh.aggregatePrivateBatch([proof]); // up to 7 leaf proofs
await rpc("author_submitExtrinsic", ["0x" + Buffer.from(wh.encodeVerifyPrivateBatch(batch)).toString("hex")]);

// 4. Settled once the nullifier is marked used (one state_getStorage call, no indexer).
const settled = (await rpc("state_getStorage", [wh.usedNullifierStorageKey(nullifier)])) !== null;

// Aggregators: fold private batches into a public batch (layer 2) and earn the rebate.
const publicBatch = await wh.aggregatePublicBatch(privateBatches, aggregatorAddress);
```

[`examples/wormhole.mjs`](https://github.com/Quantus-Network/quantus-wasm/blob/main/examples/wormhole.mjs) runs the wallet loop against a live node (`npm run wormhole -- deposit --amount ...`, then `npm run wormhole -- exit --leaf <index> --to <address>`). [`examples/consumer`](https://github.com/Quantus-Network/quantus-wasm/tree/main/examples/consumer) is a standalone project that uses both packages like an application: ML-DSA-87 and ML-DSA-65 accounts, deposits from each, one private batch with two exits, settlement.

## API

Proving functions return promises; everything else is synchronous after `await init()`. Byte arguments accept `Uint8Array`, an array of byte values (as JSON-RPC returns them), or `0x` hex; accounts also accept SS58.

| Function | Purpose |
|---|---|
| `init({ threads? })` | Load the native binary and size its pool (default: every core). Idempotent. |
| `wormholeAddress(secret)` | `{ accountId, address }` of the unspendable deposit account for a 32-byte secret. |
| `wormholeFromMnemonic(mnemonic, { index?, passphrase? })` | `{ secret, accountId, address }` at `m/44'/189189189'/0'/0'/<index>'`, as the Quantus wallets derive it. |
| `nullifier(secret, transferCount)` | The nullifier one deposit spends; check `usedNullifierStorageKey` before proving. |
| `decodeZkLeaf(leafData)` | `{ to, transferCount, assetId, amount }` from `zkTree_getMerkleProof`'s SCALE leaf. |
| `merklePositions(siblings, leafHash)` | Sorted siblings, positions and root for the circuit from the RPC's unsorted siblings. |
| `quantize(plancks)` / `dequantize(units)` / `outputAfterFee(units, feeBps?)` | 0.01 QTC circuit units and the volume fee. |
| `proveLeaf(input)` | Layer 0: `{ proof, nullifier }` for one deposit. |
| `aggregatePrivateBatch(leafProofs)` | Layer 1: one private-batch proof from up to `numLeafProofs()` leaf proofs. |
| `aggregatePublicBatch(privateBatchProofs, aggregatorAddress)` | Layer 2: one public-batch proof from up to `numPrivateBatchProofs()` private batches. |
| `parse*Proof` / `verify*Proof` (leaf, private batch, public batch) | Public inputs of a proof; `verify*` also checks it with the verifier the runtime embeds and rejects oversized or non-canonical blobs, as the runtime does. |
| `encodeVerifyPrivateBatch(proof)` / `encodeVerifyPublicBatch(proof)` | Unsigned settlement extrinsics for `author_submitExtrinsic`. |
| `usedNullifierStorageKey(nullifier)` / `extrinsicHash(xt)` | Status checks with plain `state_getStorage`. |
| `numLeafProofs()` / `numPrivateBatchProofs()` / `threadCount()` | Batch sizes compiled in (7 / 53) and pool size. |

## Trust & verification

- Circuit crates are pinned to the versions the runtime verifies against (`qp-wormhole-* 4.3.0`, `qp-plonky2 1.5.5`); the verifier artifacts are generated at build time by the same generator and sizing as `pallet-wormhole`.
- Tests prove the circuits repo's reference deposit, aggregate it into a private batch and verify it; verify the runtime's own `private_batch.hex` / `public_batch.hex` fixtures; aggregate a public batch (opt-in, `WORMHOLE_TEST_PUBLIC_BATCH=1`); decode the settlement extrinsics as the wormhole calls; and check storage keys and hashes against polkadot.js.
- `verify*` applies the runtime's own rules before verifying: the 512 KiB size cap and the canonical-encoding check.

## License

MIT
