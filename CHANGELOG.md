# Changelog

Notable changes to `@quantus-network/wasm`. Release notes with pull-request links are on [GitHub Releases](https://github.com/Quantus-Network/quantus-wasm/releases).

## Unreleased

### Added

- `signTransferAll` and `signTransferAllFromMnemonic`: build and sign `balances.transfer_all`, moving the whole transferable balance to the recipient. `keepAlive` is required: `true` leaves the existential deposit so the sender survives (the sweep for deposit addresses), `false` also moves the existential deposit and lets the sender be reaped.

## 1.0.0 - 2026-10-09

### Breaking

- `signTransfer` and `signTransferFromMnemonic` require a `keepAlive` boolean. `true` builds `balances.transfer_keep_alive`; `false` builds `balances.transfer_allow_death`, which is what every earlier version built. There is deliberately no default: omitting it is a TypeScript error and a runtime `TypeError`, so no caller changes behaviour without noticing.

### Added

- ML-DSA-65 signing via `scheme: "ml-dsa-65"` on every function. ML-DSA-87 stays the default. The two schemes derive different accounts from the same seed, and the default mnemonic `addressIndex` is 1 for ML-DSA-65, matching the Quantus wallets.
- `examples/chain-context.mjs`: how to read the mortal-era anchor and the rest of the chain context from a node.

### Changed

- Every ML-DSA signature is hedged (FIPS 204 randomized mode) with 32 bytes of fresh platform randomness. Signing the same inputs twice now yields different signature bytes and therefore different extrinsic hashes. Previously signing was deterministic, so re-signing the same call with the same nonce, for example after an account was reaped and re-funded (which resets its nonce to 0), produced byte-identical extrinsics that indexers keyed on the extrinsic hash saw as duplicates. Every byte other than the signature is unchanged, and hedged signatures verify on chain exactly as before. A randomness failure is a hard error.
- Omitting `period` still signs an immortal extrinsic but logs a one-time warning, because an immortal extrinsic can be replayed if the signer is reaped and re-funded. Pass `period: 0` to opt in explicitly and silence it.

### Fixed

- The README `signCall` snippet and the wallet example anchored mortal eras to polkadot.js's locally computed `header.hash`, a Blake2 digest. Quantus hashes headers with Poseidon, so those extrinsics failed with `BadProof`. Both now take the hash from the node via `chain_getBlockHash` and fetch the header for the block number; a test pins a real Quantus header to show the two hashes differ.

### Documentation

- New README section "Mortality, reaping and replay" covering nonce reset on reaping, immortal replay, where `blockHash` must come from, and what hedging does and does not protect against.
- Mortal eras are documented as the expected mode, anchored at the current best block; the era-boundary restriction only applies to periods above 4096 blocks.
- The `assetId` option targets the assets pallet, which is not currently on mainnet.

## 0.3.1 - 2026-09-12

- Ship the wasm in the npm tarball (#7) and accept npm 12's `pack --json` shape in the packaging test (#8).

## 0.3.0 - 2026-09-11

- Signatures are bound to the FIPS 204 context `QUANTUS_EXTRINSIC`, the runtime's `signing_context::EXTRINSIC` (#3).
- Security policy (#1); CI runs on Node 24 with npm upgraded for trusted publishing.

## 0.2.0 - 2026-08-08

- Bump `qp-poseidon-core` to 3.1.0 (#2).

## 0.1.2 - 2026-06-17

- Wallet example, `U512` type registration to silence the polkadot.js warning, release script.

## 0.1.0 and 0.1.1 - 2026-06-17

- Initial releases: ML-DSA-87 account derivation (Poseidon `AccountId32`, SS58 prefix 189) and v4 extrinsic signing, compiled from the chain's own crypto crates.
