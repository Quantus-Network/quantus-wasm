# Consumer example

A standalone project that depends on the two packages like an application
would (`file:` links here; on npm they are `@quantus-network/wasm` and
`@quantus-network/wormhole`) and runs against a node:

1. derives an ML-DSA-87 and an ML-DSA-65 account from one mnemonic,
2. funds both from the dev account and sends a transfer *from* each (so both
   signature schemes are verified on chain),
3. deposits from each into the wormhole address of the same mnemonic,
4. proves both deposits (layer 0), aggregates them into one private batch
   (layer 1) with two exit outputs, submits `verify_private_batch`, and waits
   until both nullifiers are used on chain.

```bash
# from the repository root, after `npm install && npm run build`
cd examples/consumer && npm install
quantus-node --dev --tmp --rpc-port 9944 --rpc-cors all   # in another shell
npm start                                                  # or: node index.mjs --rpc http://127.0.0.1:9944
```

Add `--offline` to run only the parts that need no node (derivation, signing,
proof verification of the repository fixtures).
