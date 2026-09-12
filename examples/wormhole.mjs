// Wormhole round trip against a live node, without an indexer:
//
//   node examples/wormhole.mjs address                        # wormhole deposit address of MNEMONIC (index 0)
//   node examples/wormhole.mjs deposit --amount <plancks>     # wallet -> wormhole address; prints leaf index
//   node examples/wormhole.mjs exit --leaf <index> --to <addr> # prove + aggregate + submit + wait for settlement
//
// Flags: --rpc <url> (default https://a1-planck.quantus.cat, env QUANTUS_RPC),
//        --account <n> (wallet HD account for deposit), --index <n> (wormhole HD index).
// Env:   MNEMONIC (or --mnemonic "...").
//
// polkadot.js is used to decode headers and events; everything else is raw
// JSON-RPC. Proving runs natively on every core (@quantus-network/wormhole).

import { parseArgs } from "node:util";
import { ApiPromise, HttpProvider } from "@polkadot/api";
import { availableParallelism } from "node:os";
import { createRequire } from "node:module";
import * as wh from "@quantus-network/wormhole";

const { accountFromMnemonic, signTransferFromMnemonic } = createRequire(import.meta.url)("../dist/index.js");

const DEFAULT_RPC = "https://a1-planck.quantus.cat";
const { values, positionals } = parseArgs({
  allowPositionals: true,
  options: { rpc: { type: "string" }, mnemonic: { type: "string" }, amount: { type: "string" }, leaf: { type: "string" }, to: { type: "string" }, account: { type: "string" }, index: { type: "string" } },
});
const rpcUrl = values.rpc ?? process.env.QUANTUS_RPC ?? DEFAULT_RPC;
const mnemonic = values.mnemonic ?? process.env.MNEMONIC;
const command = positionals[0];
if (!mnemonic || !command) {
  console.error("usage: node examples/wormhole.mjs <address|deposit|exit> [flags]; MNEMONIC is required");
  process.exit(1);
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const hex = (u8) => "0x" + Buffer.from(u8).toString("hex");

async function rpc(method, params = []) {
  const res = await fetch(rpcUrl, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) });
  if (!res.ok) throw new Error(`RPC ${res.status} ${res.statusText}`);
  const json = await res.json();
  if (json.error) throw new Error(`${method}: ${json.error.message}`);
  return json.result;
}

await wh.init({ threads: availableParallelism() });
const wormhole = wh.wormholeFromMnemonic(mnemonic, { index: Number(values.index ?? 0) });

if (command === "address") {
  console.log(wormhole.address);
  process.exit(0);
}

const api = await ApiPromise.create({ provider: new HttpProvider(rpcUrl), noInitWarn: true, types: { U512: "[u8; 64]" } });
const head = async () => (await api.rpc.chain.getHeader()).number.toNumber();

if (command === "deposit") {
  if (!values.amount) throw new Error("--amount <plancks> is required");
  const wallet = accountFromMnemonic(mnemonic, { account: Number(values.account ?? 0) });
  const rv = await rpc("state_getRuntimeVersion");
  const nonce = await rpc("system_accountNextIndex", [wallet.address]);
  const xt = signTransferFromMnemonic(
    mnemonic,
    { recipient: wormhole.address, amount: BigInt(values.amount), nonce, genesisHash: await rpc("chain_getBlockHash", [0]), specVersion: rv.specVersion, transactionVersion: rv.transactionVersion },
    { account: Number(values.account ?? 0) }
  );
  const from = await head();
  console.log(`deposit ${values.amount} plancks ${wallet.address} -> ${wormhole.address}: ${await rpc("author_submitExtrinsic", [hex(xt)])}`);
  // The NativeTransferred event carries the leaf index needed to exit later.
  for (let n = from; ; n++) {
    while ((await head()) < n) await sleep(2000);
    const blockHash = await api.rpc.chain.getBlockHash(n);
    const events = await (await api.at(blockHash)).query.system.events();
    for (const { event } of events) {
      if (event.section === "wormhole" && event.method === "NativeTransferred" && event.data.to.toString() === wormhole.address) {
        const { transferCount, leafIndex } = event.data;
        console.log(`recorded in block ${n}: transfer_count=${transferCount} leaf_index=${leafIndex}`);
        process.exit(0);
      }
    }
  }
}

if (command === "exit") {
  if (values.leaf === undefined || !values.to) throw new Error("--leaf <index> and --to <address> are required");
  const leafIndex = Number(values.leaf);

  // Header and Merkle proof must come from the same block.
  let merkle;
  let blockHash;
  for (;;) {
    blockHash = (await api.rpc.chain.getBlockHash()).toHex();
    merkle = await rpc("zkTree_getMerkleProof", [leafIndex, blockHash]);
    if (merkle) break;
    console.log(`leaf ${leafIndex} is not in the ZK tree at ${blockHash} yet, waiting`);
    await sleep(6000);
  }
  const header = await api.rpc.chain.getHeader(blockHash);
  const leaf = wh.decodeZkLeaf(merkle.leaf_data);
  if (hex(leaf.to) !== hex(wormhole.accountId)) throw new Error(`leaf ${leafIndex} belongs to ${hex(leaf.to)}, not this wormhole address`);
  const path = wh.merklePositions(merkle.siblings, merkle.leaf_hash);
  if (hex(path.root) !== hex(merkle.root)) throw new Error("Merkle path does not fold to the tree root");

  const inputAmount = wh.quantize(leaf.amount);
  const outputAmount1 = wh.outputAfterFee(inputAmount);
  console.log(`leaf ${leafIndex}: ${leaf.amount} plancks (transfer_count ${leaf.transferCount}) -> exit ${wh.dequantize(outputAmount1)} plancks to ${values.to}`);

  console.time("proveLeaf");
  const { proof, nullifier } = await wh.proveLeaf({
    secret: wormhole.secret,
    transferCount: leaf.transferCount,
    inputAmount,
    blockHash,
    blockNumber: header.number.toNumber(),
    parentHash: header.parentHash.toHex(),
    stateRoot: header.stateRoot.toHex(),
    extrinsicsRoot: header.extrinsicsRoot.toHex(),
    digest: header.digest.toU8a(),
    zkTreeRoot: merkle.root,
    sortedSiblings: path.sortedSiblings,
    positions: path.positions,
    exitAccount1: values.to,
    outputAmount1,
  });
  console.timeEnd("proveLeaf");

  const nullifierKey = wh.usedNullifierStorageKey(nullifier);
  if (await rpc("state_getStorage", [nullifierKey])) throw new Error("this deposit was already exited (nullifier used)");

  console.time("aggregatePrivateBatch");
  const batch = await wh.aggregatePrivateBatch([proof]);
  console.timeEnd("aggregatePrivateBatch");
  wh.verifyPrivateBatchProof(batch);

  const xt = wh.encodeVerifyPrivateBatch(batch);
  console.log(`submitted ${xt.length}-byte verify_private_batch: ${await rpc("author_submitExtrinsic", [hex(xt)])}`);
  for (let i = 0; i < 60; i++) {
    await sleep(3000);
    if (await rpc("state_getStorage", [nullifierKey])) {
      console.log("settled: nullifier is now used on chain");
      process.exit(0);
    }
  }
  throw new Error("not settled after 180s");
}

throw new Error(`unknown command ${command}`);
