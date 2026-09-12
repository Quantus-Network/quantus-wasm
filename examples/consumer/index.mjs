import { parseArgs } from "node:util";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import * as wh from "@quantus-network/wormhole";

const { account, accountFromMnemonic, signTransfer, signTransferFromMnemonic } =
  createRequire(import.meta.url)("@quantus-network/wasm");

const { values } = parseArgs({ options: { rpc: { type: "string" }, offline: { type: "boolean" } } });
const RPC = values.rpc ?? process.env.QUANTUS_RPC ?? "http://127.0.0.1:9944";
const MNEMONIC = "orchard answer curve patient visual flower maze noise retreat penalty cage small earth domain scan pitch bottom crunch theme club client swap slice raven";
const SCHEMES = ["ml-dsa-87", "ml-dsa-65"];
const DEV = 1_000_000_000_000n;
const hex = (u8) => "0x" + Buffer.from(u8).toString("hex");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const step = (s) => console.log(`\n== ${s}`);

async function rpc(method, params = []) {
  const res = await fetch(RPC, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) });
  if (!res.ok) throw new Error(`RPC ${res.status} ${res.statusText}`);
  const json = await res.json();
  if (json.error) throw new Error(`${method}: ${json.error.message}`);
  return json.result;
}

step("accounts from one mnemonic");
const wallets = Object.fromEntries(SCHEMES.map((scheme) => [scheme, accountFromMnemonic(MNEMONIC, { scheme })]));
for (const [scheme, w] of Object.entries(wallets)) {
  console.log(`${scheme}: ${w.address}  (pk ${w.publicKey.length} B, index ${scheme === "ml-dsa-65" ? 1 : 0})`);
}
await wh.init();
const wormhole = wh.wormholeFromMnemonic(MNEMONIC);
console.log(`wormhole : ${wormhole.address}  (proving threads: ${wh.threadCount()})`);

step("offline signing, both schemes");
const ctx = { nonce: 0, genesisHash: "0x" + "11".repeat(32), specVersion: 1, transactionVersion: 1 };
for (const scheme of SCHEMES) {
  const xt = signTransferFromMnemonic(MNEMONIC, { recipient: wormhole.address, amount: DEV, scheme, ...ctx });
  console.log(`${scheme}: ${xt.length}-byte extrinsic, signature variant ${xt[2 + 1 + 33]}`);
}

step("verify the repository's proof fixtures with the runtime's verifiers");
const fixture = async (name) => (await readFile(new URL(`../../wormhole/core/test-data/${name}`, import.meta.url), "utf8")).trim();
const privateBatch = wh.verifyPrivateBatchProof(await fixture("private_batch.hex"));
console.log(`private batch: ${privateBatch.exits.filter((e) => e.amount > 0).length} real exits of ${privateBatch.exits.length} slots, ${privateBatch.nullifiers.length} nullifiers`);
const publicBatch = wh.verifyPublicBatchProof(await fixture("public_batch.hex"));
console.log(`public batch : ${publicBatch.segments.length} segments, ${publicBatch.totalExitSlots} slots, aggregator ${hex(publicBatch.aggregatorAddress).slice(0, 12)}…`);

if (values.offline) {
  console.log("\noffline run complete");
  process.exit(0);
}

step(`node ${RPC}`);
const rv = await rpc("state_getRuntimeVersion");
const genesisHash = await rpc("chain_getBlockHash", [0]);
console.log(`spec ${rv.specVersion}, tx version ${rv.transactionVersion}`);
const chainCtx = () => ({ genesisHash, specVersion: rv.specVersion, transactionVersion: rv.transactionVersion });
const nonceOf = (address) => rpc("system_accountNextIndex", [address]);
const headNumber = async () => parseInt((await rpc("chain_getHeader")).number, 16);
const freeBalance = async (address) => {
  // System.Account storage: twox128("System") ++ twox128("Account") ++ blake2_128concat(id); free balance is the u128 after nonce(u32)+consumers+providers+sufficients(3×u32).
  const { xxhashAsHex, blake2AsHex } = createRequire(import.meta.url)("@polkadot/util-crypto");
  const { decodeAddress } = createRequire(import.meta.url)("@polkadot/util-crypto");
  const id = decodeAddress(address);
  const key = xxhashAsHex("System", 128) + xxhashAsHex("Account", 128).slice(2) + blake2AsHex(id, 128).slice(2) + Buffer.from(id).toString("hex");
  const raw = await rpc("state_getStorage", [key]);
  if (!raw) return 0n;
  const data = Buffer.from(raw.slice(2), "hex");
  return data.readBigUInt64LE(16) + (data.readBigUInt64LE(24) << 64n);
};
async function submitAndWait(xt, from) {
  const before = await nonceOf(from);
  const hash = await rpc("author_submitExtrinsic", [hex(xt)]);
  for (let i = 0; i < 40; i++) {
    await sleep(3000);
    const head = await headNumber();
    for (let n = Math.max(1, head - 3); n <= head; n++) {
      const block = await rpc("chain_getBlock", [await rpc("chain_getBlockHash", [n])]);
      if (block.block.extrinsics.some((e) => wh.extrinsicHash(e) === hash)) return { hash, block: n };
    }
  }
  throw new Error(`extrinsic ${hash} not included after 120 s (nonce before: ${before})`);
}

step("fund both accounts from crystal_alice (ML-DSA-87 dev account)");
const alice = new Uint8Array(32);
const aliceAddress = account(alice).address;
for (const scheme of SCHEMES) {
  const xt = signTransfer(alice, { recipient: wallets[scheme].address, amount: 20n * DEV, nonce: await nonceOf(aliceAddress), ...chainCtx() });
  const { block } = await submitAndWait(xt, aliceAddress);
  console.log(`funded ${scheme} account with 20 DEV in block #${block}`);
}

step("send from each account: both signature schemes verified on chain");
for (const scheme of SCHEMES) {
  const w = wallets[scheme];
  const xt = signTransferFromMnemonic(MNEMONIC, { recipient: aliceAddress, amount: DEV, scheme, nonce: await nonceOf(w.address), ...chainCtx() });
  const { hash, block } = await submitAndWait(xt, w.address);
  console.log(`${scheme}: 1 DEV -> alice, ${xt.length} bytes, ${hash.slice(0, 12)}… in block #${block}`);
}

step("deposit from each account into the wormhole");
const deposits = [];
for (const scheme of SCHEMES) {
  const w = wallets[scheme];
  const from = await headNumber();
  const xt = signTransferFromMnemonic(MNEMONIC, { recipient: wormhole.address, amount: 5n * DEV, scheme, nonce: await nonceOf(w.address), ...chainCtx() });
  const { block } = await submitAndWait(xt, w.address);
  // The NativeTransferred event carries the leaf index; read it from System.Events of that block.
  const { ApiPromise, HttpProvider } = createRequire(import.meta.url)("@polkadot/api");
  const api = await ApiPromise.create({ provider: new HttpProvider(RPC), noInitWarn: true, types: { U512: "[u8; 64]" } });
  let leaf;
  for (let n = from; n <= block && !leaf; n++) {
    const events = await (await api.at(await api.rpc.chain.getBlockHash(n))).query.system.events();
    for (const { event } of events) {
      if (event.section === "wormhole" && event.method === "NativeTransferred" && event.data.to.toString() === wormhole.address && event.data.from.toString() === w.address) {
        leaf = { index: Number(event.data.leafIndex), transferCount: BigInt(event.data.transferCount.toString()) };
      }
    }
  }
  await api.disconnect();
  if (!leaf) throw new Error(`no NativeTransferred event for the ${scheme} deposit`);
  console.log(`${scheme}: 5 DEV deposited, leaf ${leaf.index}, transfer_count ${leaf.transferCount}`);
  deposits.push({ scheme, ...leaf });
}

step("prove both deposits (layer 0) and aggregate them (layer 1)");
let blockHash, merkles;
for (;;) {
  blockHash = await rpc("chain_getBlockHash");
  merkles = await Promise.all(deposits.map((d) => rpc("zkTree_getMerkleProof", [d.index, blockHash])));
  if (merkles.every(Boolean)) break;
  console.log("waiting for the leaves to settle into the ZK tree");
  await sleep(6000);
}
const header = await rpc("chain_getHeader", [blockHash]);
const { ApiPromise: Api, HttpProvider: Http } = createRequire(import.meta.url)("@polkadot/api");
const api = await Api.create({ provider: new Http(RPC), noInitWarn: true, types: { U512: "[u8; 64]" } });
const digest = (await api.rpc.chain.getHeader(blockHash)).digest.toU8a();
await api.disconnect();
const leafProofs = [];
const exits = { "ml-dsa-87": wallets["ml-dsa-87"].address, "ml-dsa-65": wallets["ml-dsa-65"].address };
for (const [i, d] of deposits.entries()) {
  const merkle = merkles[i];
  const leaf = wh.decodeZkLeaf(merkle.leaf_data);
  const path = wh.merklePositions(merkle.siblings, merkle.leaf_hash);
  if (hex(path.root) !== hex(merkle.root)) throw new Error("Merkle path does not fold to the tree root");
  const inputAmount = wh.quantize(leaf.amount);
  const t = performance.now();
  const { proof, nullifier } = await wh.proveLeaf({
    secret: wormhole.secret, transferCount: leaf.transferCount, inputAmount,
    blockHash, blockNumber: parseInt(header.number, 16), parentHash: header.parentHash, stateRoot: header.stateRoot, extrinsicsRoot: header.extrinsicsRoot, digest,
    zkTreeRoot: merkle.root, sortedSiblings: path.sortedSiblings, positions: path.positions,
    exitAccount1: exits[d.scheme], outputAmount1: wh.outputAfterFee(inputAmount),
  });
  if (await rpc("state_getStorage", [wh.usedNullifierStorageKey(nullifier)])) throw new Error("deposit already exited");
  console.log(`${d.scheme} deposit: leaf proof ${proof.length} B in ${(performance.now() - t).toFixed(0)} ms, exits ${wh.dequantize(wh.outputAfterFee(inputAmount))} plancks back to the ${d.scheme} account`);
  leafProofs.push({ proof, nullifier });
}
const t = performance.now();
const batch = await wh.aggregatePrivateBatch(leafProofs.map((l) => l.proof));
const parsed = wh.verifyPrivateBatchProof(batch);
console.log(`private batch: ${batch.length} B in ${((performance.now() - t) / 1000).toFixed(1)} s, ${parsed.exits.filter((e) => e.amount > 0).length} real exits, verified locally`);

step("settle on chain");
const balancesBefore = Object.fromEntries(await Promise.all(SCHEMES.map(async (s) => [s, await freeBalance(wallets[s].address)])));
const hash = await rpc("author_submitExtrinsic", [hex(wh.encodeVerifyPrivateBatch(batch))]);
console.log(`verify_private_batch accepted: ${hash}`);
for (let i = 0; i < 40; i++) {
  await sleep(3000);
  const used = await Promise.all(leafProofs.map((l) => rpc("state_getStorage", [wh.usedNullifierStorageKey(l.nullifier)])));
  if (used.every(Boolean)) {
    console.log("both nullifiers are used on chain");
    for (const s of SCHEMES) {
      const after = await freeBalance(wallets[s].address);
      console.log(`${s} account: +${(after - balancesBefore[s]) / 10_000_000_000n / 100n}.${(((after - balancesBefore[s]) / 10_000_000_000n) % 100n).toString().padStart(2, "0")} DEV from the wormhole exit`);
    }
    console.log("\nround trip complete");
    process.exit(0);
  }
}
throw new Error("not settled after 120 s");
