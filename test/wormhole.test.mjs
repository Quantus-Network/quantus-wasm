import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { availableParallelism } from "node:os";
import { blake2AsHex, xxhashAsHex } from "@polkadot/util-crypto";
import { compactToU8a } from "@polkadot/util";
import * as wh from "@quantus-network/wormhole";

const fixture = async (name) => Uint8Array.from(Buffer.from((await readFile(new URL(`../wormhole/core/test-data/${name}`, import.meta.url), "utf8")).trim(), "hex"));
const LEAF = await fixture("leaf_proof.hex");
const PRIVATE_BATCH = await fixture("private_batch.hex");
const PUBLIC_BATCH = await fixture("public_batch.hex");
const LEAF_INPUT = JSON.parse(await readFile(new URL("../wormhole/core/test-data/leaf_input.json", import.meta.url), "utf8"));
const hex = (u8) => "0x" + Buffer.from(u8).toString("hex");

const MNEMONIC =
  "orchard answer curve patient visual flower maze noise retreat penalty cage small earth domain scan pitch bottom crunch theme club client swap slice raven";

await wh.init({ threads: Math.min(4, availableParallelism()) });

test("init loads the native binary, sizes the pool and exposes the chain's batch sizes", () => {
  assert.ok(wh.threadCount() >= 1);
  assert.equal(wh.numLeafProofs(), 7);
  assert.equal(wh.numPrivateBatchProofs(), 53);
});

test("wormhole keys: address, mnemonic derivation, nullifier", () => {
  const a = wh.wormholeAddress(LEAF_INPUT.secret);
  assert.equal(hex(a.accountId), LEAF_INPUT.wormholeAddress);
  assert.ok(a.address.startsWith("qz"));

  const k = wh.wormholeFromMnemonic(MNEMONIC);
  assert.equal(k.secret.length, 32);
  assert.deepEqual(wh.wormholeAddress(k.secret), { accountId: k.accountId, address: k.address });
  assert.notDeepEqual(wh.wormholeFromMnemonic(MNEMONIC, { index: 1 }).address, k.address);

  const n = wh.nullifier(LEAF_INPUT.secret, LEAF_INPUT.transferCount);
  assert.equal(hex(n), hex(wh.parseLeafProof(LEAF).nullifier));
  assert.notEqual(hex(wh.nullifier(LEAF_INPUT.secret, 5n)), hex(n));
  assert.throws(() => wh.wormholeAddress(new Uint8Array(31)), /32 bytes/);
});

test("amounts and ZK leaves", () => {
  assert.equal(wh.quantize(1_230_000_000_000n), 123);
  assert.equal(wh.quantize("9999999999"), 0);
  assert.equal(wh.dequantize(123), 1_230_000_000_000n);
  assert.equal(wh.outputAfterFee(10_000), 9_996);
  assert.equal(wh.outputAfterFee(10_000, 10), 9_990);

  const leaf = new Uint8Array(60);
  leaf.fill(7, 0, 32);
  new DataView(leaf.buffer).setBigUint64(32, 9n, true);
  new DataView(leaf.buffer).setUint32(40, 0, true);
  new DataView(leaf.buffer).setBigUint64(44, 1_230_000_000_000n, true);
  const decoded = wh.decodeZkLeaf(Array.from(leaf));
  assert.deepEqual(decoded, { to: new Uint8Array(32).fill(7), transferCount: 9n, assetId: 0, amount: 1_230_000_000_000n });
  assert.throws(() => wh.decodeZkLeaf(leaf.subarray(0, 59)));
});

test("merklePositions sorts siblings and reports positions", () => {
  const h = (b) => new Uint8Array(32).fill(b);
  const path = wh.merklePositions([[h(1), h(200), h(50)], [h(0), h(254), h(7)]], h(9));
  assert.equal(path.positions.length, 2);
  assert.equal(path.positions[0], 1);
  assert.deepEqual(path.sortedSiblings[0], [h(1), h(50), h(200)]);
  assert.equal(path.root.length, 32);
});

test("leaf proof: verify, parse, reject tampering", () => {
  const i = wh.verifyLeafProof(LEAF);
  assert.equal(i.blockNumber, 1);
  assert.equal(i.volumeFeeBps, 10);
  assert.equal(hex(i.exitAccount1), LEAF_INPUT.exitAccount1);
  assert.equal(hex(i.blockHash), LEAF_INPUT.blockHash);
  const tampered = Uint8Array.from(LEAF);
  tampered[100] ^= 1;
  assert.throws(() => wh.verifyLeafProof(tampered), /verification/);
  assert.throws(() => wh.parseLeafProof(new Uint8Array([...LEAF, 0])), /canonically/);
});

test("proveLeaf proves the fixture deposit", async () => {
  const expected = wh.verifyLeafProof(LEAF);
  const { proof, nullifier } = await wh.proveLeaf(LEAF_INPUT);
  assert.equal(proof.length, LEAF.length);
  assert.deepEqual(wh.verifyLeafProof(proof), expected);
  assert.equal(hex(nullifier), hex(wh.nullifier(LEAF_INPUT.secret, LEAF_INPUT.transferCount)));
  const derived = await wh.proveLeaf({ ...LEAF_INPUT, wormholeAddress: undefined, exitAccount2: undefined, outputAmount2: undefined });
  assert.deepEqual(wh.verifyLeafProof(derived.proof), expected);
  await assert.rejects(wh.proveLeaf({ ...LEAF_INPUT, wormholeAddress: "0x" + "11".repeat(32) }), /not derived/);
});

test("aggregatePrivateBatch produces a verifiable 7-slot batch", async () => {
  const batch = await wh.aggregatePrivateBatch([LEAF]);
  const i = wh.verifyPrivateBatchProof(batch);
  assert.equal(i.numExitSlots, 14);
  assert.equal(i.exits.length, 14);
  assert.equal(i.nullifiers.length, 7);
  assert.equal(i.blockNumber, 1);
  assert.ok(i.nullifiers.some((n) => hex(n) === hex(wh.parseLeafProof(LEAF).nullifier)));
  await assert.rejects(wh.aggregatePrivateBatch([]), /no leaf proofs/);
});

// Layer 2 needs about 7 GB and a quarter minute; opt in with WORMHOLE_TEST_PUBLIC_BATCH=1.
test("aggregatePublicBatch produces a verifiable 53-segment batch", { skip: !process.env.WORMHOLE_TEST_PUBLIC_BATCH }, async () => {
  const aggregator = new Uint8Array(32).fill(9);
  const batch = await wh.aggregatePublicBatch([PRIVATE_BATCH], aggregator);
  const i = wh.verifyPublicBatchProof(batch);
  assert.deepEqual(i.aggregatorAddress, aggregator);
  assert.equal(i.segments.length, 53);
  const inner = wh.parsePrivateBatchProof(PRIVATE_BATCH).nullifiers.map(hex);
  const all = new Set(i.segments.flatMap((s) => s.nullifiers.map(hex)));
  assert.ok(inner.every((n) => all.has(n)));
  await assert.rejects(wh.aggregatePublicBatch([LEAF], aggregator), /proof 0/);
});

test("chain fixtures verify with the embedded verifiers", () => {
  const p = wh.verifyPrivateBatchProof(PRIVATE_BATCH);
  assert.equal(p.exits.length, 14);
  assert.equal(p.volumeFeeBps, 4);
  const q = wh.verifyPublicBatchProof(PUBLIC_BATCH);
  assert.equal(q.segments.length, 53);
  assert.equal(q.totalExitSlots, 742);
  assert.ok(q.segments.every((s) => s.exits.length === 14 && s.nullifiers.length === 7));
  assert.equal(q.aggregatorAddress.length, 32);
  assert.throws(() => wh.verifyPublicBatchProof(PRIVATE_BATCH));
});

test("settlement extrinsics and status keys match polkadot.js encodings", () => {
  const proof = new Uint8Array(300).fill(0xab);
  const xt = wh.encodeVerifyPrivateBatch(proof);
  const body = Uint8Array.from([0x04, 20, 2, ...compactToU8a(proof.length), ...proof]);
  assert.deepEqual(xt, Uint8Array.from([...compactToU8a(body.length), ...body]));
  assert.equal(wh.encodeVerifyPublicBatch(proof)[compactToU8a(body.length).length + 2], 3);
  assert.equal(wh.extrinsicHash(xt), blake2AsHex(xt, 256));

  const n = new Uint8Array(32).fill(5);
  assert.equal(
    wh.usedNullifierStorageKey(n),
    xxhashAsHex("Wormhole", 128) + xxhashAsHex("UsedNullifiers", 128).slice(2) + blake2AsHex(n, 128).slice(2) + hex(n).slice(2)
  );
});
