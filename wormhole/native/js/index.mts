/**
 * Quantus wormhole for Node.js: deposit keys, leaf, private-batch and
 * public-batch proving on all CPU cores, local verification of every layer,
 * and the unsigned settlement extrinsics.
 *
 * This is a typed API over the native addon in `binding.js` (napi-rs), which
 * is built from the chain's own circuit crates pinned to the runtime's
 * versions. `await init()` once; proving functions return promises and run
 * off the event loop.
 */
import { createRequire } from "node:module";
import { availableParallelism } from "node:os";

type Native = typeof import("../binding.js");
type RawLeafPublicInputs = import("../binding.js").LeafPublicInputs;
type RawExit = import("../binding.js").Exit;
type RawPrivateBatchPublicInputs = import("../binding.js").PrivateBatchPublicInputs;
type RawPublicBatchPublicInputs = import("../binding.js").PublicBatchPublicInputs;
type Hex = string;

/** Raw bytes, an array of byte values (as JSON-RPC returns), or `0x` hex. */
export type Bytes = Uint8Array | number[] | string;
/** An account: SS58 address, `0x` hex 32-byte id, or raw bytes. */
export type Account = Bytes;

/** Volume fee the runtime charges on wormhole exits, in basis points. */
export const VOLUME_FEE_BPS = 4;
/** Chain plancks per circuit amount unit (12 decimals -> 2 decimals). */
export const SCALE_DOWN_FACTOR = 10_000_000_000n;
export const WORMHOLE_PALLET_INDEX = 20;

export interface InitOptions {
  /** Threads for proving (default: every core). */
  threads?: number;
}

let native: Native | undefined;

/** Load the native binary for this platform and size the proving pool. Idempotent. */
export async function init(opts: InitOptions = {}): Promise<void> {
  if (native) return;
  const threads = opts.threads ?? availableParallelism();
  if (!Number.isInteger(threads) || threads < 1) throw new TypeError("threads must be a positive integer");
  let mod: Native;
  try {
    mod = createRequire(import.meta.url)("../binding.js") as Native;
  } catch (e) {
    throw new Error(
      `@quantus-network/wormhole: no native binary for ${process.platform}-${process.arch}; install with optional dependencies or build from source (${(e as Error).message})`
    );
  }
  mod.initThreadPool(threads);
  native = mod;
}

function n(): Native {
  if (!native) throw new Error("call await init() first");
  return native;
}

function toBytes(value: Bytes, field: string): Uint8Array {
  if (value instanceof Uint8Array) return value;
  if (Array.isArray(value)) return Uint8Array.from(value);
  if (typeof value === "string") {
    const hex = value.startsWith("0x") ? value.slice(2) : value;
    if (hex.length % 2 !== 0 || /[^0-9a-fA-F]/.test(hex)) throw new TypeError(`${field} must be hex, a byte array, or Uint8Array`);
    return Uint8Array.from(Buffer.from(hex, "hex"));
  }
  throw new TypeError(`${field} must be hex, a byte array, or Uint8Array`);
}

function toHex(value: Bytes, field: string): Hex {
  return "0x" + Buffer.from(toBytes(value, field)).toString("hex");
}

function toAccount(value: Account, field: string): string {
  if (typeof value === "string" && !value.startsWith("0x")) return value;
  return toHex(value, field);
}

function fromHex(hex: Hex): Uint8Array {
  return Uint8Array.from(Buffer.from(hex.slice(2), "hex"));
}

function toDecimal(value: bigint | string | number, field: string): string {
  if (typeof value === "bigint") return value.toString();
  if (typeof value === "number" && Number.isInteger(value) && value >= 0) return value.toString();
  if (typeof value === "string") return value;
  throw new TypeError(`${field} must be a bigint, non-negative integer, or decimal string`);
}

function toCount(value: number | bigint, field: string): number {
  const c = typeof value === "bigint" ? Number(value) : value;
  if (!Number.isSafeInteger(c) || c < 0) throw new TypeError(`${field} must be a non-negative safe integer`);
  return c;
}

/**
 * N-API converts JS numbers to Rust `u32` with ToUint32 semantics (NaN -> 0,
 * fractions truncated, out-of-range wrapped), so every u32 is range-checked
 * here; a bad amount must be an error, not a different amount.
 */
function toU32(value: unknown, field: string): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0 || value > 0xffff_ffff) {
    throw new TypeError(`${field} must be an integer between 0 and 4294967295`);
  }
  return value;
}

function toPositions(value: unknown, field: string): number[] {
  if (!Array.isArray(value)) throw new TypeError(`${field} must be an array`);
  return value.map((p, i) => {
    if (typeof p !== "number" || !Number.isInteger(p) || p < 0 || p > 3) throw new TypeError(`${field}[${i}] must be an integer between 0 and 3`);
    return p;
  });
}

/** Leaf proofs aggregated per private batch (7 on Quantus). */
export function numLeafProofs(): number {
  return n().numLeafProofs();
}

/** Private batches aggregated per public batch (53 on Quantus). */
export function numPrivateBatchProofs(): number {
  return n().numPrivateBatchProofs();
}

/** Threads in the proving pool. */
export function threadCount(): number {
  return n().threadCount();
}

export interface WormholeAccount {
  /** 32-byte unspendable deposit account `H(H("wormhole" || secret))`. */
  accountId: Uint8Array;
  /** SS58 address (prefix 189) to send deposits to. */
  address: string;
}

export interface WormholeKey extends WormholeAccount {
  /** 32-byte secret at the wormhole HD path. Keep private. */
  secret: Uint8Array;
}

/** Deposit address for a 32-byte secret. */
export function wormholeAddress(secret: Bytes): WormholeAccount {
  const a = n().wormholeAddress(toBytes(secret, "secret"));
  return { accountId: fromHex(a.accountId), address: a.address };
}

export interface WormholeMnemonicOptions {
  /** Address index of `m/44'/189189189'/0'/0'/<index>'` (default 0). */
  index?: number;
  passphrase?: string;
}

/** Secret and deposit address from a BIP39 mnemonic, as the Quantus wallets derive them. */
export function wormholeFromMnemonic(mnemonic: string, opts: WormholeMnemonicOptions = {}): WormholeKey {
  const a = n().wormholeFromMnemonic(mnemonic, toU32(opts.index ?? 0, "index"), opts.passphrase);
  return { secret: fromHex(a.secret as Hex), accountId: fromHex(a.accountId), address: a.address };
}

/** Nullifier `H(H(salt || secret || transferCount))` of one deposit. */
export function nullifier(secret: Bytes, transferCount: number | bigint): Uint8Array {
  return n().nullifier(toBytes(secret, "secret"), toCount(transferCount, "transferCount"));
}

export interface ZkLeaf {
  /** Recipient (the wormhole address). */
  to: Uint8Array;
  transferCount: bigint;
  assetId: number;
  /** Plancks. */
  amount: bigint;
}

/** Decode the SCALE `ZkLeaf` in `zkTree_getMerkleProof`'s `leaf_data`. */
export function decodeZkLeaf(leafData: Bytes): ZkLeaf {
  const l = n().decodeZkLeaf(toBytes(leafData, "leafData"));
  return { to: fromHex(l.to), transferCount: BigInt(l.transferCount), assetId: l.assetId, amount: BigInt(l.amount) };
}

/** Plancks to the circuit's 0.01 QTC units (rounds down). */
export function quantize(plancks: bigint | string | number): number {
  return n().quantize(toDecimal(plancks, "plancks"));
}

/** Circuit units back to plancks. */
export function dequantize(quantized: number): bigint {
  return BigInt(n().dequantize(toU32(quantized, "quantized")));
}

/** Largest output the circuit allows for `inputQuantized` after the volume fee. */
export function outputAfterFee(inputQuantized: number, feeBps: number = VOLUME_FEE_BPS): number {
  return n().outputAfterFee(toU32(inputQuantized, "inputQuantized"), toU32(feeBps, "feeBps"));
}

export interface MerklePath {
  /** Siblings per level in the circuit's sorted order. */
  sortedSiblings: Uint8Array[][];
  /** Position (0-3) of the running hash at each level. */
  positions: number[];
  /** Root the path folds to; must equal the tree root fetched from the node. */
  root: Uint8Array;
}

/** Prepare `zkTree_getMerkleProof`'s unsorted `siblings` for the circuit. */
export function merklePositions(siblings: Bytes[][], leafHash: Bytes): MerklePath {
  const levels = siblings.map((level, i) => level.map((h) => toHex(h, `siblings[${i}]`)));
  const p = n().merklePositions(levels, toBytes(leafHash, "leafHash"));
  return { sortedSiblings: p.sortedSiblings.map((level) => level.map(fromHex)), positions: Array.from(p.positions), root: fromHex(p.root) };
}

export interface LeafProofInput {
  secret: Bytes;
  /** `transfer_count` of the deposit (from the `ZkLeaf` or the `NativeTransferred` event). */
  transferCount: number | bigint;
  /** Deposit address; derived from `secret` when omitted. */
  wormholeAddress?: Account;
  /** Deposit amount in circuit units (`quantize(leaf.amount)`). */
  inputAmount: number;
  /** Header of the block the Merkle proof was fetched at. */
  blockHash: Bytes;
  blockNumber: number;
  parentHash: Bytes;
  stateRoot: Bytes;
  extrinsicsRoot: Bytes;
  /** SCALE-encoded header digest (`chain_getHeader().digest`), at most 110 bytes. */
  digest: Bytes;
  /** ZK tree root at that block (`zkTree_getMerkleProof().root`). */
  zkTreeRoot: Bytes;
  sortedSiblings: Bytes[][];
  positions: number[];
  exitAccount1: Account;
  /** Circuit units; `outputAmount1 + outputAmount2 <= outputAfterFee(inputAmount)` across the batch. */
  outputAmount1: number;
  exitAccount2?: Account;
  outputAmount2?: number;
  /** Default `VOLUME_FEE_BPS`; must match the runtime. */
  volumeFeeBps?: number;
  /** Default 0 (native); the runtime accepts only native. */
  assetId?: number;
}

export interface LeafProof {
  proof: Uint8Array;
  nullifier: Uint8Array;
}

const ZERO32 = "0x" + "00".repeat(32);

/** Prove one deposit (layer 0). */
export async function proveLeaf(input: LeafProofInput): Promise<LeafProof> {
  const secret = toBytes(input.secret, "secret");
  return n().proveLeaf({
    secret: toHex(secret, "secret"),
    transferCount: toCount(input.transferCount, "transferCount"),
    wormholeAddress: input.wormholeAddress === undefined ? n().wormholeAddress(secret).accountId : toAccount(input.wormholeAddress, "wormholeAddress"),
    inputAmount: toU32(input.inputAmount, "inputAmount"),
    blockHash: toHex(input.blockHash, "blockHash"),
    blockNumber: toU32(input.blockNumber, "blockNumber"),
    parentHash: toHex(input.parentHash, "parentHash"),
    stateRoot: toHex(input.stateRoot, "stateRoot"),
    extrinsicsRoot: toHex(input.extrinsicsRoot, "extrinsicsRoot"),
    digest: toHex(input.digest, "digest"),
    zkTreeRoot: toHex(input.zkTreeRoot, "zkTreeRoot"),
    sortedSiblings: input.sortedSiblings.map((level, i) => level.map((h) => toHex(h, `sortedSiblings[${i}]`))),
    positions: toPositions(input.positions, "positions"),
    exitAccount1: toAccount(input.exitAccount1, "exitAccount1"),
    outputAmount1: toU32(input.outputAmount1, "outputAmount1"),
    exitAccount2: input.exitAccount2 === undefined ? ZERO32 : toAccount(input.exitAccount2, "exitAccount2"),
    outputAmount2: toU32(input.outputAmount2 ?? 0, "outputAmount2"),
    volumeFeeBps: toU32(input.volumeFeeBps ?? VOLUME_FEE_BPS, "volumeFeeBps"),
    assetId: toU32(input.assetId ?? 0, "assetId"),
  });
}

/**
 * Aggregate up to `numLeafProofs()` leaf proofs into one private-batch proof
 * (layer 1), padded with dummies. A few seconds on all cores.
 */
export function aggregatePrivateBatch(leafProofs: Bytes[]): Promise<Uint8Array> {
  return n().aggregatePrivateBatch(leafProofs.map((p, i) => toBytes(p, `leafProofs[${i}]`)));
}

/**
 * Aggregate up to `numPrivateBatchProofs()` private-batch proofs into one
 * public-batch proof (layer 2), padded with dummies. `aggregatorAddress`
 * receives the rebate from the burn share of the fee. Needs about 7 GB and a
 * quarter minute on a 10-core machine.
 */
export function aggregatePublicBatch(privateBatchProofs: Bytes[], aggregatorAddress: Account): Promise<Uint8Array> {
  return n().aggregatePublicBatch(
    privateBatchProofs.map((p, i) => toBytes(p, `privateBatchProofs[${i}]`)),
    toAccount(aggregatorAddress, "aggregatorAddress")
  );
}

export interface LeafPublicInputs {
  assetId: number;
  outputAmount1: number;
  outputAmount2: number;
  volumeFeeBps: number;
  nullifier: Uint8Array;
  exitAccount1: Uint8Array;
  exitAccount2: Uint8Array;
  blockHash: Uint8Array;
  blockNumber: number;
  inputAmount: number;
}

export interface Exit {
  account: Uint8Array;
  /** Circuit units; zero for dummy or deduplicated slots. */
  amount: number;
}

export interface PrivateBatchPublicInputs {
  numExitSlots: number;
  assetId: number;
  volumeFeeBps: number;
  blockHash: Uint8Array;
  blockNumber: number;
  exits: Exit[];
  nullifiers: Uint8Array[];
}

export interface Segment {
  exits: Exit[];
  nullifiers: Uint8Array[];
}

export interface PublicBatchPublicInputs {
  aggregatorAddress: Uint8Array;
  assetId: number;
  volumeFeeBps: number;
  blockHash: Uint8Array;
  blockNumber: number;
  totalExitSlots: number;
  /** One per inner private batch, in order. */
  segments: Segment[];
}

function leafInputs(i: RawLeafPublicInputs): LeafPublicInputs {
  return { ...i, nullifier: fromHex(i.nullifier), exitAccount1: fromHex(i.exitAccount1), exitAccount2: fromHex(i.exitAccount2), blockHash: fromHex(i.blockHash) };
}

function exits(list: RawExit[]): Exit[] {
  return list.map((e) => ({ account: fromHex(e.account), amount: e.amount }));
}

function privateBatchInputs(i: RawPrivateBatchPublicInputs): PrivateBatchPublicInputs {
  return { ...i, blockHash: fromHex(i.blockHash), exits: exits(i.exits), nullifiers: i.nullifiers.map(fromHex) };
}

function publicBatchInputs(i: RawPublicBatchPublicInputs): PublicBatchPublicInputs {
  return {
    ...i,
    aggregatorAddress: fromHex(i.aggregatorAddress),
    blockHash: fromHex(i.blockHash),
    segments: i.segments.map((s) => ({ exits: exits(s.exits), nullifiers: s.nullifiers.map(fromHex) })),
  };
}

/** Public inputs of a leaf proof, without the cryptographic check. */
export function parseLeafProof(proof: Bytes): LeafPublicInputs {
  return leafInputs(n().parseLeafProof(toBytes(proof, "proof")));
}

/** Verify a leaf proof locally; throws if invalid. */
export function verifyLeafProof(proof: Bytes): LeafPublicInputs {
  return leafInputs(n().verifyLeafProof(toBytes(proof, "proof")));
}

export function parsePrivateBatchProof(proof: Bytes): PrivateBatchPublicInputs {
  return privateBatchInputs(n().parsePrivateBatchProof(toBytes(proof, "proof")));
}

/** Verify with the same verifier the runtime embeds; throws if invalid. */
export function verifyPrivateBatchProof(proof: Bytes): PrivateBatchPublicInputs {
  return privateBatchInputs(n().verifyPrivateBatchProof(toBytes(proof, "proof")));
}

export function parsePublicBatchProof(proof: Bytes): PublicBatchPublicInputs {
  return publicBatchInputs(n().parsePublicBatchProof(toBytes(proof, "proof")));
}

/** Verify with the same verifier the runtime embeds; throws if invalid. */
export function verifyPublicBatchProof(proof: Bytes): PublicBatchPublicInputs {
  return publicBatchInputs(n().verifyPublicBatchProof(toBytes(proof, "proof")));
}

/** Unsigned `wormhole.verify_private_batch(proof)` extrinsic for `author_submitExtrinsic`. */
export function encodeVerifyPrivateBatch(proof: Bytes): Uint8Array {
  return n().encodeVerifyPrivateBatch(toBytes(proof, "proof"));
}

/** Unsigned `wormhole.verify_public_batch(proof)` extrinsic for `author_submitExtrinsic`. */
export function encodeVerifyPublicBatch(proof: Bytes): Uint8Array {
  return n().encodeVerifyPublicBatch(toBytes(proof, "proof"));
}

/** `state_getStorage` key of `Wormhole.UsedNullifiers(nullifier)`; non-null value means settled. */
export function usedNullifierStorageKey(nullifier: Bytes): string {
  return n().usedNullifierStorageKey(toBytes(nullifier, "nullifier"));
}

/** Hash `author_submitExtrinsic` returns for an extrinsic. */
export function extrinsicHash(extrinsic: Bytes): string {
  return n().extrinsicHash(toBytes(extrinsic, "extrinsic"));
}
