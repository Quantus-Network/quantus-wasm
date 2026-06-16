/**
 * Quantus account derivation and ML-DSA-87 transaction signing.
 *
 * Thin, typed wrapper over the wasm produced from the chain's own crypto crates
 * (`qp-poseidon-core`, `qp-rusty-crystals-dilithium`). No cryptography or
 * extrinsic encoding is reimplemented here; this layer only marshals JS types
 * (bigint, hex, Uint8Array) across the wasm boundary.
 */
import * as wasm from "../pkg/quantus_wasm.js";

/** Material derived from a 32-byte seed. */
export interface QuantusAccount {
  /** ML-DSA-87 public key (2592 bytes). */
  publicKey: Uint8Array;
  /** ML-DSA-87 secret key (4896 bytes). */
  secretKey: Uint8Array;
  /** 32-byte Poseidon `AccountId32`. */
  accountId: Uint8Array;
  /** SS58 address encoded with the Quantus prefix (189). */
  address: string;
}

/** A 32-byte hash, as raw bytes or a `0x`-prefixed hex string. */
export type Hash = Uint8Array | string;
/** A u128 amount, as a bigint, decimal string, or (small) number. */
export type Amount = bigint | string | number;
/** A recipient: SS58 address, `0x`-hex 32-byte id, or raw 32-byte id. */
export type Recipient = string | Uint8Array;

/** A SCALE-encoded `RuntimeCall` (e.g. polkadot.js `tx.method.toU8a()` / `.toHex()`). */
export type Call = Uint8Array | string;

/** Chain context shared by every signed extrinsic. */
export interface CallParams {
  nonce: number | bigint;
  /** Tip in plancks; defaults to 0. */
  tip?: Amount;
  /** Mortal era period in blocks; `0`/omitted means immortal. */
  period?: number | bigint;
  /** Reference block number the mortal era is anchored to. */
  blockNumber?: number | bigint;
  genesisHash: Hash;
  /** Required for mortal eras (period > 0). */
  blockHash?: Hash;
  specVersion: number;
  transactionVersion: number;
}

export interface TransferParams extends CallParams {
  recipient: Recipient;
  amount: Amount;
  /** When set, builds an `assets.transfer`; otherwise `balances.transfer_allow_death`. */
  assetId?: number;
}

const SEED_BYTES = 32;

function asSeed(seed: Uint8Array): Uint8Array {
  if (!(seed instanceof Uint8Array) || seed.length !== SEED_BYTES) {
    throw new TypeError(`seed must be a ${SEED_BYTES}-byte Uint8Array`);
  }
  return seed;
}

function toHex(value: Hash, field: string): string {
  if (typeof value === "string") return value;
  if (value instanceof Uint8Array) {
    return "0x" + Buffer.from(value).toString("hex");
  }
  throw new TypeError(`${field} must be a hex string or Uint8Array`);
}

function toDecimal(value: Amount, field: string): string {
  switch (typeof value) {
    case "bigint":
      return value.toString();
    case "number":
      if (!Number.isInteger(value) || value < 0) {
        throw new TypeError(`${field} must be a non-negative integer`);
      }
      return value.toString();
    case "string":
      return value;
    default:
      throw new TypeError(`${field} must be a bigint, integer, or decimal string`);
  }
}

function toNumber(value: number | bigint, field: string): number {
  const n = typeof value === "bigint" ? Number(value) : value;
  if (!Number.isInteger(n) || n < 0) {
    throw new TypeError(`${field} must be a non-negative integer`);
  }
  return n;
}

function toRecipient(value: Recipient): string {
  if (typeof value === "string") return value;
  if (value instanceof Uint8Array) return toHex(value, "recipient");
  throw new TypeError("recipient must be an SS58 string, hex string, or Uint8Array");
}

function toBytes(value: Call, field: string): Uint8Array {
  if (value instanceof Uint8Array) return value;
  if (typeof value === "string") {
    const hex = value.startsWith("0x") ? value.slice(2) : value;
    if (hex.length % 2 !== 0 || /[^0-9a-fA-F]/.test(hex)) {
      throw new TypeError(`${field} must be a hex string or Uint8Array`);
    }
    return Uint8Array.from(Buffer.from(hex, "hex"));
  }
  throw new TypeError(`${field} must be a hex string or Uint8Array`);
}

/** Quantus HD derivation indices and BIP39 passphrase. */
export interface MnemonicOptions {
  /** BIP44 account index (default 0). */
  account?: number;
  /** Change index (default 0). */
  change?: number;
  /** Address index (default 0). */
  addressIndex?: number;
  /** Optional BIP39 passphrase. */
  passphrase?: string;
}

function materialize(handle: wasm.Account): QuantusAccount {
  try {
    return {
      publicKey: handle.publicKey,
      secretKey: handle.secretKey,
      accountId: handle.accountId,
      address: handle.address,
    };
  } finally {
    handle.free();
  }
}

/** Derive the ML-DSA-87 keypair, Poseidon `AccountId32`, and SS58 address. */
export function account(seed: Uint8Array): QuantusAccount {
  return materialize(wasm.account(asSeed(seed)));
}

/**
 * Derive an account from a BIP39 mnemonic using the Quantus HD path
 * `m/44'/189189'/<account>'/<change>'/<addressIndex>'`.
 */
export function accountFromMnemonic(
  mnemonic: string,
  opts: MnemonicOptions = {}
): QuantusAccount {
  return materialize(
    wasm.accountFromMnemonic(
      mnemonic,
      opts.account ?? 0,
      opts.change ?? 0,
      opts.addressIndex ?? 0,
      opts.passphrase
    )
  );
}

/** BIP39 mnemonic -> 64-byte seed (bridge to the seed-based API). */
export function mnemonicToSeed(mnemonic: string, passphrase?: string): Uint8Array {
  return wasm.mnemonicToSeed(mnemonic, passphrase);
}

/**
 * Sign a balances/assets transfer, returning the SCALE-encoded v4 extrinsic
 * ready for `author_submitExtrinsic`.
 */
export function signTransfer(seed: Uint8Array, params: TransferParams): Uint8Array {
  return wasm.signTransfer(asSeed(seed), encodeTransfer(params));
}

/**
 * Sign a transfer from a BIP39 mnemonic using the Quantus HD path
 * `m/44'/189189'/<account>'/<change>'/<addressIndex>'`.
 */
export function signTransferFromMnemonic(
  mnemonic: string,
  params: TransferParams,
  opts: MnemonicOptions = {}
): Uint8Array {
  return wasm.signTransferFromMnemonic(
    mnemonic,
    encodeTransfer(params),
    opts.account ?? 0,
    opts.change ?? 0,
    opts.addressIndex ?? 0,
    opts.passphrase
  );
}

/**
 * Sign an arbitrary, already-encoded `RuntimeCall` (e.g. from polkadot.js
 * `api.tx.<pallet>.<method>(...).method.toU8a()` or `.toHex()`), returning the
 * SCALE-encoded v4 extrinsic ready for `author_submitExtrinsic`.
 */
export function signCall(seed: Uint8Array, call: Call, params: CallParams): Uint8Array {
  return wasm.signCall(asSeed(seed), toBytes(call, "call"), encodeContext(params));
}

/**
 * Sign an arbitrary `RuntimeCall` from a BIP39 mnemonic using the Quantus HD path
 * `m/44'/189189'/<account>'/<change>'/<addressIndex>'`.
 */
export function signCallFromMnemonic(
  mnemonic: string,
  call: Call,
  params: CallParams,
  opts: MnemonicOptions = {}
): Uint8Array {
  return wasm.signCallFromMnemonic(
    mnemonic,
    toBytes(call, "call"),
    encodeContext(params),
    opts.account ?? 0,
    opts.change ?? 0,
    opts.addressIndex ?? 0,
    opts.passphrase
  );
}

function encodeContext(params: CallParams): Record<string, unknown> {
  const period = params.period === undefined ? 0 : toNumber(params.period, "period");
  if (period > 0 && params.blockHash === undefined) {
    throw new TypeError("blockHash is required for mortal eras (period > 0)");
  }
  return {
    nonce: toNumber(params.nonce, "nonce"),
    tip: params.tip === undefined ? "0" : toDecimal(params.tip, "tip"),
    period,
    blockNumber:
      params.blockNumber === undefined ? 0 : toNumber(params.blockNumber, "blockNumber"),
    genesisHash: toHex(params.genesisHash, "genesisHash"),
    blockHash: params.blockHash === undefined ? undefined : toHex(params.blockHash, "blockHash"),
    specVersion: params.specVersion,
    transactionVersion: params.transactionVersion,
  };
}

function encodeTransfer(params: TransferParams): Record<string, unknown> {
  return {
    recipient: toRecipient(params.recipient),
    amount: toDecimal(params.amount, "amount"),
    assetId: params.assetId,
    ...encodeContext(params),
  };
}
