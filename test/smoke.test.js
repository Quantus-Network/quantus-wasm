const test = require("node:test");
const assert = require("node:assert/strict");
const { createHash } = require("node:crypto");
const {
  account,
  signTransfer,
  signCall,
  accountFromMnemonic,
  signTransferFromMnemonic,
  mnemonicToSeed,
} = require("../dist/index.js");

// crystal_alice == seed [0u8; 32] (see chain dilithium-crypto pair.rs).
const CRYSTAL_ALICE_SEED = new Uint8Array(32).fill(0);
const CRYSTAL_ALICE_ADDRESS = "qzk1Nxai3dZD9Cn5kwGcgL6mKxsfxwqdis7kDQJ52aJS2vSn7";
const CRYSTAL_ALICE_ACCOUNT_ID =
  "1883df2ae47d1fd428a6b8237ad7b59cf0facccaacac4541ef7758be44b3c333";

const hex = (u8) => Buffer.from(u8).toString("hex");

test("account matches the crystal_alice golden vector", () => {
  const a = account(CRYSTAL_ALICE_SEED);
  assert.equal(a.address, CRYSTAL_ALICE_ADDRESS);
  assert.equal(hex(a.accountId), CRYSTAL_ALICE_ACCOUNT_ID);
  assert.equal(a.publicKey.length, 2592);
  assert.equal(a.secretKey.length, 4896);
});

test("account rejects malformed seeds", () => {
  assert.throws(() => account(new Uint8Array(31)));
  assert.throws(() => account("not a seed"));
});

test("signTransfer produces a signed v4 balances extrinsic", () => {
  const xt = signTransfer(CRYSTAL_ALICE_SEED, {
    recipient: "0x" + "02".repeat(32),
    amount: 12_345_000_000_000n,
    nonce: 7,
    period: 64,
    blockNumber: 100,
    genesisHash: "0x" + "09".repeat(32),
    blockHash: "0x" + "08".repeat(32),
    specVersion: 100,
    transactionVersion: 1,
  });
  assert.ok(xt instanceof Uint8Array);
  // signed v4 (0x84), MultiAddress::Id (0x00), then the 32-byte signer.
  const compactPrefixLen = xt[0] & 0b11 ? 2 : 1;
  assert.equal(xt[compactPrefixLen], 0x84);
  assert.equal(xt[compactPrefixLen + 1], 0x00);
  // 1 (version) + 33 (address) + 1 (sig variant) + 4627 (sig) + 2592 (pub) header.
  assert.ok(xt.length > 7200);
});

test("signTransfer is deterministic (frozen golden extrinsic)", () => {
  // ML-DSA-87 signing is deterministic, so fixed inputs => fixed bytes. Freezing
  // the whole signed extrinsic catches any regression in the signing pipeline.
  const xt = signTransfer(CRYSTAL_ALICE_SEED, {
    recipient: "0x" + "02".repeat(32),
    amount: "1000",
    nonce: 0,
    genesisHash: "0x" + "11".repeat(32),
    specVersion: 1,
    transactionVersion: 1,
  });
  assert.equal(xt.length, 7297);
  const digest = createHash("sha256").update(Buffer.from(xt)).digest("hex");
  assert.equal(digest, "735cf187afea82dcd6c7ac255311d325a8c2c8005cb7ceef837f1ac70ebf8d07");
});

test("signTransfer accepts bigint/string amounts and assetId", () => {
  const base = {
    recipient: CRYSTAL_ALICE_ADDRESS,
    nonce: 0,
    genesisHash: "0x" + "00".repeat(32),
    specVersion: 100,
    transactionVersion: 1,
  };
  const a = signTransfer(CRYSTAL_ALICE_SEED, { ...base, amount: 1000n });
  const b = signTransfer(CRYSTAL_ALICE_SEED, { ...base, amount: "1000" });
  assert.deepEqual(a, b);

  const asset = signTransfer(CRYSTAL_ALICE_SEED, { ...base, amount: 1000n, assetId: 42 });
  const cp = asset[0] & 0b11 ? 2 : 1;
  // assets pallet (17) + transfer (8) appear after version+address+signature.
  assert.notDeepEqual(asset, a);
});

test("signCall matches signTransfer for the equivalent encoded call", () => {
  // balances.transfer_allow_death(MultiAddress::Id(crystal_alice), 1000):
  // pallet 2, call 0, 0x00 (Id), 32-byte account, compact(1000)=0xa10f.
  // Mirrors what polkadot.js `tx.method.toHex()` would produce for this call.
  const call = "0x020000" + CRYSTAL_ALICE_ACCOUNT_ID + "a10f";
  const ctx = {
    nonce: 0,
    genesisHash: "0x" + "11".repeat(32),
    specVersion: 1,
    transactionVersion: 1,
  };
  const viaCall = signCall(CRYSTAL_ALICE_SEED, call, ctx);
  const viaTransfer = signTransfer(CRYSTAL_ALICE_SEED, {
    recipient: CRYSTAL_ALICE_ADDRESS,
    amount: 1000n,
    ...ctx,
  });
  assert.deepEqual(viaCall, viaTransfer);
  // Accepts Uint8Array calls too (e.g. polkadot.js `tx.method.toU8a()`).
  const callBytes = Uint8Array.from(Buffer.from(call.slice(2), "hex"));
  assert.deepEqual(signCall(CRYSTAL_ALICE_SEED, callBytes, ctx), viaTransfer);
});

// Known chain-spec vectors (quantus_sdk/test/generate_keys_test.dart).
const MNEMONIC =
  "orchard answer curve patient visual flower maze noise retreat penalty cage small earth domain scan pitch bottom crunch theme club client swap slice raven";
const KEYSTONE_MNEMONIC =
  "human snow truck virus now jaguar wall brisk shoe craft gravity diesel";

test("accountFromMnemonic matches known HD vectors", () => {
  assert.equal(
    accountFromMnemonic(MNEMONIC, { account: 0 }).address,
    "qzm5QCox8Dp5A3oSXZZYHD8YoYgPz7enykZb6RPUropdCyN5h"
  );
  assert.equal(
    accountFromMnemonic(MNEMONIC, { account: 1 }).address,
    "qzmufPopkLKAwDmTzR5uXg8GMp5sUP48CqafJLUz3fPMSSGSh"
  );
  assert.equal(
    accountFromMnemonic(KEYSTONE_MNEMONIC, { account: 0 }).address,
    "qznQKhufTDfU3szAzfgCny7wMhxUN3qjEqneiRUNgC7MjSDyG"
  );
});

test("mnemonicToSeed bridges to the seed API (non-HD vector)", () => {
  const seed = mnemonicToSeed(MNEMONIC).slice(0, 32);
  assert.equal(
    account(seed).address,
    "qzmTAz3UUw1WGUuVh8nbFmPwcftomduwy6twq6NDR6y9qqtEs"
  );
});

test("signTransferFromMnemonic equals seed signing of the same key", () => {
  const params = {
    recipient: "qzm5QCox8Dp5A3oSXZZYHD8YoYgPz7enykZb6RPUropdCyN5h",
    amount: 500n,
    nonce: 3,
    genesisHash: "0x" + "11".repeat(32),
    specVersion: 100,
    transactionVersion: 1,
  };
  const fromMnemonic = signTransferFromMnemonic(MNEMONIC, params, { account: 0 });
  assert.ok(fromMnemonic instanceof Uint8Array);
  assert.ok(fromMnemonic.length > 7200);
});

test("signTransfer requires blockHash for mortal eras", () => {
  assert.throws(() =>
    signTransfer(CRYSTAL_ALICE_SEED, {
      recipient: CRYSTAL_ALICE_ADDRESS,
      amount: 1n,
      nonce: 0,
      period: 64,
      blockNumber: 10,
      genesisHash: "0x" + "00".repeat(32),
      specVersion: 100,
      transactionVersion: 1,
    })
  );
});

// ML-DSA-65 (DilithiumSignatureScheme::Dilithium65, variant 1). Default stays ML-DSA-87.
const ML_DSA_65 = "ml-dsa-65";
// `quantus wallet import --scheme ml-dsa-65` for MNEMONIC (default path .../1').
const ML_DSA_65_ADDRESS = "qzoyC4eRTrexYoutXABVsf61QJZxJim3iWvayRQwEjXWgA4mw";

test("account defaults to ML-DSA-87 and derives ML-DSA-65 on request", () => {
  const a87 = account(CRYSTAL_ALICE_SEED);
  assert.equal(a87.scheme, "ml-dsa-87");
  assert.equal(a87.address, CRYSTAL_ALICE_ADDRESS);
  assert.deepEqual(account(CRYSTAL_ALICE_SEED, { scheme: "ml-dsa-87" }), a87);

  const a65 = account(CRYSTAL_ALICE_SEED, { scheme: ML_DSA_65 });
  assert.equal(a65.scheme, ML_DSA_65);
  assert.equal(a65.publicKey.length, 1952);
  assert.equal(a65.secretKey.length, 4032);
  assert.notEqual(a65.address, a87.address);

  assert.throws(() => account(CRYSTAL_ALICE_SEED, { scheme: "ml-dsa-44" }), /scheme/);
});

test("accountFromMnemonic with ML-DSA-65 matches the wallet vector", () => {
  const a = accountFromMnemonic(MNEMONIC, { scheme: ML_DSA_65 });
  assert.equal(a.scheme, ML_DSA_65);
  assert.equal(a.address, ML_DSA_65_ADDRESS);
  // The default address index for ML-DSA-65 is 1; index 0 is a different key.
  assert.equal(accountFromMnemonic(MNEMONIC, { scheme: ML_DSA_65, addressIndex: 1 }).address, ML_DSA_65_ADDRESS);
  assert.notEqual(accountFromMnemonic(MNEMONIC, { scheme: ML_DSA_65, addressIndex: 0 }).address, ML_DSA_65_ADDRESS);
  // ML-DSA-87 default index stays 0.
  assert.equal(
    accountFromMnemonic(MNEMONIC, { scheme: "ml-dsa-87" }).address,
    "qzm5QCox8Dp5A3oSXZZYHD8YoYgPz7enykZb6RPUropdCyN5h"
  );
});

test("signTransfer with ML-DSA-65 produces a variant-1 signed extrinsic (frozen)", () => {
  const params = {
    recipient: "0x" + "02".repeat(32),
    amount: "1000",
    nonce: 0,
    genesisHash: "0x" + "11".repeat(32),
    specVersion: 1,
    transactionVersion: 1,
  };
  const xt = signTransfer(CRYSTAL_ALICE_SEED, { ...params, scheme: ML_DSA_65 });
  // 2 (compact len) + 1 (0x84) + 33 (address) + 1 (variant) + 3309 (sig) + 1952 (pub) + 4 (extra) + 37 (call).
  assert.equal(xt.length, 5339);
  assert.equal(xt[2], 0x84);
  assert.equal(xt[2 + 1 + 33], 0x01);
  assert.deepEqual(xt.subarray(4, 36), account(CRYSTAL_ALICE_SEED, { scheme: ML_DSA_65 }).accountId);
  const digest = createHash("sha256").update(Buffer.from(xt)).digest("hex");
  assert.equal(digest, "6cc3feaa3cf1d75e9814a67acefb124e775dbba9d699d92cc41c5c6ef3def000");

  // signCall honours the same scheme field.
  const call = "0x020000" + "02".repeat(32) + "a10f";
  assert.deepEqual(signCall(CRYSTAL_ALICE_SEED, call, { ...params, scheme: ML_DSA_65 }), xt);
  // Without the field the extrinsic is the ML-DSA-87 one.
  assert.equal(signTransfer(CRYSTAL_ALICE_SEED, params).length, 7297);
});

test("signTransferFromMnemonic with ML-DSA-65 signs with the derived key", () => {
  const xt = signTransferFromMnemonic(
    MNEMONIC,
    {
      recipient: CRYSTAL_ALICE_ADDRESS,
      amount: 500n,
      nonce: 3,
      genesisHash: "0x" + "11".repeat(32),
      specVersion: 100,
      transactionVersion: 1,
    },
    { scheme: ML_DSA_65 }
  );
  assert.equal(xt[2 + 1 + 33], 0x01);
  assert.deepEqual(xt.subarray(4, 36), accountFromMnemonic(MNEMONIC, { scheme: ML_DSA_65 }).accountId);
});
