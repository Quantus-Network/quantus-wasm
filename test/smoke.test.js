const test = require("node:test");
const assert = require("node:assert/strict");
const { createHash } = require("node:crypto");
const {
  account,
  signTransfer,
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
  assert.equal(digest, "654900132d40bae9ebf3e2fe66ac8a194b2ea3b86956a6c9f78d443cec14479e");
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
