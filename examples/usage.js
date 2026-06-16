// Runnable example exercising every documented @quantus/wasm function.
//
//   npm run build && npm run example
//
// Chain context (genesisHash, blockHash, specVersion, nonce, ...) is hardcoded
// here for illustration. In a real signer you fetch these over RPC:
//   genesisHash       <- chain_getBlockHash(0)
//   specVersion/txVer <- state_getRuntimeVersion
//   nonce             <- system_accountNextIndex(address)
//   blockHash/number  <- chain_getHeader (for mortal eras)

const {
  account,
  signTransfer,
  accountFromMnemonic,
  signTransferFromMnemonic,
  mnemonicToSeed,
} = require("../dist/index.js");

const toHex = (u8) => "0x" + Buffer.from(u8).toString("hex");
const preview = (u8, n = 8) =>
  `${toHex(u8.slice(0, n))}… (${u8.length} bytes)`;

// A 32-byte seed. Use real entropy from your KMS / secure storage in production.
const seed = new Uint8Array(32).fill(0); // == chain dev account "crystal_alice"

// A valid BIP39 mnemonic (DO NOT use for real funds).
const mnemonic =
  "orchard answer curve patient visual flower maze noise retreat penalty cage small earth domain scan pitch bottom crunch theme club client swap slice raven";

// Shared chain context for the signing examples.
const ctx = {
  genesisHash: "0x" + "11".repeat(32),
  specVersion: 100,
  transactionVersion: 1,
};

console.log("== account(seed) ==");
const acct = account(seed);
console.log("address  :", acct.address);
console.log("accountId:", toHex(acct.accountId));
console.log("publicKey:", preview(acct.publicKey));
console.log("secretKey:", preview(acct.secretKey));

console.log("\n== accountFromMnemonic(mnemonic, { account }) ==");
const hd0 = accountFromMnemonic(mnemonic, { account: 0 });
const hd1 = accountFromMnemonic(mnemonic, { account: 1 });
console.log("HD account 0:", hd0.address);
console.log("HD account 1:", hd1.address);

console.log("\n== mnemonicToSeed(mnemonic) ==");
const seed64 = mnemonicToSeed(mnemonic);
console.log("seed (64b):", preview(seed64));
console.log("first-32 address:", account(seed64.slice(0, 32)).address);

console.log("\n== signTransfer(seed, params) — immortal balances transfer ==");
const balancesXt = signTransfer(seed, {
  recipient: hd0.address,
  amount: 1_000_000_000_000n, // plancks
  nonce: 0,
  ...ctx,
});
console.log("extrinsic:", preview(balancesXt, 6));
console.log("submit    : author_submitExtrinsic([", toHex(balancesXt).slice(0, 18) + "…", "])");

console.log("\n== signTransfer(seed, params) — assets transfer (assetId) ==");
const assetXt = signTransfer(seed, {
  recipient: hd0.address,
  amount: "5000",
  assetId: 1,
  nonce: 1,
  tip: 0n,
  ...ctx,
});
console.log("extrinsic:", preview(assetXt, 6));

console.log("\n== signTransfer(seed, params) — mortal era ==");
const mortalXt = signTransfer(seed, {
  recipient: hd0.address,
  amount: 1_000n,
  nonce: 2,
  period: 64,
  blockNumber: 0, // era anchor; its hash is blockHash
  blockHash: "0x" + "22".repeat(32),
  ...ctx,
});
console.log("extrinsic:", preview(mortalXt, 6));

console.log("\n== signTransferFromMnemonic(mnemonic, params, { account }) ==");
const fromMnemonicXt = signTransferFromMnemonic(
  mnemonic,
  { recipient: acct.address, amount: 42n, nonce: 0, ...ctx },
  { account: 0 }
);
console.log("signer    :", hd0.address);
console.log("extrinsic :", preview(fromMnemonicXt, 6));

console.log("\nAll documented functions invoked successfully.");
