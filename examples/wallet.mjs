// Minimal command-line wallet exercising @quantus-network/wasm against a live node.
//
//   node examples/wallet.mjs address [--account N]
//   node examples/wallet.mjs balance [address] [--rpc URL]
//   node examples/wallet.mjs send --to <address> --amount <plancks> [--account N] [--rpc URL]
//
// polkadot.js is used only for what it does best here: connecting, reading
// storage (balance/nonce), runtime metadata, and SCALE-encoding the call. The
// post-quantum signature is produced by this package, and the signed extrinsic
// is submitted via raw author_submitExtrinsic (it is too large for polkadot.js
// to re-decode).

import { parseArgs } from "node:util";
import { ApiPromise, HttpProvider } from "@polkadot/api";
import { mnemonicGenerate } from "@polkadot/util-crypto";
import * as quantus from "../dist/index.js";

const DEFAULT_RPC = "https://a1-planck.quantus.cat";

const HELP = `quantus wallet example

usage:
  node examples/wallet.mjs generate [--account N]
  node examples/wallet.mjs address [--account N] [--mnemonic "..."]
  node examples/wallet.mjs balance [address] [--rpc URL]
  node examples/wallet.mjs send --to <address> --amount <plancks> [--account N] [--rpc URL]

env:
  QUANTUS_RPC   RPC endpoint, overridden by --rpc   [default ${DEFAULT_RPC}]
  MNEMONIC      BIP39 mnemonic, overridden by --mnemonic
`;

function fail(message) {
  console.error(`error: ${message}`);
  process.exit(1);
}

function formatAmount(planck, decimals, symbol) {
  const digits = planck.toString().padStart(decimals + 1, "0");
  const whole = digits.slice(0, digits.length - decimals);
  const frac = digits.slice(digits.length - decimals).replace(/0+$/, "");
  return `${whole}${frac ? `.${frac}` : ""}${symbol ? ` ${symbol}` : ""}`;
}

async function connect(rpcUrl) {
  return ApiPromise.create({
    provider: new HttpProvider(rpcUrl),
    noInitWarn: true,
    // U512 (512-bit unsigned int) is referenced by the runtime metadata but not
    // a polkadot.js primitive; register it so it stops warning on decode.
    types: { U512: "[u8; 64]" },
  });
}

async function submit(rpcUrl, hex) {
  const res = await fetch(rpcUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "author_submitExtrinsic", params: [hex] }),
  });
  if (!res.ok) fail(`RPC ${res.status} ${res.statusText}`);
  const json = await res.json();
  if (json.error) fail(`author_submitExtrinsic: ${json.error.message}`);
  return json.result;
}

const { values, positionals } = parseArgs({
  allowPositionals: true,
  options: {
    rpc: { type: "string" },
    mnemonic: { type: "string" },
    to: { type: "string" },
    amount: { type: "string" },
    account: { type: "string" },
  },
});

const rpc = values.rpc ?? process.env.QUANTUS_RPC ?? DEFAULT_RPC;
const accountIndex = Number(values.account ?? 0);
const command = positionals[0];

function requireMnemonic() {
  const mnemonic = values.mnemonic ?? process.env.MNEMONIC;
  if (!mnemonic) fail("a mnemonic is required (set MNEMONIC or pass --mnemonic)");
  return mnemonic;
}

switch (command) {
  case "generate": {
    const mnemonic = mnemonicGenerate(24);
    const { address } = quantus.accountFromMnemonic(mnemonic, { account: accountIndex });
    console.log(`mnemonic: ${mnemonic}`);
    console.log(`address:  ${address}`);
    break;
  }

  case "address": {
    const { address } = quantus.accountFromMnemonic(requireMnemonic(), { account: accountIndex });
    console.log(address);
    break;
  }

  case "balance": {
    const address =
      positionals[1] ?? quantus.accountFromMnemonic(requireMnemonic(), { account: accountIndex }).address;
    const api = await connect(rpc);
    const decimals = api.registry.chainDecimals[0] ?? 12;
    const symbol = api.registry.chainTokens[0] ?? "";
    const { data, nonce } = await api.query.system.account(address);
    console.log(`address: ${address}`);
    console.log(`free:    ${formatAmount(data.free.toBigInt(), decimals, symbol)} (${data.free.toString()} planck)`);
    console.log(`nonce:   ${nonce.toNumber()}`);
    await api.disconnect();
    break;
  }

  case "send": {
    const to = values.to ?? fail("--to <address> is required");
    if (values.amount === undefined) fail("--amount <plancks> is required");
    const amount = BigInt(values.amount);
    const mnemonic = requireMnemonic();
    const sender = quantus.accountFromMnemonic(mnemonic, { account: accountIndex });

    const api = await connect(rpc);
    const { nonce } = await api.query.system.account(sender.address);
    // Encode the call directly: building a SubmittableExtrinsic would force
    // polkadot.js to instantiate the 7219-byte Dilithium signature type (> its
    // 2048 array cap) and throw.
    const call = api.registry
      .createType("Call", {
        callIndex: api.tx.balances.transferAllowDeath.callIndex,
        args: { dest: to, value: amount },
      })
      .toHex();
    const extrinsic = quantus.signCallFromMnemonic(
      mnemonic,
      call,
      {
        nonce: nonce.toNumber(),
        genesisHash: api.genesisHash.toHex(),
        specVersion: api.runtimeVersion.specVersion.toNumber(),
        transactionVersion: api.runtimeVersion.transactionVersion.toNumber(),
      },
      { account: accountIndex }
    );
    await api.disconnect();

    const txHash = await submit(rpc, "0x" + Buffer.from(extrinsic).toString("hex"));
    console.log(`from:   ${sender.address}`);
    console.log(`to:     ${to}`);
    console.log(`amount: ${amount} planck`);
    console.log(`tx:     ${txHash}`);
    break;
  }

  default:
    console.log(HELP);
    if (command !== undefined) process.exit(1);
}
