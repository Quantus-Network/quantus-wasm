const test = require("node:test");
const assert = require("node:assert/strict");
const { TypeRegistry } = require("@polkadot/types");
const { signCall } = require("../dist/index.js");

// Block 1233521 on a1-planck.quantus.cat: chain_getBlockHash(1233521), then
// chain_getHeader(hash). The chain hashes headers with Poseidon.
const BLOCK_NUMBER = 1233521;
const BLOCK_HASH = "0x1bb1bf45ad108fa7f1daaf9289cffe7fd2a4686ac0e49fbeac0b9aa92d0802aa";
const HEADER = {
  parentHash: "0x16b35db697f9e6c38c75db032431ca0db882c0d2760c5ff3cba1989ef133bff3",
  number: "0x12d271",
  stateRoot: "0xe2240c9a287eedd36558c4f3ceb3127cd596ef12175e0531d01c7b07b2b559f5",
  extrinsicsRoot: "0x2ebadcf147739198b4de8d3a74f352181c4f8233818a1d6d9fcf0552260c22d1",
  zkTreeRoot: "0xad1be08461a945622845df5e7afe593d734792ad8cfe9be18ec4d3e184e386f6",
  digest: {
    logs: [
      "0x06706f775f80792cfdaab9d9cfad6f0dcb69e0c2d6eb3f28dcf4bf9791da4635d1031d48e2d7",
      "0x05706f775f0101000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000d38a3b583aa1b156d7a3bc40f90358c5",
    ],
  },
};
// What polkadot.js computes for that header: Blake2-256 of its own re-encoding.
const CODEC_HEADER_HASH = "0x9304ed948a0e7fecbe7191864545faa476f5755a5645557c4baf9cec2479aaf8";
const GENESIS_HASH = "0x4901bf5c57fd3f9e726af399c763de6670dbdb115a91c0237e173f16eef65e72";

const registry = new TypeRegistry();
const header = registry.createType("Header", HEADER);

test("polkadot.js header.hash is not the block hash the node reports", () => {
  assert.equal(header.number.toNumber(), BLOCK_NUMBER);
  assert.equal(header.hash.toHex(), CODEC_HEADER_HASH);
  assert.notEqual(header.hash.toHex(), BLOCK_HASH);
});

test("chainContext anchors the mortal era at the node's block hash", async () => {
  const { chainContext } = await import("../examples/chain-context.mjs");
  const api = {
    rpc: {
      chain: {
        getBlockHash: async (at) => {
          assert.equal(at, undefined);
          return registry.createType("Hash", BLOCK_HASH);
        },
        getHeader: async (hash) => {
          assert.equal(hash.toHex(), BLOCK_HASH);
          return header;
        },
      },
    },
    genesisHash: registry.createType("Hash", GENESIS_HASH),
    runtimeVersion: registry.createType("RuntimeVersion", { specVersion: 153, transactionVersion: 1 }),
  };
  const ctx = await chainContext(api);
  assert.deepEqual(ctx, {
    period: 64,
    blockNumber: BLOCK_NUMBER,
    blockHash: BLOCK_HASH,
    genesisHash: GENESIS_HASH,
    specVersion: 153,
    transactionVersion: 1,
  });
  assert.notEqual(ctx.blockHash, header.hash.toHex());
  // The context is accepted as-is by the signer.
  const call = "0x020300" + "02".repeat(32) + "a10f";
  assert.ok(signCall(new Uint8Array(32), call, { nonce: 0, ...ctx }) instanceof Uint8Array);
});
