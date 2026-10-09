// Chain context for signing with @quantus-network/wasm, read from a polkadot.js api.
//
// Quantus hashes block headers with Poseidon. polkadot.js computes `header.hash`
// locally with Blake2, so it is not the hash CheckMortality signs over and an
// extrinsic anchored to it is rejected (BadProof). Take the hash from the node
// (chain_getBlockHash), then fetch that block's header for its number.
export async function chainContext(api, period = 64) {
  const blockHash = await api.rpc.chain.getBlockHash();
  const header = await api.rpc.chain.getHeader(blockHash);
  return {
    period,
    blockNumber: header.number.toNumber(),
    blockHash: blockHash.toHex(),
    genesisHash: api.genesisHash.toHex(),
    specVersion: api.runtimeVersion.specVersion.toNumber(),
    transactionVersion: api.runtimeVersion.transactionVersion.toNumber(),
  };
}
