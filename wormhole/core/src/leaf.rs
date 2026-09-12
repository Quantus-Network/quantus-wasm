//! ZK-tree leaves: decoding, amount quantisation and Merkle path preparation.

use parity_scale_codec::{Decode, DecodeAll};
use qp_zk_circuits_common::zk_merkle::{hash_node_presorted, MAX_DEPTH, SIBLINGS_PER_LEVEL};

/// Circuit amounts are u32 with 2 decimals; chain amounts have 12.
pub const SCALE_DOWN_FACTOR: u128 = 10_000_000_000;

/// SCALE layout of `pallet_zk_tree::ZkLeaf<AccountId32, u32, u128>` (60 bytes).
#[derive(Decode, Debug, PartialEq, Eq)]
pub struct ZkLeaf {
    pub to: [u8; 32],
    pub transfer_count: u64,
    pub asset_id: u32,
    pub amount: u128,
}

pub fn decode_zk_leaf(bytes: &[u8]) -> Result<ZkLeaf, String> {
    ZkLeaf::decode_all(&mut &bytes[..]).map_err(|e| format!("leaf: {e}"))
}

pub fn quantize(plancks: u128) -> Result<u32, String> {
    u32::try_from(plancks / SCALE_DOWN_FACTOR)
        .map_err(|_| format!("amount {plancks} exceeds the u32 quantized range"))
}

pub fn dequantize(quantized: u32) -> u128 {
    quantized as u128 * SCALE_DOWN_FACTOR
}

/// `input * (10000 - fee_bps) / 10000`, rounded down.
pub fn output_after_fee(input: u32, fee_bps: u32) -> Result<u32, String> {
    if fee_bps > 10_000 {
        return Err(format!("fee_bps {fee_bps} exceeds 10000"));
    }
    Ok((input as u64 * (10_000 - fee_bps as u64) / 10_000) as u32)
}

pub type Siblings = [[u8; 32]; SIBLINGS_PER_LEVEL];

pub struct MerklePath {
    pub sorted_siblings: Vec<Siblings>,
    pub positions: Vec<u8>,
    pub root: [u8; 32],
}

/// The node RPC returns unsorted siblings per level of the sorted 4-ary tree.
/// Sort each level with the running hash, record the hash's position, and fold
/// up to the root so callers can check it against the tree root they fetched.
pub fn merkle_positions(unsorted: &[Siblings], leaf_hash: [u8; 32]) -> Result<MerklePath, String> {
    if unsorted.len() > MAX_DEPTH {
        return Err(format!(
            "merkle depth {} exceeds {MAX_DEPTH}",
            unsorted.len()
        ));
    }
    let mut current = leaf_hash;
    let mut sorted_siblings = Vec::with_capacity(unsorted.len());
    let mut positions = Vec::with_capacity(unsorted.len());
    for level in unsorted {
        let mut nodes = [current, level[0], level[1], level[2]];
        nodes.sort();
        let position = nodes
            .iter()
            .position(|h| *h == current)
            .expect("current hash is in nodes");
        positions.push(position as u8);
        let mut siblings = [[0u8; 32]; SIBLINGS_PER_LEVEL];
        for (slot, node) in nodes
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != position)
            .map(|(_, n)| n)
            .enumerate()
        {
            siblings[slot] = *node;
        }
        sorted_siblings.push(siblings);
        current = hash_node_presorted(&nodes).map_err(|e| format!("merkle: {e}"))?;
    }
    Ok(MerklePath {
        sorted_siblings,
        positions,
        root: current,
    })
}
