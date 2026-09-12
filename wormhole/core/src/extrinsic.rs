//! Unsigned settlement extrinsics and storage keys for status checks.

use parity_scale_codec::{Compact, Encode};
use sp_core::hashing::{blake2_128, blake2_256, twox_128};

pub const WORMHOLE_PALLET: u8 = 20;
pub const VERIFY_PRIVATE_BATCH: u8 = 2;
pub const VERIFY_PUBLIC_BATCH: u8 = 3;
/// Unsigned v4 extrinsic version byte.
const UNSIGNED_V4: u8 = 4;

/// `wormhole.verify_private_batch(proof)` / `verify_public_batch(proof)` as an
/// unsigned, fee-free extrinsic for `author_submitExtrinsic`.
pub fn encode_settlement(call_index: u8, proof: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(proof.len() + 8);
    body.push(UNSIGNED_V4);
    body.push(WORMHOLE_PALLET);
    body.push(call_index);
    proof.encode_to(&mut body);
    let mut out = Vec::with_capacity(body.len() + 5);
    Compact(body.len() as u32).encode_to(&mut out);
    out.extend_from_slice(&body);
    out
}

/// `Wormhole::UsedNullifiers(nullifier)` storage key (Blake2_128Concat).
pub fn used_nullifier_storage_key(nullifier: &[u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(16 + 16 + 16 + 32);
    key.extend_from_slice(&twox_128(b"Wormhole"));
    key.extend_from_slice(&twox_128(b"UsedNullifiers"));
    key.extend_from_slice(&blake2_128(nullifier));
    key.extend_from_slice(nullifier);
    key
}

/// Hash `author_submitExtrinsic` returns for these bytes.
pub fn extrinsic_hash(extrinsic: &[u8]) -> [u8; 32] {
    blake2_256(extrinsic)
}
