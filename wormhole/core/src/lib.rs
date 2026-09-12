//! Quantus wormhole core: deposit keys, leaf and batch proving, local
//! verification of every proof layer, and the unsigned settlement extrinsics.
//! Pure Rust; the Node.js addon in `../native` is a thin layer over it.

pub mod encoding;
pub mod extrinsic;
pub mod keys;
pub mod leaf;
pub mod prove;
pub mod verify;

pub use verify::{NUM_LEAF_PROOFS, NUM_PRIVATE_BATCH_PROOFS};

/// Size the global rayon pool used by every prover. Call once, before proving;
/// later calls fail because the pool is already built.
pub fn init_thread_pool(threads: usize) -> Result<(), String> {
    rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build_global()
        .map_err(|e| format!("thread pool: {e}"))
}

pub fn thread_count() -> usize {
    rayon::current_num_threads()
}
