//! Generates the circuit verifier artifacts embedded at compile time, with the
//! same generator and sizing as the runtime's `pallet-wormhole` build script.
//! With the `public-batch` feature it also proves the dummy private batch the
//! layer-2 prover pads with.

use std::{env, fs, path::Path};

fn knob(name: &str, default: usize) -> usize {
    println!("cargo:rerun-if-env-changed={name}");
    env::var(name).map_or(default, |v| {
        v.parse()
            .unwrap_or_else(|_| panic!("{name} must be a usize"))
    })
}

fn main() {
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR");
    let num_leaf_proofs = knob("QP_NUM_LEAF_PROOFS", 7);
    let num_private_batch_proofs = knob("QP_NUM_PRIVATE_BATCH_PROOFS", 53);
    let include_prover = env::var("CARGO_FEATURE_PUBLIC_BATCH").is_ok();
    qp_wormhole_circuit_builder::generate_all_circuit_binaries(
        Path::new(&out_dir),
        include_prover,
        num_leaf_proofs,
        Some(num_private_batch_proofs),
    )
    .expect("circuit binaries");
    fs::write(
        Path::new(&out_dir).join("circuit_config.rs"),
        format!(
            "pub const NUM_LEAF_PROOFS: usize = {num_leaf_proofs};\n\
             pub const NUM_PRIVATE_BATCH_PROOFS: usize = {num_private_batch_proofs};\n"
        ),
    )
    .expect("circuit_config.rs");
}
