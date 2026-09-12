//! Proof decoding, parsing and local verification for all three layers, with
//! the verifier artifacts embedded at build time (see `build.rs`).

use qp_plonky2_verifier::util::serialization::DefaultGateSerializer;
use qp_wormhole_verifier::{
    parse_private_batch_public_inputs, parse_public_batch_public_inputs, parse_public_inputs,
    CircuitConfig, CommonCircuitData, PrivateBatchPublicInputs, ProofWithPublicInputs,
    PublicBatchPublicInputs, PublicCircuitInputs, VerifierCircuitData, VerifierOnlyCircuitData,
    WormholeVerifier, C, D, F, MIN_LEAF_SECURITY_BITS, PUBLIC_INPUTS_FELTS_LEN,
};
use qp_zk_circuits_common::circuit::{
    wormhole_private_batch_circuit_config, wormhole_public_batch_circuit_config,
};
use std::sync::OnceLock;

pub use qp_wormhole_verifier::{BytesDigest, PublicInputsByAccount};

pub mod circuit_config {
    include!(concat!(env!("OUT_DIR"), "/circuit_config.rs"));
}
pub use circuit_config::{NUM_LEAF_PROOFS, NUM_PRIVATE_BATCH_PROOFS};

pub const LEAF_COMMON: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/common.bin"));
pub const LEAF_VERIFIER: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/verifier.bin"));
pub const DUMMY_LEAF_PROOF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/dummy_proof.bin"));
pub const PRIVATE_BATCH_COMMON: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/private_batch_common.bin"));
pub const PRIVATE_BATCH_VERIFIER: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/private_batch_verifier.bin"));
#[cfg(feature = "public-batch")]
pub const DUMMY_PRIVATE_BATCH_PROOF: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/dummy_private_batch_proof.bin"));
const PUBLIC_BATCH_COMMON: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/public_batch_common.bin"));
const PUBLIC_BATCH_VERIFIER: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/public_batch_verifier.bin"));

/// Same cap the runtime enforces before touching a settlement proof.
pub const MAX_PROOF_BYTES: usize = 512 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Layer {
    Leaf,
    PrivateBatch,
    PublicBatch,
}

impl Layer {
    fn name(self) -> &'static str {
        match self {
            Layer::Leaf => "leaf",
            Layer::PrivateBatch => "private batch",
            Layer::PublicBatch => "public batch",
        }
    }
}

fn leaf_verifier() -> &'static WormholeVerifier {
    static V: OnceLock<WormholeVerifier> = OnceLock::new();
    V.get_or_init(|| {
        WormholeVerifier::new_from_bytes(LEAF_VERIFIER, LEAF_COMMON)
            .expect("embedded leaf verifier")
    })
}

/// Mirrors the runtime's `load_batch_verifier_from_bytes`: batch artifacts are
/// not the canonical leaf pin, so their profile is checked instead.
fn load_batch_verifier(
    verifier_bytes: &[u8],
    common_bytes: &[u8],
    expected_config: CircuitConfig,
    expected_public_inputs: usize,
) -> WormholeVerifier {
    let verifier_only = VerifierOnlyCircuitData::from_bytes(verifier_bytes.to_vec())
        .expect("embedded verifier data");
    let common = CommonCircuitData::from_bytes(common_bytes.to_vec(), &DefaultGateSerializer)
        .expect("embedded common data");
    assert!(
        common.config == expected_config,
        "batch verifier config is not canonical"
    );
    assert!(
        common.config.security_bits >= MIN_LEAF_SECURITY_BITS,
        "batch verifier below security floor"
    );
    assert!(
        common.num_public_inputs == expected_public_inputs,
        "batch verifier public-input count mismatch"
    );
    WormholeVerifier {
        circuit_data: VerifierCircuitData {
            verifier_only,
            common,
        },
    }
}

fn private_batch_verifier() -> &'static WormholeVerifier {
    static V: OnceLock<WormholeVerifier> = OnceLock::new();
    V.get_or_init(|| {
        load_batch_verifier(
            PRIVATE_BATCH_VERIFIER,
            PRIVATE_BATCH_COMMON,
            wormhole_private_batch_circuit_config(),
            8 + NUM_LEAF_PROOFS * PUBLIC_INPUTS_FELTS_LEN,
        )
    })
}

fn public_batch_verifier() -> &'static WormholeVerifier {
    static V: OnceLock<WormholeVerifier> = OnceLock::new();
    V.get_or_init(|| {
        load_batch_verifier(
            PUBLIC_BATCH_VERIFIER,
            PUBLIC_BATCH_COMMON,
            wormhole_public_batch_circuit_config(),
            qp_wormhole_inputs::public_batch_pi::pi_len(NUM_PRIVATE_BATCH_PROOFS, NUM_LEAF_PROOFS),
        )
    })
}

fn verifier(layer: Layer) -> &'static WormholeVerifier {
    match layer {
        Layer::Leaf => leaf_verifier(),
        Layer::PrivateBatch => private_batch_verifier(),
        Layer::PublicBatch => public_batch_verifier(),
    }
}

/// Decode with the layer's circuit data. Rejects oversized blobs and
/// non-canonical encodings exactly like the runtime does.
pub fn decode_proof(bytes: &[u8], layer: Layer) -> Result<ProofWithPublicInputs<F, C, D>, String> {
    if bytes.len() > MAX_PROOF_BYTES {
        return Err(format!(
            "{} proof is {} bytes, above the {MAX_PROOF_BYTES}-byte cap",
            layer.name(),
            bytes.len()
        ));
    }
    let proof =
        ProofWithPublicInputs::from_bytes(bytes.to_vec(), &verifier(layer).circuit_data.common)
            .map_err(|e| format!("{} proof does not decode: {e}", layer.name()))?;
    if proof.to_bytes() != bytes {
        return Err(format!("{} proof is not canonically encoded", layer.name()));
    }
    Ok(proof)
}

pub fn verify(proof: &ProofWithPublicInputs<F, C, D>, layer: Layer) -> Result<(), String> {
    verifier(layer)
        .verify_ref(proof)
        .map_err(|e| format!("{} proof failed verification: {e}", layer.name()))
}

pub fn parse_leaf(proof: &ProofWithPublicInputs<F, C, D>) -> Result<PublicCircuitInputs, String> {
    parse_public_inputs(proof).map_err(|e| e.to_string())
}

pub fn parse_private_batch(
    proof: &ProofWithPublicInputs<F, C, D>,
) -> Result<PrivateBatchPublicInputs, String> {
    parse_private_batch_public_inputs(proof).map_err(|e| e.to_string())
}

pub fn parse_public_batch(
    proof: &ProofWithPublicInputs<F, C, D>,
) -> Result<PublicBatchPublicInputs, String> {
    parse_public_batch_public_inputs(proof, NUM_PRIVATE_BATCH_PROOFS, NUM_LEAF_PROOFS)
        .map_err(|e| e.to_string())
}
