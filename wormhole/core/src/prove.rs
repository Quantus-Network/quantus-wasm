//! Layer 0 (leaf), layer 1 (private batch) and, with the `public-batch`
//! feature, layer 2 (public batch) proving.

use plonky2::{
    plonk::{circuit_data::CommonCircuitData, proof::ProofWithPublicInputs},
    util::serialization::DefaultGateSerializer,
};
use qp_wormhole_aggregator::private_batch::prover::PrivateBatchProver;
use qp_wormhole_circuit::{
    block_header::header::DIGEST_LOGS_SIZE,
    inputs::{CircuitInputs, PrivateCircuitInputs},
    nullifier::Nullifier,
    sensitive::Secret,
    unspendable_account::UnspendableAccount,
};
use qp_wormhole_inputs::{BytesDigest, PublicCircuitInputs};
use qp_zk_circuits_common::{
    circuit::{C, D, F},
    utils::digest_to_bytes,
    zk_merkle::MAX_DEPTH,
};

use crate::keys::secret_digest;
use crate::leaf::Siblings;
use crate::verify::{
    decode_proof, Layer, DUMMY_LEAF_PROOF, LEAF_COMMON, LEAF_VERIFIER, NUM_LEAF_PROOFS,
};

pub struct LeafInput {
    pub secret: [u8; 32],
    pub transfer_count: u64,
    pub wormhole_address: [u8; 32],
    pub input_amount: u32,
    pub block_hash: [u8; 32],
    pub block_number: u32,
    pub parent_hash: [u8; 32],
    pub state_root: [u8; 32],
    pub extrinsics_root: [u8; 32],
    pub digest: Vec<u8>,
    pub zk_tree_root: [u8; 32],
    pub sorted_siblings: Vec<Siblings>,
    pub positions: Vec<u8>,
    pub exit_account_1: [u8; 32],
    pub output_amount_1: u32,
    pub exit_account_2: [u8; 32],
    pub output_amount_2: u32,
    pub volume_fee_bps: u32,
    pub asset_id: u32,
}

fn digest(bytes: [u8; 32], field: &str) -> Result<BytesDigest, String> {
    BytesDigest::try_from(bytes).map_err(|e| format!("{field}: {e}"))
}

/// Proves one deposit. Returns the proof bytes and the nullifier it commits to.
pub fn prove_leaf(input: &LeafInput) -> Result<(Vec<u8>, [u8; 32]), String> {
    if input.digest.len() > DIGEST_LOGS_SIZE {
        return Err(format!(
            "digest is {} bytes, max {DIGEST_LOGS_SIZE}",
            input.digest.len()
        ));
    }
    if input.sorted_siblings.len() != input.positions.len() || input.positions.len() > MAX_DEPTH {
        return Err(
            "sortedSiblings and positions must have the same length (at most 16 levels)".into(),
        );
    }
    let secret = secret_digest(&input.secret)?;
    let unspendable = UnspendableAccount::from_secret(secret);
    if *digest_to_bytes(unspendable.account_id) != input.wormhole_address {
        return Err("wormholeAddress is not derived from this secret".into());
    }
    let nullifier = Nullifier::from_preimage(secret, input.transfer_count);
    let mut padded_digest = [0u8; DIGEST_LOGS_SIZE];
    padded_digest[..input.digest.len()].copy_from_slice(&input.digest);

    let inputs = CircuitInputs {
        public: PublicCircuitInputs {
            asset_id: input.asset_id,
            output_amount_1: input.output_amount_1,
            output_amount_2: input.output_amount_2,
            volume_fee_bps: input.volume_fee_bps,
            nullifier: digest_to_bytes(nullifier.hash),
            exit_account_1: digest(input.exit_account_1, "exitAccount1")?,
            exit_account_2: digest(input.exit_account_2, "exitAccount2")?,
            block_hash: digest(input.block_hash, "blockHash")?,
            block_number: input.block_number,
            input_amount: input.input_amount,
        },
        private: PrivateCircuitInputs {
            secret: Secret::from(secret),
            transfer_count: input.transfer_count,
            unspendable_account: digest_to_bytes(unspendable.account_id),
            parent_hash: digest(input.parent_hash, "parentHash")?,
            state_root: digest(input.state_root, "stateRoot")?,
            extrinsics_root: digest(input.extrinsics_root, "extrinsicsRoot")?,
            digest: padded_digest,
            zk_tree_root: input.zk_tree_root,
            zk_merkle_siblings: input.sorted_siblings.clone(),
            zk_merkle_positions: input.positions.clone(),
        },
    };
    let proof = qp_wormhole_prover::build_fresh()
        .commit(&inputs)
        .map_err(|e| format!("leaf prover rejected the inputs: {e}"))?
        .prove()
        .map_err(|e| format!("leaf proving failed: {e}"))?;
    Ok((proof.to_bytes(), *digest_to_bytes(nullifier.hash)))
}

/// Aggregates up to `NUM_LEAF_PROOFS` leaf proofs (padded with dummies) into
/// one private-batch proof ready for `verify_private_batch`.
pub fn aggregate_private_batch(leaf_proofs: &[Vec<u8>]) -> Result<Vec<u8>, String> {
    let proofs = decode_for_prover(leaf_proofs, Layer::Leaf, LEAF_COMMON)
        .map_err(|e| format!("leaf {e}"))?;
    let prover = PrivateBatchProver::new_from_bytes(
        LEAF_COMMON,
        LEAF_VERIFIER,
        DUMMY_LEAF_PROOF,
        NUM_LEAF_PROOFS,
    )
    .map_err(|e| format!("private-batch prover build failed: {e}"))?;
    let proof = prover
        .commit(proofs)
        .map_err(|e| format!("private-batch prover rejected the leaf proofs: {e}"))?
        .prove()
        .map_err(|e| format!("private-batch proving failed: {e}"))?;
    Ok(proof.to_bytes())
}

/// Validate proofs with the shared decoder, then decode them again into the
/// prover's plonky2 types (the verifier crate has its own).
fn decode_for_prover(
    proofs: &[Vec<u8>],
    layer: Layer,
    common_bytes: &[u8],
) -> Result<Vec<ProofWithPublicInputs<F, C, D>>, String> {
    let common =
        CommonCircuitData::<F, D>::from_bytes(common_bytes.to_vec(), &DefaultGateSerializer)
            .map_err(|e| format!("embedded common data: {e}"))?;
    proofs
        .iter()
        .enumerate()
        .map(|(i, bytes)| {
            decode_proof(bytes, layer).map_err(|e| format!("proof {i}: {e}"))?;
            ProofWithPublicInputs::<F, C, D>::from_bytes(bytes.clone(), &common)
                .map_err(|e| format!("proof {i}: {e}"))
        })
        .collect()
}

/// Aggregates up to `NUM_PRIVATE_BATCH_PROOFS` private-batch proofs (padded
/// with dummies) into one public-batch proof ready for `verify_public_batch`.
/// `aggregator_address` receives the rebate from the burn share of the fee.
#[cfg(feature = "public-batch")]
pub fn aggregate_public_batch(
    private_batch_proofs: &[Vec<u8>],
    aggregator_address: [u8; 32],
) -> Result<Vec<u8>, String> {
    use crate::verify::{
        DUMMY_PRIVATE_BATCH_PROOF, NUM_PRIVATE_BATCH_PROOFS, PRIVATE_BATCH_COMMON,
        PRIVATE_BATCH_VERIFIER,
    };
    use qp_wormhole_aggregator::public_batch::prover::{PublicBatchInputs, PublicBatchProver};

    let proofs = decode_for_prover(
        private_batch_proofs,
        Layer::PrivateBatch,
        PRIVATE_BATCH_COMMON,
    )
    .map_err(|e| format!("private-batch {e}"))?;
    let aggregator_address = digest(aggregator_address, "aggregatorAddress")?;
    let prover = PublicBatchProver::new_from_bytes(
        PRIVATE_BATCH_COMMON,
        PRIVATE_BATCH_VERIFIER,
        DUMMY_PRIVATE_BATCH_PROOF,
        (NUM_LEAF_PROOFS, NUM_PRIVATE_BATCH_PROOFS),
    )
    .map_err(|e| format!("public-batch prover build failed: {e}"))?;
    let proof = prover
        .commit(PublicBatchInputs {
            proofs,
            aggregator_address,
        })
        .map_err(|e| format!("public-batch prover rejected the private-batch proofs: {e}"))?
        .prove()
        .map_err(|e| format!("public-batch proving failed: {e}"))?;
    Ok(proof.to_bytes())
}
