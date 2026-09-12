use parity_scale_codec::{Compact, Decode, Encode};
use quantus_wormhole_core::{extrinsic, keys, leaf, prove, verify};
use serde::Deserialize;
use verify::Layer;

// The circuits repo's reference deposit (`test_inputs_0` at v4.3.0) and the
// leaf proof it produces; both generated once from `qp-zk-circuits`.
const LEAF_INPUT_JSON: &str = include_str!("../test-data/leaf_input.json");
const LEAF_PROOF_HEX: &str = include_str!("../test-data/leaf_proof.hex");
// The runtime's own settlement fixtures (`pallets/wormhole/test-data`).
const PRIVATE_BATCH_HEX: &str = include_str!("../test-data/private_batch.hex");
const PUBLIC_BATCH_HEX: &str = include_str!("../test-data/public_batch.hex");

fn fixture(hex_text: &str) -> Vec<u8> {
    hex::decode(hex_text.trim()).unwrap()
}

fn h32(s: &str) -> [u8; 32] {
    hex::decode(&s[2..]).unwrap().try_into().unwrap()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LeafInputJson {
    secret: String,
    transfer_count: u64,
    wormhole_address: String,
    input_amount: u32,
    block_hash: String,
    block_number: u32,
    parent_hash: String,
    state_root: String,
    extrinsics_root: String,
    digest: String,
    zk_tree_root: String,
    sorted_siblings: Vec<Vec<String>>,
    positions: Vec<u8>,
    exit_account_1: String,
    output_amount_1: u32,
    exit_account_2: String,
    output_amount_2: u32,
    volume_fee_bps: u32,
    asset_id: u32,
}

fn leaf_input() -> prove::LeafInput {
    let j: LeafInputJson = serde_json::from_str(LEAF_INPUT_JSON).unwrap();
    prove::LeafInput {
        secret: h32(&j.secret),
        transfer_count: j.transfer_count,
        wormhole_address: h32(&j.wormhole_address),
        input_amount: j.input_amount,
        block_hash: h32(&j.block_hash),
        block_number: j.block_number,
        parent_hash: h32(&j.parent_hash),
        state_root: h32(&j.state_root),
        extrinsics_root: h32(&j.extrinsics_root),
        digest: hex::decode(&j.digest[2..]).unwrap(),
        zk_tree_root: h32(&j.zk_tree_root),
        sorted_siblings: j
            .sorted_siblings
            .iter()
            .map(|l| [h32(&l[0]), h32(&l[1]), h32(&l[2])])
            .collect(),
        positions: j.positions,
        exit_account_1: h32(&j.exit_account_1),
        output_amount_1: j.output_amount_1,
        exit_account_2: h32(&j.exit_account_2),
        output_amount_2: j.output_amount_2,
        volume_fee_bps: j.volume_fee_bps,
        asset_id: j.asset_id,
    }
}

#[test]
fn keys_match_circuit_derivation() {
    let input = leaf_input();
    assert_eq!(
        keys::wormhole_address(&input.secret).unwrap(),
        input.wormhole_address
    );
    let fixture_inputs =
        verify::parse_leaf(&verify::decode_proof(&fixture(LEAF_PROOF_HEX), Layer::Leaf).unwrap())
            .unwrap();
    assert_eq!(
        keys::nullifier(&input.secret, input.transfer_count).unwrap(),
        *fixture_inputs.nullifier
    );
    assert_ne!(
        keys::nullifier(&input.secret, input.transfer_count + 1).unwrap(),
        *fixture_inputs.nullifier
    );
    assert!(keys::wormhole_address(&[0u8; 31]).is_err());
}

#[test]
fn mnemonic_derivation_matches_hdwallet() {
    let mnemonic = "orchard answer curve patient visual flower maze noise retreat penalty cage small earth domain scan pitch bottom crunch theme club client swap slice raven";
    let (secret, address) = keys::from_mnemonic(mnemonic, None, 0).unwrap();
    assert_eq!(keys::wormhole_address(&secret).unwrap(), address);
    let (secret1, _) = keys::from_mnemonic(mnemonic, None, 1).unwrap();
    assert_ne!(secret, secret1);
    assert_eq!(keys::wormhole_path(3), "m/44'/189189189'/0'/0'/3'");
    assert!(keys::from_mnemonic("not a mnemonic", None, 0).is_err());
}

#[test]
fn leaf_fixture_verifies_and_parses() {
    let bytes = fixture(LEAF_PROOF_HEX);
    let proof = verify::decode_proof(&bytes, Layer::Leaf).unwrap();
    verify::verify(&proof, Layer::Leaf).unwrap();
    let i = verify::parse_leaf(&proof).unwrap();
    assert_eq!(i.block_number, 1);
    assert_eq!(i.volume_fee_bps, 10);
    assert_eq!(*i.exit_account_1, [4u8; 32]);
    assert_eq!(
        hex::encode(*i.nullifier),
        "4e7059e77c7213121dc74a104573270c18f64900abde406794fc93a323f2abe0"
    );

    let mut padded = bytes.clone();
    padded.push(0);
    assert!(verify::decode_proof(&padded, Layer::Leaf)
        .unwrap_err()
        .contains("canonically"));
    assert!(
        verify::decode_proof(&vec![0u8; verify::MAX_PROOF_BYTES + 1], Layer::Leaf)
            .unwrap_err()
            .contains("cap")
    );
    assert!(verify::decode_proof(&bytes, Layer::PrivateBatch).is_err());
}

#[test]
fn prove_leaf_matches_fixture() {
    let input = leaf_input();
    let (proof, nullifier) = prove::prove_leaf(&input).unwrap();
    let decoded = verify::decode_proof(&proof, Layer::Leaf).unwrap();
    verify::verify(&decoded, Layer::Leaf).unwrap();
    let expected =
        verify::parse_leaf(&verify::decode_proof(&fixture(LEAF_PROOF_HEX), Layer::Leaf).unwrap())
            .unwrap();
    assert_eq!(verify::parse_leaf(&decoded).unwrap(), expected);
    assert_eq!(
        nullifier,
        keys::nullifier(&input.secret, input.transfer_count).unwrap()
    );

    let mut wrong = leaf_input();
    wrong.wormhole_address[0] ^= 1;
    assert!(prove::prove_leaf(&wrong)
        .unwrap_err()
        .contains("not derived"));
    let mut wrong = leaf_input();
    wrong.digest = vec![0; 111];
    assert!(prove::prove_leaf(&wrong).unwrap_err().contains("digest"));
}

#[test]
fn aggregate_private_batch_verifies_and_parses() {
    let leaf = fixture(LEAF_PROOF_HEX);
    let batch = prove::aggregate_private_batch(std::slice::from_ref(&leaf)).unwrap();
    let proof = verify::decode_proof(&batch, Layer::PrivateBatch).unwrap();
    verify::verify(&proof, Layer::PrivateBatch).unwrap();
    let i = verify::parse_private_batch(&proof).unwrap();
    assert_eq!(i.num_exit_slots as usize, 2 * verify::NUM_LEAF_PROOFS);
    assert_eq!(i.account_data.len(), 2 * verify::NUM_LEAF_PROOFS);
    assert_eq!(i.nullifiers.len(), verify::NUM_LEAF_PROOFS);
    assert_eq!(i.block_data.block_number, 1);
    let leaf_inputs =
        verify::parse_leaf(&verify::decode_proof(&leaf, Layer::Leaf).unwrap()).unwrap();
    assert!(i.nullifiers.contains(&leaf_inputs.nullifier));

    assert!(prove::aggregate_private_batch(&[]).is_err());
    assert!(
        prove::aggregate_private_batch(&vec![leaf; verify::NUM_LEAF_PROOFS + 1])
            .unwrap_err()
            .contains("too many")
    );
    assert!(prove::aggregate_private_batch(&[batch])
        .unwrap_err()
        .contains("leaf proof 0"));
}

#[test]
fn chain_fixtures_verify_with_embedded_verifiers() {
    let private = verify::decode_proof(&fixture(PRIVATE_BATCH_HEX), Layer::PrivateBatch).unwrap();
    verify::verify(&private, Layer::PrivateBatch).unwrap();
    let i = verify::parse_private_batch(&private).unwrap();
    assert_eq!(i.account_data.len(), 2 * verify::NUM_LEAF_PROOFS);
    assert_eq!(i.volume_fee_bps, 4);

    let public = verify::decode_proof(&fixture(PUBLIC_BATCH_HEX), Layer::PublicBatch).unwrap();
    verify::verify(&public, Layer::PublicBatch).unwrap();
    let i = verify::parse_public_batch(&public).unwrap();
    assert_eq!(
        i.account_data.len(),
        2 * verify::NUM_LEAF_PROOFS * verify::NUM_PRIVATE_BATCH_PROOFS
    );
    assert_eq!(
        i.nullifiers.len(),
        verify::NUM_LEAF_PROOFS * verify::NUM_PRIVATE_BATCH_PROOFS
    );
    assert_eq!(i.volume_fee_bps, 4);

    assert!(verify::verify(&private, Layer::PublicBatch).is_err());
}

#[test]
fn zk_leaf_decodes_scale_layout() {
    let encoded = ([7u8; 32], 9u64, 0u32, 1_230_000_000_000u128).encode();
    assert_eq!(encoded.len(), 60);
    let l = leaf::decode_zk_leaf(&encoded).unwrap();
    assert_eq!(
        (l.to, l.transfer_count, l.asset_id, l.amount),
        ([7u8; 32], 9, 0, 1_230_000_000_000)
    );
    assert!(leaf::decode_zk_leaf(&encoded[..59]).is_err());
    assert!(leaf::decode_zk_leaf(&[encoded.clone(), vec![0]].concat()).is_err());
}

#[test]
fn amounts_quantize_and_fee() {
    assert_eq!(leaf::quantize(1_230_000_000_000).unwrap(), 123);
    assert_eq!(leaf::quantize(9_999_999_999).unwrap(), 0);
    assert!(leaf::quantize(u128::MAX).is_err());
    assert_eq!(leaf::dequantize(123), 1_230_000_000_000);
    assert_eq!(leaf::output_after_fee(10_000, 4).unwrap(), 9_996);
    assert_eq!(leaf::output_after_fee(1, 4).unwrap(), 0);
    assert!(leaf::output_after_fee(1, 10_001).is_err());
}

#[test]
fn merkle_positions_sort_and_fold() {
    use qp_zk_circuits_common::zk_merkle::hash_node_presorted;
    let h = |b: u8| [b; 32];
    let leaf = h(9);
    let level0 = [h(1), h(200), h(50)];
    let level1 = [h(0), h(254), h(7)];
    let path = leaf::merkle_positions(&[level0, level1], leaf).unwrap();

    let mut nodes0 = [leaf, h(1), h(200), h(50)];
    nodes0.sort();
    assert_eq!(path.positions[0], 1);
    assert_eq!(path.sorted_siblings[0], [h(1), h(50), h(200)]);
    let parent = hash_node_presorted(&nodes0).unwrap();
    let mut nodes1 = [parent, h(0), h(254), h(7)];
    nodes1.sort();
    assert_eq!(
        path.positions[1] as usize,
        nodes1.iter().position(|n| *n == parent).unwrap()
    );
    assert_eq!(path.root, hash_node_presorted(&nodes1).unwrap());
    assert!(leaf::merkle_positions(&vec![level0; 17], leaf).is_err());
}

#[derive(Decode, Debug, PartialEq)]
enum WormholeCall {
    #[codec(index = 2)]
    VerifyPrivateBatch { proof_bytes: Vec<u8> },
    #[codec(index = 3)]
    VerifyPublicBatch { proof_bytes: Vec<u8> },
}

#[derive(Decode, Debug, PartialEq)]
enum RuntimeCall {
    #[codec(index = 20)]
    Wormhole(WormholeCall),
}

#[test]
fn settlement_extrinsics_decode_as_unsigned_calls() {
    // `UncheckedExtrinsic` wire format: compact(len) || version (4 = unsigned v4) || call.
    let proof = vec![0xABu8; 300];
    for (index, expected) in [
        (
            extrinsic::VERIFY_PRIVATE_BATCH,
            WormholeCall::VerifyPrivateBatch {
                proof_bytes: proof.clone(),
            },
        ),
        (
            extrinsic::VERIFY_PUBLIC_BATCH,
            WormholeCall::VerifyPublicBatch {
                proof_bytes: proof.clone(),
            },
        ),
    ] {
        let bytes = extrinsic::encode_settlement(index, &proof);
        let mut input = &bytes[..];
        let len = Compact::<u32>::decode(&mut input).unwrap().0 as usize;
        assert_eq!(len, input.len());
        assert_eq!(input[0], 4);
        let mut call = &input[1..];
        assert_eq!(
            RuntimeCall::decode(&mut call).unwrap(),
            RuntimeCall::Wormhole(expected)
        );
        assert!(call.is_empty());
    }
    assert_eq!(
        extrinsic::extrinsic_hash(b"abc"),
        sp_core::hashing::blake2_256(b"abc")
    );
}

#[test]
fn used_nullifier_key_layout() {
    let n = [5u8; 32];
    let key = extrinsic::used_nullifier_storage_key(&n);
    assert_eq!(key.len(), 16 + 16 + 16 + 32);
    assert_eq!(&key[48..], &n);
    assert_eq!(&key[..16], &sp_core::hashing::twox_128(b"Wormhole"));
}

/// Layer 2 needs about 7 GB and a quarter minute; opt in with
/// `WORMHOLE_TEST_PUBLIC_BATCH=1`.
#[cfg(feature = "public-batch")]
#[test]
fn aggregate_public_batch_verifies_and_parses() {
    if std::env::var("WORMHOLE_TEST_PUBLIC_BATCH").is_err() {
        return;
    }
    let private = fixture(PRIVATE_BATCH_HEX);
    let public = prove::aggregate_public_batch(std::slice::from_ref(&private), [9u8; 32]).unwrap();
    let proof = verify::decode_proof(&public, Layer::PublicBatch).unwrap();
    verify::verify(&proof, Layer::PublicBatch).unwrap();
    let i = verify::parse_public_batch(&proof).unwrap();
    assert_eq!(*i.aggregator_address, [9u8; 32]);
    assert_eq!(
        i.nullifiers.len(),
        verify::NUM_LEAF_PROOFS * verify::NUM_PRIVATE_BATCH_PROOFS
    );
    let inner =
        verify::parse_private_batch(&verify::decode_proof(&private, Layer::PrivateBatch).unwrap())
            .unwrap();
    assert!(inner.nullifiers.iter().all(|n| i.nullifiers.contains(n)));
    assert!(
        prove::aggregate_public_batch(&[fixture(LEAF_PROOF_HEX)], [9u8; 32])
            .unwrap_err()
            .contains("proof 0")
    );
}
