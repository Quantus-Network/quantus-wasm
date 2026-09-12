//! Node.js bindings (napi-rs) over `quantus-wormhole-core`. Byte inputs are
//! `Uint8Array`; digests inside objects are `0x` hex; proving runs off the
//! event loop on the libuv pool and fans out over the rayon pool.

use napi::bindgen_prelude::*;
use napi_derive::napi;
use quantus_wormhole_core::encoding::{
    account_id, bytes32, from_hex, hex32, siblings, ss58, to_hex,
};
use quantus_wormhole_core::{extrinsic, keys, leaf, prove, verify};

fn err(e: String) -> Error {
    Error::from_reason(e)
}

fn count(value: i64, field: &str) -> Result<u64> {
    u64::try_from(value).map_err(|_| err(format!("{field} must be non-negative")))
}

/// Size the rayon pool used for proving. Call once before proving.
#[napi(js_name = "initThreadPool")]
pub fn init_thread_pool(threads: u32) -> Result<()> {
    quantus_wormhole_core::init_thread_pool(threads as usize).map_err(err)
}

#[napi(js_name = "threadCount")]
pub fn thread_count() -> u32 {
    quantus_wormhole_core::thread_count() as u32
}

#[napi(js_name = "numLeafProofs")]
pub fn num_leaf_proofs() -> u32 {
    verify::NUM_LEAF_PROOFS as u32
}

#[napi(js_name = "numPrivateBatchProofs")]
pub fn num_private_batch_proofs() -> u32 {
    verify::NUM_PRIVATE_BATCH_PROOFS as u32
}

#[napi(object)]
pub struct WormholeAccount {
    pub account_id: String,
    pub address: String,
    pub secret: Option<String>,
}

#[napi(js_name = "wormholeAddress")]
pub fn wormhole_address(secret: Uint8Array) -> Result<WormholeAccount> {
    let account = keys::wormhole_address(&secret).map_err(err)?;
    Ok(WormholeAccount {
        account_id: to_hex(&account),
        address: ss58(account),
        secret: None,
    })
}

#[napi(js_name = "wormholeFromMnemonic")]
pub fn wormhole_from_mnemonic(
    mnemonic: String,
    index: u32,
    passphrase: Option<String>,
) -> Result<WormholeAccount> {
    let (secret, account) =
        keys::from_mnemonic(&mnemonic, passphrase.as_deref(), index).map_err(err)?;
    Ok(WormholeAccount {
        account_id: to_hex(&account),
        address: ss58(account),
        secret: Some(to_hex(&secret)),
    })
}

#[napi]
pub fn nullifier(secret: Uint8Array, transfer_count: i64) -> Result<Uint8Array> {
    let n = keys::nullifier(&secret, count(transfer_count, "transferCount")?).map_err(err)?;
    Ok(n.to_vec().into())
}

#[napi(object)]
pub struct ZkLeaf {
    pub to: String,
    pub transfer_count: String,
    pub asset_id: u32,
    pub amount: String,
}

#[napi(js_name = "decodeZkLeaf")]
pub fn decode_zk_leaf(bytes: Uint8Array) -> Result<ZkLeaf> {
    let l = leaf::decode_zk_leaf(&bytes).map_err(err)?;
    Ok(ZkLeaf {
        to: to_hex(&l.to),
        transfer_count: l.transfer_count.to_string(),
        asset_id: l.asset_id,
        amount: l.amount.to_string(),
    })
}

#[napi]
pub fn quantize(plancks: String) -> Result<u32> {
    let v: u128 = plancks
        .trim()
        .parse()
        .map_err(|_| err("amount: invalid u128 decimal string".into()))?;
    leaf::quantize(v).map_err(err)
}

#[napi]
pub fn dequantize(quantized: u32) -> String {
    leaf::dequantize(quantized).to_string()
}

#[napi(js_name = "outputAfterFee")]
pub fn output_after_fee(input: u32, fee_bps: u32) -> Result<u32> {
    leaf::output_after_fee(input, fee_bps).map_err(err)
}

#[napi(object)]
pub struct MerklePath {
    pub sorted_siblings: Vec<Vec<String>>,
    pub positions: Vec<u32>,
    pub root: String,
}

#[napi(js_name = "merklePositions")]
pub fn merkle_positions(unsorted: Vec<Vec<String>>, leaf_hash: Uint8Array) -> Result<MerklePath> {
    let path = leaf::merkle_positions(
        &siblings(&unsorted).map_err(err)?,
        bytes32(&leaf_hash, "leafHash").map_err(err)?,
    )
    .map_err(err)?;
    Ok(MerklePath {
        sorted_siblings: path
            .sorted_siblings
            .iter()
            .map(|l| l.iter().map(|h| to_hex(h)).collect())
            .collect(),
        positions: path.positions.iter().map(|p| *p as u32).collect(),
        root: to_hex(&path.root),
    })
}

#[napi(object)]
pub struct LeafInput {
    pub secret: String,
    pub transfer_count: i64,
    pub wormhole_address: String,
    pub input_amount: u32,
    pub block_hash: String,
    pub block_number: u32,
    pub parent_hash: String,
    pub state_root: String,
    pub extrinsics_root: String,
    pub digest: String,
    pub zk_tree_root: String,
    pub sorted_siblings: Vec<Vec<String>>,
    pub positions: Vec<u32>,
    pub exit_account_1: String,
    pub output_amount_1: u32,
    pub exit_account_2: String,
    pub output_amount_2: u32,
    pub volume_fee_bps: u32,
    pub asset_id: u32,
}

#[napi(object)]
pub struct LeafProof {
    pub proof: Uint8Array,
    pub nullifier: Uint8Array,
}

pub struct ProveLeaf(prove::LeafInput);

impl Task for ProveLeaf {
    type Output = (Vec<u8>, [u8; 32]);
    type JsValue = LeafProof;

    fn compute(&mut self) -> Result<Self::Output> {
        prove::prove_leaf(&self.0).map_err(err)
    }

    fn resolve(&mut self, _: Env, (proof, nullifier): Self::Output) -> Result<Self::JsValue> {
        Ok(LeafProof {
            proof: proof.into(),
            nullifier: nullifier.to_vec().into(),
        })
    }
}

/// Prove one deposit (layer 0).
#[napi(js_name = "proveLeaf", ts_return_type = "Promise<LeafProof>")]
pub fn prove_leaf(i: LeafInput) -> Result<AsyncTask<ProveLeaf>> {
    let e = |m: String| err(m);
    let input = prove::LeafInput {
        secret: hex32(&i.secret, "secret").map_err(e)?,
        transfer_count: count(i.transfer_count, "transferCount")?,
        wormhole_address: account_id(&i.wormhole_address, "wormholeAddress").map_err(e)?,
        input_amount: i.input_amount,
        block_hash: hex32(&i.block_hash, "blockHash").map_err(e)?,
        block_number: i.block_number,
        parent_hash: hex32(&i.parent_hash, "parentHash").map_err(e)?,
        state_root: hex32(&i.state_root, "stateRoot").map_err(e)?,
        extrinsics_root: hex32(&i.extrinsics_root, "extrinsicsRoot").map_err(e)?,
        digest: from_hex(&i.digest, "digest").map_err(e)?,
        zk_tree_root: hex32(&i.zk_tree_root, "zkTreeRoot").map_err(e)?,
        sorted_siblings: siblings(&i.sorted_siblings).map_err(e)?,
        positions: i
            .positions
            .iter()
            .map(|p| (*p <= 3).then_some(*p as u8).ok_or_else(|| err("positions: each entry must be 0-3".into())))
            .collect::<Result<Vec<_>>>()?,
        exit_account_1: account_id(&i.exit_account_1, "exitAccount1").map_err(e)?,
        output_amount_1: i.output_amount_1,
        exit_account_2: account_id(&i.exit_account_2, "exitAccount2").map_err(e)?,
        output_amount_2: i.output_amount_2,
        volume_fee_bps: i.volume_fee_bps,
        asset_id: i.asset_id,
    };
    Ok(AsyncTask::new(ProveLeaf(input)))
}

pub struct Aggregate {
    proofs: Vec<Vec<u8>>,
    aggregator_address: Option<[u8; 32]>,
}

impl Task for Aggregate {
    type Output = Vec<u8>;
    type JsValue = Uint8Array;

    fn compute(&mut self) -> Result<Self::Output> {
        match self.aggregator_address {
            None => prove::aggregate_private_batch(&self.proofs),
            Some(address) => prove::aggregate_public_batch(&self.proofs, address),
        }
        .map_err(err)
    }

    fn resolve(&mut self, _: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output.into())
    }
}

/// Aggregate leaf proofs into a private-batch proof (layer 1).
#[napi(
    js_name = "aggregatePrivateBatch",
    ts_return_type = "Promise<Uint8Array>"
)]
pub fn aggregate_private_batch(leaf_proofs: Vec<Uint8Array>) -> AsyncTask<Aggregate> {
    AsyncTask::new(Aggregate {
        proofs: leaf_proofs.iter().map(|p| p.to_vec()).collect(),
        aggregator_address: None,
    })
}

/// Aggregate private-batch proofs into a public-batch proof (layer 2).
#[napi(
    js_name = "aggregatePublicBatch",
    ts_return_type = "Promise<Uint8Array>"
)]
pub fn aggregate_public_batch(
    private_batch_proofs: Vec<Uint8Array>,
    aggregator_address: String,
) -> Result<AsyncTask<Aggregate>> {
    Ok(AsyncTask::new(Aggregate {
        proofs: private_batch_proofs.iter().map(|p| p.to_vec()).collect(),
        aggregator_address: Some(
            account_id(&aggregator_address, "aggregatorAddress").map_err(err)?,
        ),
    }))
}

#[napi(object)]
pub struct LeafPublicInputs {
    pub asset_id: u32,
    pub output_amount_1: u32,
    pub output_amount_2: u32,
    pub volume_fee_bps: u32,
    pub nullifier: String,
    pub exit_account_1: String,
    pub exit_account_2: String,
    pub block_hash: String,
    pub block_number: u32,
    pub input_amount: u32,
}

#[napi(object)]
pub struct Exit {
    pub account: String,
    pub amount: u32,
}

#[napi(object)]
pub struct PrivateBatchPublicInputs {
    pub num_exit_slots: u32,
    pub asset_id: u32,
    pub volume_fee_bps: u32,
    pub block_hash: String,
    pub block_number: u32,
    pub exits: Vec<Exit>,
    pub nullifiers: Vec<String>,
}

#[napi(object)]
pub struct Segment {
    pub exits: Vec<Exit>,
    pub nullifiers: Vec<String>,
}

#[napi(object)]
pub struct PublicBatchPublicInputs {
    pub aggregator_address: String,
    pub asset_id: u32,
    pub volume_fee_bps: u32,
    pub block_hash: String,
    pub block_number: u32,
    pub total_exit_slots: u32,
    pub segments: Vec<Segment>,
}

fn exits(slots: &[verify::PublicInputsByAccount]) -> Vec<Exit> {
    slots
        .iter()
        .map(|s| Exit {
            account: to_hex(&*s.exit_account),
            amount: s.summed_output_amount,
        })
        .collect()
}

fn digests(items: &[verify::BytesDigest]) -> Vec<String> {
    items.iter().map(|d| to_hex(&**d)).collect()
}

fn leaf_public_inputs(proof: &[u8], check: bool) -> Result<LeafPublicInputs> {
    let p = verify::decode_proof(proof, verify::Layer::Leaf).map_err(err)?;
    if check {
        verify::verify(&p, verify::Layer::Leaf).map_err(err)?;
    }
    let i = verify::parse_leaf(&p).map_err(err)?;
    Ok(LeafPublicInputs {
        asset_id: i.asset_id,
        output_amount_1: i.output_amount_1,
        output_amount_2: i.output_amount_2,
        volume_fee_bps: i.volume_fee_bps,
        nullifier: to_hex(&*i.nullifier),
        exit_account_1: to_hex(&*i.exit_account_1),
        exit_account_2: to_hex(&*i.exit_account_2),
        block_hash: to_hex(&*i.block_hash),
        block_number: i.block_number,
        input_amount: i.input_amount,
    })
}

fn private_batch_public_inputs(proof: &[u8], check: bool) -> Result<PrivateBatchPublicInputs> {
    let p = verify::decode_proof(proof, verify::Layer::PrivateBatch).map_err(err)?;
    if check {
        verify::verify(&p, verify::Layer::PrivateBatch).map_err(err)?;
    }
    let i = verify::parse_private_batch(&p).map_err(err)?;
    Ok(PrivateBatchPublicInputs {
        num_exit_slots: i.num_exit_slots,
        asset_id: i.asset_id,
        volume_fee_bps: i.volume_fee_bps,
        block_hash: to_hex(&*i.block_data.block_hash),
        block_number: i.block_data.block_number,
        exits: exits(&i.account_data),
        nullifiers: digests(&i.nullifiers),
    })
}

fn public_batch_public_inputs(proof: &[u8], check: bool) -> Result<PublicBatchPublicInputs> {
    let p = verify::decode_proof(proof, verify::Layer::PublicBatch).map_err(err)?;
    if check {
        verify::verify(&p, verify::Layer::PublicBatch).map_err(err)?;
    }
    let i = verify::parse_public_batch(&p).map_err(err)?;
    let slots = verify::NUM_LEAF_PROOFS * 2;
    let segments = i
        .account_data
        .chunks(slots)
        .zip(i.nullifiers.chunks(verify::NUM_LEAF_PROOFS))
        .map(|(e, n)| Segment {
            exits: exits(e),
            nullifiers: digests(n),
        })
        .collect();
    Ok(PublicBatchPublicInputs {
        aggregator_address: to_hex(&*i.aggregator_address),
        asset_id: i.asset_id,
        volume_fee_bps: i.volume_fee_bps,
        block_hash: to_hex(&*i.block_data.block_hash),
        block_number: i.block_data.block_number,
        total_exit_slots: i.total_exit_slots,
        segments,
    })
}

#[napi(js_name = "parseLeafProof")]
pub fn parse_leaf_proof(proof: Uint8Array) -> Result<LeafPublicInputs> {
    leaf_public_inputs(&proof, false)
}

#[napi(js_name = "verifyLeafProof")]
pub fn verify_leaf_proof(proof: Uint8Array) -> Result<LeafPublicInputs> {
    leaf_public_inputs(&proof, true)
}

#[napi(js_name = "parsePrivateBatchProof")]
pub fn parse_private_batch_proof(proof: Uint8Array) -> Result<PrivateBatchPublicInputs> {
    private_batch_public_inputs(&proof, false)
}

#[napi(js_name = "verifyPrivateBatchProof")]
pub fn verify_private_batch_proof(proof: Uint8Array) -> Result<PrivateBatchPublicInputs> {
    private_batch_public_inputs(&proof, true)
}

#[napi(js_name = "parsePublicBatchProof")]
pub fn parse_public_batch_proof(proof: Uint8Array) -> Result<PublicBatchPublicInputs> {
    public_batch_public_inputs(&proof, false)
}

#[napi(js_name = "verifyPublicBatchProof")]
pub fn verify_public_batch_proof(proof: Uint8Array) -> Result<PublicBatchPublicInputs> {
    public_batch_public_inputs(&proof, true)
}

#[napi(js_name = "encodeVerifyPrivateBatch")]
pub fn encode_verify_private_batch(proof: Uint8Array) -> Uint8Array {
    extrinsic::encode_settlement(extrinsic::VERIFY_PRIVATE_BATCH, &proof).into()
}

#[napi(js_name = "encodeVerifyPublicBatch")]
pub fn encode_verify_public_batch(proof: Uint8Array) -> Uint8Array {
    extrinsic::encode_settlement(extrinsic::VERIFY_PUBLIC_BATCH, &proof).into()
}

#[napi(js_name = "usedNullifierStorageKey")]
pub fn used_nullifier_storage_key(nullifier: Uint8Array) -> Result<String> {
    Ok(to_hex(&extrinsic::used_nullifier_storage_key(
        &bytes32(&nullifier, "nullifier").map_err(err)?,
    )))
}

#[napi(js_name = "extrinsicHash")]
pub fn extrinsic_hash(xt: Uint8Array) -> String {
    to_hex(&extrinsic::extrinsic_hash(&xt))
}
