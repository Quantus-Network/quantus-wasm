//! Wormhole secrets: unspendable deposit address, nullifier and HD derivation.

use qp_rusty_crystals_hdwallet::{derive_wormhole_from_mnemonic, QUANTUS_WORMHOLE_CHAIN_ID};
use qp_wormhole_circuit::{nullifier::Nullifier, unspendable_account::UnspendableAccount};
use qp_wormhole_inputs::BytesDigest;
use qp_zk_circuits_common::utils::digest_to_bytes;

pub fn secret_digest(secret: &[u8]) -> Result<BytesDigest, String> {
    let bytes: [u8; 32] = secret
        .try_into()
        .map_err(|_| "secret: expected 32 bytes".to_string())?;
    BytesDigest::try_from(bytes).map_err(|e| format!("secret: {e}"))
}

/// `H(H("wormhole" || secret))`: the deposit address for `secret`.
pub fn wormhole_address(secret: &[u8]) -> Result<[u8; 32], String> {
    Ok(*digest_to_bytes(
        UnspendableAccount::from_secret(secret_digest(secret)?).account_id,
    ))
}

/// `H(H(salt || secret || transfer_count))`: marks one deposit as spent.
pub fn nullifier(secret: &[u8], transfer_count: u64) -> Result<[u8; 32], String> {
    Ok(*digest_to_bytes(
        Nullifier::from_preimage(secret_digest(secret)?, transfer_count).hash,
    ))
}

/// Quantus wormhole HD path `m/44'/189189189'/0'/0'/<index>'`.
pub fn wormhole_path(index: u32) -> String {
    format!("m/44'/{QUANTUS_WORMHOLE_CHAIN_ID}/0'/0'/{index}'")
}

/// (secret, address) at the wormhole HD path, as the Quantus wallets derive it.
pub fn from_mnemonic(
    mnemonic: &str,
    passphrase: Option<&str>,
    index: u32,
) -> Result<([u8; 32], [u8; 32]), String> {
    let pair = derive_wormhole_from_mnemonic(mnemonic, passphrase, &wormhole_path(index))
        .map_err(|e| format!("mnemonic derivation failed: {e}"))?;
    Ok((*pair.secret().as_bytes(), *pair.address()))
}
