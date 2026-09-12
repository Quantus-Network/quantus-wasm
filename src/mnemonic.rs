//! BIP39 mnemonic -> Quantus HD account/signing, via `qp-rusty-crystals-hdwallet`.
//!
//! Uses the canonical Quantus derivation path `m/44'/189189'/<account>'/<change>'/<addressIndex>'`
//! so accounts match the wallets. All account/signing logic delegates to the
//! seed-path core in [`crate::ext`]; only the keypair source differs.

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

use qp_rusty_crystals_hdwallet::{ml_dsa_65, ml_dsa_87, mnemonic_to_seed, SensitiveBytes64};
use wasm_bindgen::prelude::*;

use crate::{ext, parse_scheme, Account, Scheme};

fn quantus_path(account: u32, change: u32, address_index: u32) -> String {
    alloc::format!("m/44'/189189'/{account}'/{change}'/{address_index}'")
}

fn keypair_from_mnemonic(
    mnemonic: &str,
    passphrase: Option<String>,
    account: u32,
    change: u32,
    address_index: u32,
    scheme: Scheme,
) -> Result<ext::Keypair, JsError> {
    let path = quantus_path(account, change, address_index);
    let passphrase = passphrase.as_deref();
    let keypair = match scheme {
        Scheme::MlDsa87 => ml_dsa_87::derive_key_from_mnemonic(mnemonic, passphrase, &path)
            .map(ext::Keypair::from),
        Scheme::MlDsa65 => ml_dsa_65::derive_key_from_mnemonic(mnemonic, passphrase, &path)
            .map(ext::Keypair::from),
    };
    keypair.map_err(|e| JsError::new(&alloc::format!("mnemonic derivation failed: {e}")))
}

/// Derive a Quantus account from a mnemonic at the given HD indices.
#[wasm_bindgen(js_name = accountFromMnemonic)]
pub fn account_from_mnemonic(
    mnemonic: &str,
    account: u32,
    change: u32,
    address_index: u32,
    passphrase: Option<String>,
    scheme: Option<String>,
) -> Result<Account, JsError> {
    let scheme = parse_scheme(scheme.as_deref())?;
    let keypair =
        keypair_from_mnemonic(mnemonic, passphrase, account, change, address_index, scheme)?;
    Ok(crate::account_from_keys(ext::derive_account_from_keypair(&keypair)))
}

/// Sign a transfer from a mnemonic at the given HD indices.
#[wasm_bindgen(js_name = signTransferFromMnemonic)]
pub fn sign_transfer_from_mnemonic(
    mnemonic: &str,
    params: JsValue,
    account: u32,
    change: u32,
    address_index: u32,
    passphrase: Option<String>,
) -> Result<Vec<u8>, JsError> {
    let (params, scheme) = crate::build_transfer_params(params)?;
    let keypair =
        keypair_from_mnemonic(mnemonic, passphrase, account, change, address_index, scheme)?;
    ext::sign_transfer_with_keypair(&keypair, &params).map_err(crate::to_js_error)
}

/// Sign an already-encoded `RuntimeCall` from a mnemonic at the given HD indices.
#[wasm_bindgen(js_name = signCallFromMnemonic)]
pub fn sign_call_from_mnemonic(
    mnemonic: &str,
    call: &[u8],
    context: JsValue,
    account: u32,
    change: u32,
    address_index: u32,
    passphrase: Option<String>,
) -> Result<Vec<u8>, JsError> {
    let (ctx, scheme) = crate::build_sign_context_from_value(context)?;
    let keypair =
        keypair_from_mnemonic(mnemonic, passphrase, account, change, address_index, scheme)?;
    ext::sign_call_with_keypair(&keypair, call, &ctx).map_err(crate::to_js_error)
}

/// BIP39 mnemonic -> 64-byte seed (bridge to the seed-based API).
#[wasm_bindgen(js_name = mnemonicToSeed)]
pub fn mnemonic_to_seed_js(mnemonic: String, passphrase: Option<String>) -> Result<Vec<u8>, JsError> {
    let mut seed = SensitiveBytes64::zeroed();
    mnemonic_to_seed(mnemonic, passphrase.as_deref(), &mut seed)
        .map_err(|e| JsError::new(&alloc::format!("mnemonic_to_seed failed: {e}")))?;
    Ok(seed.as_mut_bytes().to_vec())
}
