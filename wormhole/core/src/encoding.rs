//! Text forms used at the JS boundary: `0x` hex and SS58 (prefix 189).

use sp_core::crypto::{AccountId32, Ss58AddressFormat, Ss58Codec};

pub const SS58_PREFIX: u16 = 189;

pub fn to_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

pub fn from_hex(s: &str, field: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    hex::decode(s.strip_prefix("0x").unwrap_or(s)).map_err(|_| format!("{field}: invalid hex"))
}

pub fn hex32(s: &str, field: &str) -> Result<[u8; 32], String> {
    from_hex(s, field)?
        .try_into()
        .map_err(|_| format!("{field}: expected 32 bytes"))
}

pub fn bytes32(bytes: &[u8], field: &str) -> Result<[u8; 32], String> {
    bytes
        .try_into()
        .map_err(|_| format!("{field}: expected 32 bytes"))
}

pub fn ss58(account: [u8; 32]) -> String {
    AccountId32::new(account).to_ss58check_with_version(Ss58AddressFormat::custom(SS58_PREFIX))
}

/// `0x` hex or SS58 account.
pub fn account_id(s: &str, field: &str) -> Result<[u8; 32], String> {
    let s = s.trim();
    if s.starts_with("0x") {
        return hex32(s, field);
    }
    AccountId32::from_ss58check_with_version(s)
        .map(|(account, _)| account.into())
        .map_err(|_| format!("{field}: invalid SS58 address"))
}

/// `hex[levels][3]` sibling hashes to the circuit's sibling arrays.
pub fn siblings(levels: &[Vec<String>]) -> Result<Vec<crate::leaf::Siblings>, String> {
    levels
        .iter()
        .enumerate()
        .map(|(i, level)| {
            let parsed = level
                .iter()
                .map(|h| hex32(h, "siblings"))
                .collect::<Result<Vec<_>, _>>()?;
            parsed
                .try_into()
                .map_err(|_| format!("siblings: level {i} must have 3 hashes"))
        })
        .collect()
}
