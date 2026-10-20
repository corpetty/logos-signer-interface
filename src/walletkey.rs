//! The key that opens a Bitcoin account's data: the public key at a reserved hardened path, the same
//! from every holder of the account's seed. A signer seals the account's xpub under it and hands the
//! manager the database key it gives; nothing signs at that path.

use std::str::FromStr;

use bip32::XPub;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::verify::parse_path;
use crate::wire::{Chain, ErrorCode, Family, Result, Secret, SignerError};

/// "LOGO" in ASCII: a purpose no account uses.
pub const PURPOSE: u32 = 1_280_263_247;
const SALT: &[u8] = b"logos/v1";
const SEALED: &str = "v1:";

fn invalid(msg: impl Into<String>) -> SignerError {
    SignerError::new(ErrorCode::Invalid, msg)
}

/// What makes two signers' Bitcoin accounts one: `btc_` and 32 hex of a hash over the family, the
/// chain, the chain code and the key, whatever the xpub's metadata.
pub fn roster_key(family: Family, chain: Option<Chain>, xpub: &str) -> Result<String> {
    let x = XPub::from_str(xpub.trim()).map_err(|e| invalid(format!("xpub: {e}")))?;
    let json = |v: serde_json::Result<String>| v.map_err(|e| invalid(e.to_string()));
    let mut h = Sha256::new();
    h.update(json(serde_json::to_string(&family))?.as_bytes());
    h.update(json(serde_json::to_string(&chain))?.as_bytes());
    h.update(x.attrs().chain_code);
    h.update(x.public_key().to_encoded_point(true).as_bytes());
    Ok(format!("btc_{}", hex::encode(&h.finalize()[..16])))
}

/// The xpub is this account's: its roster key is `key`.
pub fn check_xpub(key: &str, family: Family, chain: Option<Chain>, xpub: &str) -> Result<()> {
    if roster_key(family, chain, xpub)? != key {
        return Err(invalid("the xpub is not this account's"));
    }
    Ok(())
}

/// `m/1280263247'/i'`, with `i` the first 31 bits of the roster key: one key per account.
pub fn wallet_key_path(roster_key: &str) -> Result<String> {
    let digits = roster_key
        .strip_prefix("btc_")
        .filter(|d| d.len() == 32)
        .ok_or_else(|| invalid(format!("roster key {roster_key:?}")))?;
    let head = u32::from_str_radix(&digits[..8], 16).map_err(|_| invalid("roster key is not hex"))?;
    Ok(format!("m/{PURPOSE}'/{}'", head & 0x7fff_ffff))
}

/// Under the reserved purpose, hardened or not: nothing may sign there.
pub fn is_reserved(path: &str) -> bool {
    parse_path(path)
        .ok()
        .and_then(|p| p.first().map(|c| c.index() == PURPOSE))
        .unwrap_or(false)
}

/// An EVM account's path sits under `m/44'/60'`.
pub fn evm_path_ok(path: &str) -> bool {
    parse_path(path).is_ok_and(|p| {
        p.len() >= 2 && p[0].is_hardened() && p[0].index() == 44 && p[1].is_hardened() && p[1].index() == 60
    })
}

/// The keys one account's open key gives: its database key, and the key its xpub is sealed under.
pub struct AccountKeys {
    database: Zeroizing<[u8; 32]>,
    seal: Zeroizing<[u8; 32]>,
}

/// `seed_key`: the account's key at [`wallet_key_path`], 33 bytes compressed.
pub fn account_keys(seed_key: &[u8]) -> Result<AccountKeys> {
    if seed_key.len() != 33 {
        return Err(invalid("an open key is 33 bytes"));
    }
    let hk = Hkdf::<Sha256>::new(Some(SALT), seed_key);
    let mut database = Zeroizing::new([0u8; 32]);
    let mut seal = Zeroizing::new([0u8; 32]);
    hk.expand(b"wallet-db", &mut database[..])
        .and_then(|_| hk.expand(b"xpub", &mut seal[..]))
        .map_err(|_| SignerError::new(ErrorCode::Internal, "key expansion"))?;
    Ok(AccountKeys { database, seal })
}

impl AccountKeys {
    /// The database key, hex, as the wallet core reads it.
    pub fn database_key(&self) -> Secret {
        Secret::new(hex::encode(&self.database[..]))
    }

    fn cipher(&self) -> Result<XChaCha20Poly1305> {
        XChaCha20Poly1305::new_from_slice(&self.seal[..]).map_err(|_| SignerError::new(ErrorCode::Internal, "seal key"))
    }

    pub fn seal(&self, roster_key: &str, xpub: &str) -> Result<String> {
        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut nonce);
        let sealed = self
            .cipher()?
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: xpub.as_bytes(),
                    aad: roster_key.as_bytes(),
                },
            )
            .map_err(|_| SignerError::new(ErrorCode::Internal, "sealing the xpub"))?;
        Ok(format!("{SEALED}{}{}", hex::encode(nonce), hex::encode(sealed)))
    }

    /// The sealed xpub, or [`ErrorCode::WrongSeed`] when this key is another seed's.
    pub fn unseal(&self, roster_key: &str, sealed: &str) -> Result<Zeroizing<String>> {
        let raw = sealed
            .strip_prefix(SEALED)
            .and_then(|h| hex::decode(h).ok())
            .filter(|b| b.len() > 24)
            .ok_or_else(|| invalid("not a sealed xpub"))?;
        let nonce: [u8; 24] = raw[..24].try_into().map_err(|_| invalid("not a sealed xpub"))?;
        let open = self
            .cipher()?
            .decrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &raw[24..],
                    aad: roster_key.as_bytes(),
                },
            )
            .map_err(|_| SignerError::new(ErrorCode::WrongSeed, "this device holds another seed"))?;
        String::from_utf8(open)
            .map(Zeroizing::new)
            .map_err(|_| invalid("the sealed xpub is not text"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bip32::{DerivationPath, Prefix, XPrv};

    fn tpub() -> String {
        let path = DerivationPath::from_str("m/84'/1'/0'").unwrap();
        XPrv::derive_from_path([7u8; 64], &path)
            .unwrap()
            .public_key()
            .to_string(Prefix::TPUB)
    }

    #[test]
    fn a_key_path_is_hardened_under_the_purpose_and_stable() {
        let key = format!("btc_{}", "8badf00d".repeat(4));
        assert_eq!(wallet_key_path(&key).unwrap(), "m/1280263247'/195948557'");
        assert!(is_reserved(&wallet_key_path(&key).unwrap()));
        assert!(is_reserved("m/1280263247/0"));
        assert!(!is_reserved("m/84'/1'/0'/0/0"));
        assert!(wallet_key_path("btc_short").is_err());
    }

    #[test]
    fn evm_paths_sit_under_44_60() {
        assert!(evm_path_ok("m/44'/60'/0'/0/0"));
        assert!(!evm_path_ok("m/44'/0'/0'/0/0"));
        assert!(!evm_path_ok("m/1280263247'/0'"));
        assert!(!evm_path_ok("garbage"));
    }

    #[test]
    fn a_sealed_xpub_opens_only_with_its_key_and_account() {
        let keys = account_keys(&[2u8; 33]).unwrap();
        let other = account_keys(&[3u8; 33]).unwrap();
        let sealed = keys.seal("btc_a", &tpub()).unwrap();
        assert!(!sealed.contains("tpub"));
        assert_eq!(keys.unseal("btc_a", &sealed).unwrap().as_str(), tpub());
        assert_eq!(other.unseal("btc_a", &sealed).unwrap_err().code, ErrorCode::WrongSeed);
        assert_eq!(keys.unseal("btc_b", &sealed).unwrap_err().code, ErrorCode::WrongSeed);
        assert_ne!(keys.database_key(), other.database_key());
        assert_eq!(keys.database_key().expose().len(), 64);
    }

    #[test]
    fn the_roster_key_ignores_xpub_metadata_and_checks() {
        let key = roster_key(Family::Bitcoin, Some(Chain::Test), &tpub()).unwrap();
        assert!(key.starts_with("btc_") && key.len() == 36);
        assert!(check_xpub(&key, Family::Bitcoin, Some(Chain::Test), &tpub()).is_ok());
        assert!(check_xpub(&key, Family::BitcoinTaproot, Some(Chain::Test), &tpub()).is_err());
    }
}
