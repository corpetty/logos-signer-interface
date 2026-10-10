//! A signer with software keys behind the interface: an EVM account, a native segwit and a taproot
//! account from the "test … junk" phrase. Optionally it asks for a secret, or holds every job until
//! [`MockSigner::confirm`], the way a device waits for its button.

use std::str::FromStr;

use bip32::{DerivationPath, Prefix, XPrv};
use k256::elliptic_curve::point::AffineCoordinates;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{schnorr, PublicKey};

use crate::jobs::JobTable;
use crate::verify::{bip86_tweak, evm_address, hex32, relative};
use crate::wire::*;
use crate::{Signer, INTERFACE};

pub const PHRASE: &str = "test test test test test test test test test test test junk";

#[derive(Clone)]
pub struct MockOptions {
    pub collects: Collects,
    /// The secret it accepts when `collects` asks for one.
    pub secret: String,
    /// Jobs wait in `confirm_on_device` until confirmed or refused.
    pub needs_confirmation: bool,
    pub request_kinds: Vec<RequestKind>,
}

impl Default for MockOptions {
    fn default() -> Self {
        MockOptions {
            collects: Collects::Nothing,
            secret: String::new(),
            needs_confirmation: false,
            request_kinds: vec![RequestKind::Hash],
        }
    }
}

struct Held {
    account: Account,
    key: XPrv,
}

pub struct MockSigner {
    opts: MockOptions,
    accounts: Vec<Held>,
    jobs: JobTable,
    waiting: Vec<(String, SignRequest)>,
}

fn fingerprint(master: &XPrv) -> String {
    hex::encode(master.public_key().fingerprint())
}

impl MockSigner {
    pub fn new(opts: MockOptions) -> Self {
        let mut seed = [0u8; 64];
        pbkdf2::pbkdf2_hmac::<sha2::Sha512>(PHRASE.as_bytes(), b"mnemonic", 2048, &mut seed);
        let master = XPrv::new(seed).expect("master");
        let fp = fingerprint(&master);
        let derive = |p: &str| XPrv::derive_from_path(seed, &DerivationPath::from_str(p).unwrap()).unwrap();

        let evm = derive("m/44'/60'/0'/0/0");
        let address = evm_address(&PublicKey::from(evm.public_key().public_key()));
        let mut accounts = vec![Held {
            account: Account {
                id: address.clone(),
                family: Family::Evm,
                chain: None,
                path: Some("m/44'/60'/0'/0/0".into()),
                fingerprint: Some(fp.clone()),
                address: Some(address),
                xpub: None,
                label: Some("Mock EVM".into()),
                available: true,
            },
            key: evm,
        }];
        for (id, family, path, label) in [
            ("mock-segwit", Family::Bitcoin, "m/84'/1'/0'", "Mock native segwit"),
            ("mock-taproot", Family::BitcoinTaproot, "m/86'/1'/0'", "Mock taproot"),
        ] {
            let key = derive(path);
            accounts.push(Held {
                account: Account {
                    id: id.into(),
                    family,
                    chain: Some(Chain::Test),
                    path: Some(path.into()),
                    fingerprint: Some(fp.clone()),
                    address: None,
                    xpub: Some(key.public_key().to_string(Prefix::TPUB)),
                    label: Some(label.into()),
                    available: true,
                },
                key,
            });
        }
        MockSigner {
            opts,
            accounts,
            jobs: JobTable::new(),
            waiting: Vec::new(),
        }
    }

    /// The person confirms on the "device".
    pub fn confirm(&mut self, job: &str) -> Result<()> {
        let at = self.waiting.iter().position(|(j, _)| j == job);
        let Some(at) = at else {
            return Err(SignerError::new(ErrorCode::UnknownJob, job));
        };
        let (_, request) = self.waiting.remove(at);
        let outcome = self.sign_now(&request);
        self.jobs.finish(job, outcome)
    }

    /// The person declines on the "device".
    pub fn refuse(&mut self, job: &str) -> Result<()> {
        self.waiting.retain(|(j, _)| j != job);
        self.jobs
            .finish(job, Err(SignerError::new(ErrorCode::Refused, "declined on the device")))
    }

    fn held(&self, id: &str) -> Result<&Held> {
        self.accounts
            .iter()
            .find(|h| h.account.id.eq_ignore_ascii_case(id))
            .ok_or_else(|| SignerError::new(ErrorCode::UnknownAccount, format!("no account {id}")))
    }

    fn sign_now(&self, request: &SignRequest) -> Result<Vec<Signature>> {
        let held = self.held(&request.account)?;
        let Payload::Hash { items } = &request.payload else {
            return Err(SignerError::new(ErrorCode::Unsupported, "the mock signs hashes only"));
        };
        items
            .iter()
            .enumerate()
            .map(|(i, item)| sign_item(held, i, item))
            .collect()
    }
}

fn sign_item(held: &Held, index: usize, item: &HashItem) -> Result<Signature> {
    let digest = hex32(&item.digest)?;
    let unsupported = || {
        SignerError::new(
            ErrorCode::Unsupported,
            format!("{:?} for {:?}", item.scheme, held.account.family),
        )
    };
    let mut key = held.key.clone();
    if held.account.family.is_bitcoin() {
        let base = held.account.path.as_deref().unwrap_or_default();
        let path = item
            .path
            .as_deref()
            .ok_or_else(|| SignerError::new(ErrorCode::Invalid, "Bitcoin item without a path"))?;
        for child in relative(base, path)? {
            key = key
                .derive_child(child)
                .map_err(|e| SignerError::new(ErrorCode::Internal, e.to_string()))?;
        }
    } else if item.path.is_some() {
        return Err(SignerError::new(
            ErrorCode::Invalid,
            "an EVM account signs with its own key",
        ));
    }
    let secret = key.private_key().clone();
    match (held.account.family, item.scheme) {
        (Family::Evm, Scheme::Evm) | (Family::Bitcoin, Scheme::Ecdsa) => {
            let (sig, id) = secret
                .sign_prehash_recoverable(&digest)
                .map_err(|e| SignerError::new(ErrorCode::Internal, e.to_string()))?;
            let pubkey = PublicKey::from(secret.verifying_key());
            Ok(Signature {
                item: index,
                signature: hex::encode(sig.to_bytes()),
                recovery_id: (item.scheme == Scheme::Evm).then(|| id.to_byte()),
                pubkey: hex::encode(pubkey.to_encoded_point(true).as_bytes()),
            })
        }
        (Family::BitcoinTaproot, Scheme::Bip86) => {
            let internal = PublicKey::from(secret.verifying_key());
            let (tweak, output) = bip86_tweak(&internal)?;
            let mut d = *secret.as_nonzero_scalar().as_ref();
            if bool::from(internal.as_affine().y_is_odd()) {
                d = -d;
            }
            let signer = schnorr::SigningKey::from_bytes(&(d + tweak).to_bytes())
                .map_err(|e| SignerError::new(ErrorCode::Internal, e.to_string()))?;
            let sig = signer
                .sign_raw(&digest, &[0u8; 32])
                .map_err(|e| SignerError::new(ErrorCode::Internal, e.to_string()))?;
            Ok(Signature {
                item: index,
                signature: hex::encode(sig.to_bytes()),
                recovery_id: None,
                pubkey: hex::encode(output.to_bytes()),
            })
        }
        _ => Err(unsupported()),
    }
}

impl Signer for MockSigner {
    fn info(&self) -> SignerInfo {
        SignerInfo {
            interface: INTERFACE.into(),
            kind: "mock".into(),
            model: "software keys".into(),
            families: vec![Family::Evm, Family::Bitcoin, Family::BitcoinTaproot],
            request_kinds: self.opts.request_kinds.clone(),
            shows_request: self.opts.needs_confirmation,
            collects: self.opts.collects,
        }
    }

    fn accounts(&mut self) -> Result<Vec<Account>> {
        Ok(self.accounts.iter().map(|h| h.account.clone()).collect())
    }

    fn sign(&mut self, request: SignRequest) -> Result<String> {
        self.held(&request.account)?;
        if !self.opts.request_kinds.contains(&request.payload.kind()) {
            return Err(SignerError::new(
                ErrorCode::Unsupported,
                format!("{:?}", request.payload.kind()),
            ));
        }
        if self.opts.collects != Collects::Nothing {
            match &request.secret {
                None => return Err(SignerError::new(ErrorCode::Locked, "this signer needs its secret")),
                Some(s) if s.expose() != self.opts.secret => {
                    return Err(SignerError::new(ErrorCode::WrongSecret, "wrong secret"))
                }
                Some(_) => {}
            }
        }
        if self.opts.needs_confirmation {
            let job = self.jobs.start(JobState::ConfirmOnDevice);
            self.waiting.push((job.clone(), request));
            return Ok(job);
        }
        let job = self.jobs.start(JobState::Working);
        let outcome = self.sign_now(&request);
        self.jobs.finish(&job, outcome)?;
        Ok(job)
    }

    fn status(&mut self, job: &str) -> Result<JobStatus> {
        self.jobs.status(job)
    }

    fn result(&mut self, job: &str) -> Result<Vec<Signature>> {
        self.jobs.result(job)
    }

    fn cancel(&mut self, job: &str) -> Result<()> {
        self.waiting.retain(|(j, _)| j != job);
        self.jobs.cancel(job)
    }
}
