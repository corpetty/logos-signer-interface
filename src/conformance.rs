//! The suite every signer module runs in its own CI. It drives a [`Signer`] in process and checks
//! every answer with [`crate::verify`], against the account's public material only.
//!
//! ```ignore
//! let fixture = Fixture { secret: Some(Secret::new("pw")), wrong_secret: Some(Secret::new("no")) };
//! conformance::run(&mut my_signer, &fixture, &mut |_, _| {});
//! ```

use rand_core::{OsRng, RngCore};

use crate::verify::check;
use crate::wire::*;
use crate::{Signer, INTERFACE};

pub struct Fixture {
    /// The secret `sign` needs, when `signer_info` says it collects one.
    pub secret: Option<Secret>,
    pub wrong_secret: Option<Secret>,
}

/// Called while a job waits on its device: confirm it the way a person would.
pub type Drive<'a, S> = dyn FnMut(&mut S, &str) + 'a;

fn random_digest() -> String {
    let mut b = [0u8; 32];
    OsRng.fill_bytes(&mut b);
    hex::encode(b)
}

/// Hash items for an account: two for Bitcoin (a receive and a change key), one for EVM.
pub fn items_for(account: &Account) -> Vec<HashItem> {
    match account.family {
        Family::Evm => vec![HashItem {
            path: None,
            scheme: Scheme::Evm,
            digest: random_digest(),
        }],
        family => {
            let scheme = if family == Family::Bitcoin {
                Scheme::Ecdsa
            } else {
                Scheme::Bip86
            };
            let base = account.path.clone().unwrap_or_default();
            ["0/0", "1/3"]
                .into_iter()
                .map(|tail| HashItem {
                    path: Some(format!("{base}/{tail}")),
                    scheme,
                    digest: random_digest(),
                })
                .collect()
        }
    }
}

fn request(account: &Account, items: Vec<HashItem>, secret: Option<Secret>) -> SignRequest {
    SignRequest {
        account: account.id.clone(),
        payload: Payload::Hash { items },
        secret,
    }
}

/// Run a job to its end, driving the device while it waits.
fn settle<S: Signer>(s: &mut S, job: &str, drive: &mut Drive<'_, S>) -> JobStatus {
    for _ in 0..50 {
        let st = s.status(job).expect("status of a job the signer just started");
        if st.state.is_final() {
            return st;
        }
        drive(s, job);
    }
    panic!("job {job} never settled");
}

pub fn info_is_well_formed<S: Signer>(s: &S) {
    let info = s.info();
    assert_eq!(info.interface, INTERFACE, "interface version");
    assert!(!info.kind.is_empty(), "kind");
    assert!(!info.families.is_empty(), "families");
    assert!(!info.request_kinds.is_empty(), "request kinds");
    if !info.shows_request {
        assert!(
            info.request_kinds == [RequestKind::Hash],
            "a signer without a screen signs hashes only"
        );
    }
}

pub fn accounts_are_public_and_match_info<S: Signer>(s: &mut S) {
    let info = s.info();
    let accounts = s.accounts().expect("accounts");
    for a in &accounts {
        assert!(!a.id.is_empty(), "account id");
        assert!(
            info.families.contains(&a.family),
            "{}: family {:?} not in signer_info",
            a.id,
            a.family
        );
        match a.family {
            Family::Evm => {
                let addr = a.address.as_deref().unwrap_or_default();
                assert!(
                    addr.starts_with("0x") && addr.len() == 42,
                    "{}: EVM address {addr:?}",
                    a.id
                );
            }
            _ => {
                let xpub = a.xpub.as_deref().unwrap_or_default();
                assert!(
                    xpub.starts_with("xpub") || xpub.starts_with("tpub"),
                    "{}: an xpub, never a private key",
                    a.id
                );
                assert!(a.path.is_some() && a.chain.is_some(), "{}: path and chain", a.id);
                assert_eq!(a.fingerprint.as_deref().map(str::len), Some(8), "{}: fingerprint", a.id);
            }
        }
    }
}

pub fn unknown_accounts_and_jobs_are_refused<S: Signer>(s: &mut S, fx: &Fixture) {
    let ghost = Account {
        id: "no-such-account".into(),
        family: Family::Evm,
        chain: None,
        path: None,
        fingerprint: None,
        address: None,
        xpub: None,
        label: None,
        available: true,
    };
    let e = s
        .sign(request(&ghost, items_for(&ghost), fx.secret.clone()))
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::UnknownAccount);
    assert_eq!(s.status("job_unknown").unwrap_err().code, ErrorCode::UnknownJob);
    assert_eq!(s.result("job_unknown").unwrap_err().code, ErrorCode::UnknownJob);
}

pub fn kinds_it_does_not_sign_are_refused<S: Signer>(s: &mut S, fx: &Fixture) {
    let info = s.info();
    let Some(account) = s
        .accounts()
        .expect("accounts")
        .into_iter()
        .find(|a| a.family == Family::Evm)
    else {
        return;
    };
    if info.request_kinds.contains(&RequestKind::EvmMessage) {
        return;
    }
    let r = SignRequest {
        account: account.id.clone(),
        payload: Payload::EvmMessage {
            message: hex::encode("hello"),
        },
        secret: fx.secret.clone(),
    };
    assert_eq!(s.sign(r).unwrap_err().code, ErrorCode::Unsupported);
}

pub fn a_wrong_or_missing_secret_signs_nothing<S: Signer>(s: &mut S, fx: &Fixture, drive: &mut Drive<'_, S>) {
    if s.info().collects == Collects::Nothing {
        return;
    }
    let account = s.accounts().expect("accounts").remove(0);
    for (secret, code) in [
        (fx.wrong_secret.clone(), ErrorCode::WrongSecret),
        (None, ErrorCode::Locked),
    ] {
        let refused = match s.sign(request(&account, items_for(&account), secret)) {
            Err(e) => e,
            Ok(job) => {
                let st = settle(s, &job, drive);
                assert_ne!(st.state, JobState::Done, "signed without its secret");
                st.error.expect("a failed job says why")
            }
        };
        assert_eq!(refused.code, code);
    }
}

pub fn every_account_signs_and_every_signature_checks<S: Signer>(s: &mut S, fx: &Fixture, drive: &mut Drive<'_, S>) {
    for account in s.accounts().expect("accounts") {
        let items = items_for(&account);
        let job = s
            .sign(request(&account, items.clone(), fx.secret.clone()))
            .expect("sign");
        let st = settle(s, &job, drive);
        assert_eq!(st.state, JobState::Done, "{}: {:?}", account.id, st.error);
        let sigs = s.result(&job).expect("result");
        assert_eq!(sigs.len(), items.len(), "{}: one signature per item", account.id);
        for sig in &sigs {
            check(&account, &items[sig.item], sig).unwrap_or_else(|e| panic!("{}: {e}", account.id));
        }
        assert_eq!(s.result(&job).expect("result again"), sigs, "results repeat");
        s.cancel(&job).expect("cancelling a finished job is harmless");
        assert_eq!(s.status(&job).expect("status").state, JobState::Done);
    }
}

pub fn paths_outside_an_account_are_refused<S: Signer>(s: &mut S, fx: &Fixture, drive: &mut Drive<'_, S>) {
    for account in s
        .accounts()
        .expect("accounts")
        .into_iter()
        .filter(|a| a.family.is_bitcoin())
    {
        let mut items = items_for(&account);
        items[0].path = Some("m/84'/1'/99'/0/0".into());
        let refused = match s.sign(request(&account, items, fx.secret.clone())) {
            Err(e) => e,
            Ok(job) => settle(s, &job, drive).error.expect("signed outside the account"),
        };
        assert_eq!(refused.code, ErrorCode::Invalid, "{}", account.id);
    }
}

/// Every check, in order.
pub fn run<S: Signer>(s: &mut S, fx: &Fixture, drive: &mut Drive<'_, S>) {
    info_is_well_formed(s);
    accounts_are_public_and_match_info(s);
    unknown_accounts_and_jobs_are_refused(s, fx);
    kinds_it_does_not_sign_are_refused(s, fx);
    a_wrong_or_missing_secret_signs_nothing(s, fx, drive);
    every_account_signs_and_every_signature_checks(s, fx, drive);
    paths_outside_an_account_are_refused(s, fx, drive);
}
