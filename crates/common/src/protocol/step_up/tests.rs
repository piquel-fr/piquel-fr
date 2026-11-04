//! Requirement checks and the authorization parameters they produce.
use super::*;

/// A passkey confirmation within five minutes, checked at a fixed `now`.
const RECENT_PASSKEY: StepUpRequirement = StepUpRequirement::passkey_within(300);

/// The time `seconds` before a fixed `now`, and that `now`.
fn ago(seconds: i64) -> (Option<DateTime<Utc>>, DateTime<Utc>) {
    let now = DateTime::from_timestamp(1_800_000_000, 0).expect("timestamp");
    (Some(now - TimeDelta::seconds(seconds)), now)
}

/// A social sign-in, or none at all, does not meet a `phr` requirement, however recent.
#[test]
fn weak_acr_fails() {
    let (auth_time, now) = ago(10);
    for acr in [Some(&Acr::Social), None] {
        assert_eq!(
            RECENT_PASSKEY.check(acr, auth_time, now),
            Err(RECENT_PASSKEY)
        );
    }
}

/// An authentication older than `max_age`, even by part of a second, or with no
/// `auth_time`, fails.
#[test]
fn old_authentication_fails() {
    let acr = Some(&Acr::PhishingResistant);
    let (auth_time, now) = ago(300);
    let late = now + TimeDelta::milliseconds(500);
    assert_eq!(
        RECENT_PASSKEY.check(acr, auth_time, late),
        Err(RECENT_PASSKEY)
    );
    let (auth_time, now) = ago(301);
    assert_eq!(
        RECENT_PASSKEY.check(acr, auth_time, now),
        Err(RECENT_PASSKEY)
    );
    assert_eq!(RECENT_PASSKEY.check(acr, None, now), Err(RECENT_PASSKEY));
}

/// A recent passkey meets both parts, up to `max_age` exactly, and `phr` meets a
/// social requirement too.
#[test]
fn strong_recent_authentication_passes() {
    let acr = Some(&Acr::PhishingResistant);
    for age in [0, 300] {
        let (auth_time, now) = ago(age);
        assert_eq!(RECENT_PASSKEY.check(acr, auth_time, now), Ok(()));
    }
    let social = StepUpRequirement {
        acr: Some(Acr::Social),
        max_age: None,
    };
    assert_eq!(social.check(acr, None, ago(0).1), Ok(()));
    assert_eq!(
        StepUpRequirement::default().check(None, None, ago(0).1),
        Ok(())
    );
}

/// `max_age=0` needs an authentication at `now` itself: it is a requirement, not
/// its absence.
#[test]
fn zero_max_age_needs_authentication_now() {
    let now_only = StepUpRequirement {
        acr: None,
        max_age: Some(0),
    };
    let (auth_time, now) = ago(0);
    assert_eq!(now_only.check(None, auth_time, now), Ok(()));
    let (auth_time, now) = ago(1);
    assert_eq!(now_only.check(None, auth_time, now), Err(now_only));
}

/// Only the parts the requirement names become parameters.
#[test]
fn authorize_params_name_each_part() {
    assert_eq!(
        RECENT_PASSKEY.authorize_params().collect::<Vec<_>>(),
        [("acr_values", "phr".into()), ("max_age", "300".into())]
    );
    let fresh = StepUpRequirement {
        acr: None,
        max_age: Some(0),
    };
    assert_eq!(
        fresh.authorize_params().collect::<Vec<_>>(),
        [("max_age", "0".into())]
    );
    assert_eq!(StepUpRequirement::default().authorize_params().count(), 0);
}
