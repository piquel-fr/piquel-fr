//! Requirement checks and the authorization parameters they produce.
use super::*;

/// A passkey confirmation within five minutes, checked at a fixed `now`.
const RECENT_PASSKEY: StepUpRequirement = StepUpRequirement::passkey_within(300);

/// An authentication passes only when its `acr` meets the requirement's (`phr`
/// meets `social` too) and its `auth_time` is at most `max_age` old, to the part of
/// a second. A missing claim fails any requirement on it, and `max_age=0` is a
/// requirement, not its absence.
#[test]
fn checks_need_a_strong_enough_and_recent_enough_authentication() {
    let social = StepUpRequirement {
        acr: Some(Acr::Social),
        max_age: None,
    };
    let now_only = StepUpRequirement {
        acr: None,
        max_age: Some(0),
    };
    let now = DateTime::from_timestamp(1_800_000_000, 0).expect("timestamp");
    let ago = |milliseconds: i64| Some(now - TimeDelta::milliseconds(milliseconds));
    let (phr, weak) = (Some(&Acr::PhishingResistant), Some(&Acr::Social));
    for (requirement, acr, auth_time, passes) in [
        (RECENT_PASSKEY, phr, ago(0), true),
        (RECENT_PASSKEY, phr, ago(300_000), true),
        (RECENT_PASSKEY, phr, ago(300_500), false),
        (RECENT_PASSKEY, phr, None, false),
        (RECENT_PASSKEY, weak, ago(10_000), false),
        (RECENT_PASSKEY, None, ago(10_000), false),
        (social, phr, None, true),
        (now_only, None, ago(0), true),
        (now_only, None, ago(1_000), false),
        (StepUpRequirement::default(), None, None, true),
    ] {
        let expected = if passes { Ok(()) } else { Err(requirement) };
        assert_eq!(
            requirement.check(acr, auth_time, now),
            expected,
            "{requirement:?} {acr:?} {auth_time:?}"
        );
    }
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
