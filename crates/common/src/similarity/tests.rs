//! Look-alike vectors, and the reserved names they guard.
use super::Skeleton;
use crate::{
    Handle, HandleError,
    clients::{DisplayName, ReservedDisplayName},
    handle::RESERVED,
};

/// Look-alikes share a skeleton, however they are cased, punctuated, accented or
/// spelled in another script; distinct names do not.
#[test]
fn skeleton_vectors() {
    for (left, right) in [
        ("s0urce0rigin", "sourceorigin"),
        ("source-origin", "sourceorigin"),
        ("Source Origin!", "sourceorigin"),
        ("rnoon", "moon"),
        ("vvave", "wave"),
        ("b0b", "bob"),
        ("5am", "sam"),
        ("adm1n", "admin"),
        // Cyrillic о and е, Greek ο, fullwidth letters, accents.
        ("gооglе", "google"),
        ("gοogle", "google"),
        ("ＧＯＯＧＬＥ", "google"),
        ("Gööglé", "google"),
    ] {
        assert_eq!(Skeleton::of(left), Skeleton::of(right), "{left} / {right}");
    }
    assert_eq!(Skeleton::of("rn-0-1i5-vv").as_str(), "mollsw");
    assert_ne!(Skeleton::of("alice"), Skeleton::of("alicia"));
    assert_eq!(Skeleton::of("日本語").as_str(), "");
}

/// A whole match finds only names the text looks like entirely; a contained match
/// also finds names inside longer text.
#[test]
fn whole_and_contained_matches() {
    let names = ["admin", "google"];
    assert_eq!(Skeleton::of("adm1n").find_alike(names), Some("admin"));
    assert_eq!(Skeleton::of("admins").find_alike(names), None);
    assert_eq!(
        Skeleton::of("Sign in with G00gle").find_contained(names),
        Some("google")
    );
    assert_eq!(Skeleton::of("Notes").find_contained(names), None);
}

/// Reserved handles and their look-alikes are refused; other handles are not.
#[test]
fn reserved_handles() {
    let reserved = |handle: &str| Handle::parse(handle).expect("valid").ensure_unreserved();
    for (handle, name) in [
        ("admin", "admin"),
        ("adm1n", "admin"),
        ("s0urce0rigin", "sourceorigin"),
        ("source-origin", "sourceorigin"),
        ("postmaster", "postmaster"),
        ("www", "www"),
    ] {
        assert_eq!(
            reserved(handle),
            Err(HandleError::Reserved(name.into())),
            "{handle}"
        );
    }
    for handle in ["alice", "admins", "sourceorigin-fan"] {
        assert_eq!(reserved(handle), Ok(()), "{handle}");
    }
}

/// Every reserved handle is a canonical handle, so it can match, and no two share
/// a skeleton, so none is listed twice.
#[test]
fn reserved_handles_are_distinct() {
    let mut skeletons = std::collections::BTreeSet::new();
    for name in RESERVED {
        let handle = name.parse::<Handle>().expect("a canonical handle");
        assert!(
            skeletons.insert(handle.skeleton()),
            "{name} is listed twice"
        );
    }
}

/// A display name containing a reserved brand, however it is spaced, cased or
/// disguised as a look-alike, is refused; one merely sharing letters with a brand
/// is not.
#[test]
fn reserved_brands_are_refused_inside_names() {
    for (name, brand) in [
        ("SourceOrigin", Some("sourceorigin")),
        ("SourceOrigin Settings", Some("sourceorigin")),
        ("my-SOURCEORIGIN.dev app", Some("sourceorigin")),
        ("S0urce0r1gin", Some("sourceorigin")),
        ("Origin Auth Login", Some("originauth")),
        ("Sign in with G00gle", Some("google")),
        ("Sign in with Gооgle", Some("google")),
        ("GitHub Desktop", Some("github")),
        ("Notes", None),
        ("Source Notes", None),
    ] {
        let name: DisplayName = name.parse().expect("display name");
        assert_eq!(
            name.ensure_unreserved(),
            brand.map_or(Ok(()), |brand| Err(ReservedDisplayName(brand))),
            "{name:?}"
        );
    }
}
