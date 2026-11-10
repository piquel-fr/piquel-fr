//! Look-alike vectors.
use super::Skeleton;

/// Look-alikes share a skeleton, however they are cased or punctuated; distinct
/// names do not.
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
    ] {
        assert_eq!(Skeleton::of(left), Skeleton::of(right), "{left} / {right}");
    }
    assert_eq!(Skeleton::of("rn-0-1i5-vv").as_str(), "mollsw");
    assert_ne!(Skeleton::of("alice"), Skeleton::of("alicia"));
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
