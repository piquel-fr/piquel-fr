//! Scope requirements are checked at compile time.

/// Requiring an undeclared scope, or declaring an invalid scope name, fails to compile.
#[test]
fn scope_mistakes_do_not_compile() {
    trybuild::TestCases::new().compile_fail("tests/ui/*.rs");
}
