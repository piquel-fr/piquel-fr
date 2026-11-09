//! Type rules the compiler enforces: scopes are declared once, and validated values
//! are made only by validating.

/// Requiring an undeclared scope, declaring an invalid scope name, building a
/// validated token by hand, or checking scopes another way fails to compile.
#[test]
fn type_mistakes_do_not_compile() {
    trybuild::TestCases::new().compile_fail("tests/ui/*.rs");
}
