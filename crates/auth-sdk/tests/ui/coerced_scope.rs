use piquel_auth::AccessToken;
use std::marker::PhantomData;

/// Two scope sets told apart only by a lifetime.
struct Policy<T>(PhantomData<T>);

impl piquel_auth::__private::Declared for Policy<fn(&str)> {
    const NAMES: &'static [&'static str] = &["notes:read"];
}

impl piquel_auth::__private::Declared for Policy<fn(&'static str)> {
    const NAMES: &'static [&'static str] = &["notes:write"];
}

/// A proof of one set never coerces into a proof of the other.
fn coerce(token: AccessToken<Policy<fn(&str)>>) -> AccessToken<Policy<fn(&'static str)>> {
    token
}

fn main() {}
