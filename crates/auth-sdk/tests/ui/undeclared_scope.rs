piquel_auth::scopes! {
    pub mod notes {
        Read = "notes:read",
    }
}

fn delete(token: &piquel_auth::AccessToken) {
    let _ = token.require::<notes::Delete>();
}

fn main() {}
