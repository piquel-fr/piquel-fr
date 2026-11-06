use piquel_auth::{AccessToken, ProfileClaims, Scopes, Subject};

fn main() {
    let now = chrono::Utc::now();
    let _: AccessToken = AccessToken {
        subject: Subject::User("01936f3e-8c00-7000-8000-000000000001".parse().unwrap()),
        client_id: "notes-web".parse().unwrap(),
        scopes: Scopes::default(),
        token_id: "01936f3e-8c00-7000-8000-000000000003".parse().unwrap(),
        session_id: None,
        auth_time: None,
        amr: Vec::new(),
        acr: None,
        actor: None,
        confirmation: None,
        profile: ProfileClaims::default(),
        issued_at: now,
        expires_at: now,
        extra: (),
    };
}
