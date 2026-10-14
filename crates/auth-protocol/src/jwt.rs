//! JWT claims and JOSE metadata shared by token issuers and verifiers.

piquel_common::str_enum! {
    /// JWT `typ` headers. Distinct types stop an ID token being accepted as an access token.
    pub enum TokenType {
        /// Access token (RFC 9068).
        Access = "at+jwt",
        /// ID token, also accepted back as an `id_token_hint`.
        Id = "JWT",
    }
}
piquel_common::str_enum! {
    /// JWT claim names shared by token issuance, verification and `UserInfo`.
    pub enum Claim {
        /// Issuer that signed the token.
        Issuer = "iss",
        /// Account ID.
        Subject = "sub",
        /// Who the token is for: the resource for access tokens, the client for ID tokens.
        Audience = "aud",
        /// Issue time, in Unix seconds.
        IssuedAt = "iat",
        /// Expiry time, in Unix seconds.
        ExpiresAt = "exp",
        /// Browser session that authorized the grant.
        Session = "sid",
        /// When the browser session signed in.
        AuthTime = "auth_time",
        /// How the browser session signed in.
        Methods = "amr",
        /// Display name, with the profile scope.
        Name = "name",
        /// Username, with the profile scope.
        Username = "preferred_username",
        /// Primary email, with the email scope.
        Email = "email",
        /// Always true: only verified emails are released.
        EmailVerified = "email_verified",
        /// Profile version, so clients can tell when cached profile data is stale.
        ProfileVersion = "profile_version",
        /// Client that requested the access token.
        Client = "client_id",
        /// Unique access token ID.
        TokenId = "jti",
        /// Granted scopes, space-separated.
        Scope = "scope",
        /// Client nonce, echoed in the ID token.
        Nonce = "nonce",
    }
}
piquel_common::str_enum! {
    /// Signing algorithms accepted by this workspace.
    pub enum Algorithm {
        /// RSA PKCS#1 v1.5 with SHA-256.
        Rs256 = "RS256",
    }
}
piquel_common::str_enum! {
    /// JWK key families accepted for signing.
    pub enum KeyType {
        /// RSA modulus and exponent.
        Rsa = "RSA",
    }
}
piquel_common::str_enum! {
    /// JWK purposes accepted for signing keys.
    pub enum KeyUse {
        /// Digital signatures.
        Signature = "sig",
    }
}
