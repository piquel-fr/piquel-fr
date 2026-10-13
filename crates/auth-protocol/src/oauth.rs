//! OAuth 2.0 and `OpenID` Connect wire vocabulary, shared by the OIDC provider and
//! the social-login client so both sides spell the protocol identically.

piquel_common::str_enum! {
    /// Token endpoint grants (RFC 6749 §4.1.3 and §6).
    pub enum GrantType {
        /// Exchange a single-use authorization code, bound to PKCE.
        AuthorizationCode = "authorization_code",
        /// Rotate a refresh token.
        RefreshToken = "refresh_token",
    }
}

piquel_common::str_enum! {
    /// Authorization response types. Only the code flow is supported.
    pub enum ResponseType {
        /// Return an authorization code to the redirect URI.
        Code = "code",
    }
}

piquel_common::str_enum! {
    /// PKCE code challenge methods (RFC 7636). `plain` is deliberately absent.
    pub enum CodeChallengeMethod {
        /// The challenge is the base64url SHA-256 of the verifier.
        S256 = "S256",
    }
}

piquel_common::str_enum! {
    /// OIDC `prompt` values controlling browser interaction.
    pub enum Prompt {
        /// Fail instead of showing any page.
        None = "none",
        /// Require a fresh sign-in.
        Login = "login",
        /// Require explicit consent.
        Consent = "consent",
        /// Let the user choose an account.
        SelectAccount = "select_account",
    }
}

piquel_common::str_enum! {
    /// Standard OIDC scopes. Clients may also be granted registered extension scopes.
    pub enum Scope {
        /// Issue an ID token and allow `UserInfo`.
        OpenId = "openid",
        /// Include profile claims.
        Profile = "profile",
        /// Include email claims.
        Email = "email",
        /// Allow refresh tokens when the client permits them.
        OfflineAccess = "offline_access",
    }
}
