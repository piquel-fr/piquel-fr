//! Values of the authentication claims (`acr`, `amr`) that tokens report about the
//! browser session behind a grant.

piquel_common::str_enum! {
    /// `amr` values (RFC 8176): how the user authenticated. This is the wire view,
    /// separate from [`crate::AuthenticationMethod`], which auth stores on sessions.
    pub enum Amr {
        /// Proof of possession of a key, such as a passkey.
        Pop = "pop",
        /// More than one factor.
        Mfa = "mfa",
        /// User presence and verification, such as a passkey's PIN or biometric.
        User = "user",
        /// An external identity provider. RFC 8176 registers no such value; this is
        /// Piquel's documented spelling.
        Fed = "fed",
    }
}

piquel_common::str_enum! {
    /// `acr` values: the authentication context class a session reached, strongest first.
    pub enum Acr {
        /// Phishing-resistant authentication, such as a passkey with user
        /// verification (OpenID Connect EAP ACR Values).
        PhishingResistant = "phr",
        /// Sign-in through an external identity provider.
        Social = "urn:piquel:acr:social",
    }
}

impl Acr {
    /// Whether a session at this class meets `required`. Phishing-resistant
    /// authentication meets every class.
    #[must_use]
    pub const fn satisfies(self, required: Self) -> bool {
        matches!(
            (self, required),
            (Self::PhishingResistant, _) | (Self::Social, Self::Social)
        )
    }

    /// The class an authorization targets from its space-separated `acr_values`, in
    /// the client's order of preference (OIDC Core §3.1.2.1): the first known value.
    /// Unknown values are skipped, and with none known there is no target.
    ///
    /// Every active account keeps a passkey, and a passkey meets every class, so any
    /// account can reach the first known value; no later value needs considering.
    #[must_use]
    pub fn select(acr_values: &str) -> Option<Self> {
        acr_values
            .split_ascii_whitespace()
            .find_map(|value| value.parse().ok())
    }
}

#[cfg(test)]
mod tests {
    //! Class ordering and `acr_values` selection.
    use super::*;

    /// Phishing-resistant authentication meets both classes; social meets only itself.
    #[test]
    fn stronger_classes_satisfy_weaker_ones() {
        assert!(Acr::PhishingResistant.satisfies(Acr::PhishingResistant));
        assert!(Acr::PhishingResistant.satisfies(Acr::Social));
        assert!(Acr::Social.satisfies(Acr::Social));
        assert!(!Acr::Social.satisfies(Acr::PhishingResistant));
    }

    /// The client's order wins, unknown values are skipped, and nothing known means
    /// no target.
    #[test]
    fn selection_takes_the_first_known_value() {
        assert_eq!(Acr::select("urn:piquel:acr:social phr"), Some(Acr::Social));
        assert_eq!(
            Acr::select("phr urn:piquel:acr:social"),
            Some(Acr::PhishingResistant)
        );
        assert_eq!(
            Acr::select("urn:example:gold  phr"),
            Some(Acr::PhishingResistant)
        );
        assert_eq!(Acr::select("urn:example:gold 2"), None);
        assert_eq!(Acr::select(""), None);
    }
}
