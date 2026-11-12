//! Signup invitations' links.
//!
//! Administrators create invitations (`AdminService::create_invitation`),
//! whatever the signup setting: while signup needs one, an invitation admits one
//! account; while it is open, it is a tracked signup link. An invitation's link
//! names the registration page with its token. The token is derived from the
//! invitation's ID with [`InvitationLinks`], and only its SHA-256 digest is
//! stored, so the email sender and a resend rebuild the link, and nobody else can.
//!
//! An invitation mailed to an address is bound to it: the account created with it
//! starts with that address, verified, since opening the mailed link proves the
//! same thing a verification email does.

use crate::{config::LinkKeys, routes};
use sourceorigin_common::{TokenId, config::Origin};
use sourceorigin_crypto::Secret;
use url::Url;

/// Derives invitation links' tokens from invitations' IDs, with keys derived
/// from the token digest keys, so every replica, the email sender and the CLI
/// derive the same token, and builds the links on auth's origin. During a change
/// of token digest key, the sender rebuilds a link under whichever key created
/// its invitation ([`LinkKeys`]).
#[derive(Clone)]
pub(crate) struct InvitationLinks {
    /// Auth's origin, where the registration page is.
    origin: Origin,
    /// HMAC keys reserved for invitation tokens.
    keys: LinkKeys,
}

impl InvitationLinks {
    /// Links on `origin`, with tokens derived with `keys`.
    pub(crate) const fn new(origin: Origin, keys: LinkKeys) -> Self {
        Self { origin, keys }
    }

    /// The token of a new invitation `id`'s link, under the current key.
    pub(crate) fn token(&self, id: TokenId) -> Secret {
        self.keys.token(id.as_uuid().as_bytes())
    }

    /// Invitation `id`'s link, as [`Self::url`] builds it, under the key whose
    /// token has the stored SHA-256 `digest`. `None` once no configured key
    /// derives it, which fails its delivery.
    pub(crate) fn link(&self, id: TokenId, digest: &[u8]) -> Option<Url> {
        let token = self.keys.rebuild(id.as_uuid().as_bytes(), digest)?;
        Some(self.url(&token))
    }

    /// The link holding `token`: the registration page, with the token in its
    /// query, so the page can show the address it invites.
    pub(crate) fn url(&self, token: &Secret) -> Url {
        let mut link = self.origin.url(routes::page::REGISTER);
        link.query_pairs_mut()
            .append_pair("invitation", &token.encoded());
        link
    }

    /// The SHA-256 digest of an invitation token a browser `presented`, which
    /// finds its invitation, or `None` if it is not a token at all.
    pub(crate) fn digest(presented: &str) -> Option<Vec<u8>> {
        Secret::parse(presented)
            .ok()
            .map(|secret| secret.digest().as_bytes().to_vec())
    }
}
