//! The browser isolation headers every response of SourceOrigin's servers
//! carries, auth's and sourceorigin.dev's alike, by name and value.

/// Whether another site's page that opens this one keeps a handle on it.
pub const OPENER_POLICY_HEADER: &str = "cross-origin-opener-policy";

/// `Cross-Origin-Opener-Policy`: a page of another site that opens one of
/// SourceOrigin's in a window, such as sign-in or consent, keeps no handle on it.
/// Signing in is a top-level redirect: a popup's opener loses it.
pub const OPENER_POLICY: &str = "same-origin";

/// Which sites' pages may embed or read a response without CORS.
pub const RESOURCE_POLICY_HEADER: &str = "cross-origin-resource-policy";

/// `Cross-Origin-Resource-Policy` of what other sites' pages may embed or read,
/// such as profile pictures, public documents and keys.
pub const RESOURCE_POLICY_PUBLIC: &str = "cross-origin";

/// `Cross-Origin-Resource-Policy` of everything else: each server's pages load
/// only its own files.
pub const RESOURCE_POLICY_PRIVATE: &str = "same-origin";

/// Which powerful features a page, and what it embeds, may use.
pub const PERMISSIONS_POLICY_HEADER: &str = "permissions-policy";

/// `Permissions-Policy`: the pages may use passkeys and write to the clipboard,
/// for their copy buttons, and no other powerful feature, nor may anything they
/// embed.
pub const PERMISSIONS_POLICY: &str = "publickey-credentials-get=(self), \
    publickey-credentials-create=(self), clipboard-write=(self), accelerometer=(), \
    ambient-light-sensor=(), attribution-reporting=(), autoplay=(), bluetooth=(), \
    browsing-topics=(), camera=(), compute-pressure=(), display-capture=(), \
    encrypted-media=(), fullscreen=(), gamepad=(), geolocation=(), gyroscope=(), \
    hid=(), identity-credentials-get=(), idle-detection=(), local-fonts=(), \
    magnetometer=(), microphone=(), midi=(), otp-credentials=(), payment=(), \
    picture-in-picture=(), screen-wake-lock=(), serial=(), storage-access=(), usb=(), \
    web-share=(), window-management=(), xr-spatial-tracking=()";
