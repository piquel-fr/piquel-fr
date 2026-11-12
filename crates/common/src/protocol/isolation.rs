//! The browser isolation headers every response of SourceOrigin's servers
//! carries, auth's and sourceorigin.dev's alike.

/// `Cross-Origin-Opener-Policy`: a page of another site that opens one of
/// SourceOrigin's in a window, such as sign-in or consent, keeps no handle on it.
pub const OPENER_POLICY: &str = "same-origin";

/// `Permissions-Policy`: the pages may use passkeys and write to the clipboard,
/// for their copy buttons, and no other powerful feature, nor may anything they
/// embed.
pub const PERMISSIONS_POLICY: &str = "publickey-credentials-get=(self), \
    publickey-credentials-create=(self), clipboard-write=(self), accelerometer=(), \
    autoplay=(), bluetooth=(), camera=(), display-capture=(), encrypted-media=(), \
    fullscreen=(), geolocation=(), gyroscope=(), hid=(), idle-detection=(), \
    local-fonts=(), magnetometer=(), microphone=(), midi=(), otp-credentials=(), \
    payment=(), picture-in-picture=(), screen-wake-lock=(), serial=(), \
    storage-access=(), usb=(), web-share=(), xr-spatial-tracking=()";

/// `Cross-Origin-Resource-Policy` of what other sites' pages may embed or read,
/// such as profile pictures, public documents and keys.
pub const RESOURCE_POLICY_PUBLIC: &str = "cross-origin";

/// `Cross-Origin-Resource-Policy` of the files SourceOrigin's pages load, which
/// its other sites' pages may share, as the admin dashboard does auth's
/// stylesheet and typefaces.
pub const RESOURCE_POLICY_ASSETS: &str = "same-site";

/// `Cross-Origin-Resource-Policy` of everything else.
pub const RESOURCE_POLICY_PRIVATE: &str = "same-origin";
