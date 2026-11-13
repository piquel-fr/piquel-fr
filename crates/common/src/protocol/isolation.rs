//! The browser isolation headers every response of SourceOrigin's servers
//! carries, auth's and sourceorigin.dev's alike, by name and value.

/// Whether another site's page that opens this one keeps a handle on it.
const OPENER_POLICY_HEADER: &str = "cross-origin-opener-policy";

/// `Cross-Origin-Opener-Policy`: a page of another site that opens one of
/// SourceOrigin's in a window, such as sign-in or consent, keeps no handle on it.
/// Signing in is a top-level redirect: a popup's opener loses it.
const OPENER_POLICY: &str = "same-origin";

/// Which sites' pages may embed or read a response without CORS.
const RESOURCE_POLICY_HEADER: &str = "cross-origin-resource-policy";

/// `Cross-Origin-Resource-Policy` of what other sites' pages may embed or read,
/// such as profile pictures, public documents and keys.
const RESOURCE_POLICY_PUBLIC: &str = "cross-origin";

/// `Cross-Origin-Resource-Policy` of everything else: each server's pages load
/// only its own files.
const RESOURCE_POLICY_PRIVATE: &str = "same-origin";

/// Which powerful features a page, and what it embeds, may use.
const PERMISSIONS_POLICY_HEADER: &str = "permissions-policy";

/// `Permissions-Policy`: the pages may use passkeys and write to the clipboard,
/// for their copy buttons, and no other powerful feature, nor may anything they
/// embed. A feature it leaves out keeps its default, often `self`, so every
/// feature that reaches a device, the user's data or another site is listed,
/// including ones only some browsers know yet, which Chromium logs as
/// unrecognized or as needing an origin trial.
pub const PERMISSIONS_POLICY: &str = "publickey-credentials-get=(self), publickey-credentials-create=(self), \
    clipboard-write=(self), accelerometer=(), ambient-light-sensor=(), \
    autoplay=(), bluetooth=(), browsing-topics=(), camera=(), \
    captured-surface-control=(), clipboard-read=(), compute-pressure=(), \
    deferred-fetch=(), deferred-fetch-minimal=(), device-attributes=(), \
    digital-credentials-create=(), digital-credentials-get=(), direct-sockets=(), \
    display-capture=(), encrypted-media=(), fullscreen=(), gamepad=(), \
    geolocation=(), gyroscope=(), hid=(), identity-credentials-get=(), \
    idle-detection=(), interest-cohort=(), keyboard-map=(), language-detector=(), \
    language-model=(), local-fonts=(), local-network=(), local-network-access=(), \
    loopback-network=(), magnetometer=(), media-playback-while-not-visible=(), \
    microphone=(), midi=(), on-device-speech-recognition=(), otp-credentials=(), \
    payment=(), picture-in-picture=(), private-state-token-issuance=(), \
    private-state-token-redemption=(), rewriter=(), screen-wake-lock=(), \
    serial=(), smart-card=(), speaker-selection=(), storage-access=(), \
    summarizer=(), tools=(), translator=(), usb=(), web-share=(), \
    window-management=(), writer=(), xr-spatial-tracking=()";

/// The isolation headers of a response, by name and value: other sites may embed
/// or read it only if it is `public`.
#[must_use]
pub const fn headers(public: bool) -> [(&'static str, &'static str); 3] {
    let resource_policy = if public {
        RESOURCE_POLICY_PUBLIC
    } else {
        RESOURCE_POLICY_PRIVATE
    };
    [
        (OPENER_POLICY_HEADER, OPENER_POLICY),
        (RESOURCE_POLICY_HEADER, resource_policy),
        (PERMISSIONS_POLICY_HEADER, PERMISSIONS_POLICY),
    ]
}
