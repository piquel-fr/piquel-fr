//! Focused tests for the coarse user agent family.
use super::{Browser, Platform, UserAgentFamily};

/// Real `User-Agent` headers classify to their browser and platform.
#[test]
fn user_agents_classify() {
    let cases = [
        (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
            Browser::Chrome,
            Platform::Windows,
        ),
        (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 Edg/129.0.0.0",
            Browser::Edge,
            Platform::Windows,
        ),
        (
            "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
            Browser::Firefox,
            Platform::Linux,
        ),
        (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
            Browser::Safari,
            Platform::MacOs,
        ),
        (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 OPR/114.0.0.0",
            Browser::Opera,
            Platform::MacOs,
        ),
        (
            "Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
            Browser::Chrome,
            Platform::ChromeOs,
        ),
        (
            "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
            Browser::Safari,
            Platform::Ios,
        ),
        (
            "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/129.0.6668.69 Mobile/15E148 Safari/604.1",
            Browser::Chrome,
            Platform::Ios,
        ),
        (
            "Mozilla/5.0 (iPad; CPU OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/131.0 Mobile/15E148 Safari/605.1.15",
            Browser::Firefox,
            Platform::Ios,
        ),
        (
            "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Mobile Safari/537.36",
            Browser::Chrome,
            Platform::Android,
        ),
        (
            "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Mobile Safari/537.36 EdgA/129.0.0.0",
            Browser::Edge,
            Platform::Android,
        ),
        (
            "Mozilla/5.0 (Android 14; Mobile; rv:131.0) Gecko/131.0 Firefox/131.0",
            Browser::Firefox,
            Platform::Android,
        ),
        ("curl/8.9.1", Browser::Other, Platform::Other),
        ("", Browser::Other, Platform::Other),
    ];
    for (user_agent, browser, platform) in cases {
        assert_eq!(
            UserAgentFamily::classify(user_agent),
            UserAgentFamily { browser, platform },
            "{user_agent}"
        );
    }
}

/// The stored text round-trips and needs both halves; a half a newer release
/// wrote reads as `other`.
#[test]
fn user_agent_family_text_round_trips() {
    let family = UserAgentFamily {
        browser: Browser::Firefox,
        platform: Platform::Linux,
    };
    assert_eq!(family.to_string(), "firefox/linux");
    assert_eq!("firefox/linux".parse(), Ok(family));
    assert!("firefox".parse::<UserAgentFamily>().is_err());
    assert_eq!(
        "samsung/harmony_os".parse(),
        Ok(UserAgentFamily {
            browser: Browser::Other,
            platform: Platform::Other,
        })
    );
}
