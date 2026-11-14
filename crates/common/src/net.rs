//! Which IP addresses are public: the only ones auth delivers to, such as
//! back-channel logout tokens.

use ipnet::{Ipv4Net, Ipv6Net};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// IPv4 ranges a destination may not use: the special-purpose ranges that are not
/// globally reachable (RFC 6890), multicast, and the reserved block.
const REFUSED_V4: [Ipv4Net; 11] = [
    Ipv4Net::new_assert(Ipv4Addr::UNSPECIFIED, 8),
    Ipv4Net::new_assert(Ipv4Addr::new(10, 0, 0, 0), 8),
    Ipv4Net::new_assert(Ipv4Addr::new(100, 64, 0, 0), 10),
    Ipv4Net::new_assert(Ipv4Addr::new(127, 0, 0, 0), 8),
    Ipv4Net::new_assert(Ipv4Addr::new(169, 254, 0, 0), 16),
    Ipv4Net::new_assert(Ipv4Addr::new(172, 16, 0, 0), 12),
    Ipv4Net::new_assert(Ipv4Addr::new(192, 0, 0, 0), 24),
    Ipv4Net::new_assert(Ipv4Addr::new(192, 168, 0, 0), 16),
    Ipv4Net::new_assert(Ipv4Addr::new(198, 18, 0, 0), 15),
    Ipv4Net::new_assert(Ipv4Addr::new(224, 0, 0, 0), 4),
    Ipv4Net::new_assert(Ipv4Addr::new(240, 0, 0, 0), 4),
];
/// IPv6 ranges a destination may not use: unspecified, loopback and the
/// deprecated IPv4-compatible addresses (`::/96`), discard-only, local-use NAT64
/// (RFC 8215), unique-local, link-local, site-local and multicast.
const REFUSED_V6: [Ipv6Net; 7] = [
    Ipv6Net::new_assert(Ipv6Addr::UNSPECIFIED, 96),
    Ipv6Net::new_assert(Ipv6Addr::new(0x100, 0, 0, 0, 0, 0, 0, 0), 64),
    Ipv6Net::new_assert(Ipv6Addr::new(0x64, 0xff9b, 1, 0, 0, 0, 0, 0), 48),
    Ipv6Net::new_assert(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0), 7),
    Ipv6Net::new_assert(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), 10),
    Ipv6Net::new_assert(Ipv6Addr::new(0xfec0, 0, 0, 0, 0, 0, 0, 0), 10),
    Ipv6Net::new_assert(Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0), 8),
];
/// Well-known NAT64 (RFC 6052): the last 32 bits are the IPv4 address reached.
const NAT64: Ipv6Net = Ipv6Net::new_assert(Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0, 0), 96);
/// 6to4 (RFC 3056): bits 16 to 48 are the IPv4 address reached.
const SIX_TO_FOUR: Ipv6Net = Ipv6Net::new_assert(Ipv6Addr::new(0x2002, 0, 0, 0, 0, 0, 0, 0), 16);

/// Whether an address is public, so a delivery may go to it.
pub trait PublicAddress {
    /// Whether the address is outside every refused range, and so is the IPv4
    /// address it reaches when it is IPv4-mapped, NAT64 or 6to4.
    fn is_public(&self) -> bool;
}

impl PublicAddress for IpAddr {
    fn is_public(&self) -> bool {
        match self.to_canonical() {
            Self::V4(v4) => !REFUSED_V4.iter().any(|range| range.contains(&v4)),
            Self::V6(v6) => {
                let bits = u128::from(v6);
                let embedded = if NAT64.contains(&v6) {
                    u32::try_from(bits & 0xffff_ffff).ok()
                } else if SIX_TO_FOUR.contains(&v6) {
                    u32::try_from((bits >> 80) & 0xffff_ffff).ok()
                } else {
                    None
                };
                !REFUSED_V6.iter().any(|range| range.contains(&v6))
                    && embedded.is_none_or(|v4| Self::V4(v4.into()).is_public())
            }
        }
    }
}
