// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

//! Address classification for outbound requests.
//!
//! Lives in `noombat-core` because two crates need the same answer and
//! neither can depend on the other: `noombat-federation::http` guards
//! every federation fetch and delivery, and
//! `noombat_identity::oauth_mastodon` guards instance discovery. When
//! this test existed twice, one copy protected one route and the other
//! protected everything else, which is how the federation inbox came to
//! be an unauthenticated port scanner.

use std::net::{IpAddr, Ipv4Addr};

/// Whether `ip` is in a range no outbound user-directed request should
/// reach.
///
/// Covers loopback, the RFC 1918 private ranges, link-local (which is
/// where cloud instance-metadata services live), carrier-grade NAT,
/// documentation, multicast, broadcast and the reserved top of the IPv4
/// space; for IPv6, loopback, unspecified, unique-local, link-local, and
/// any IPv4-mapped form of the above.
pub fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_private_v4(v4),
        IpAddr::V6(v6) => {
            v6.is_loopback()                              // ::1
                || v6.is_unspecified()                    // ::
                || (v6.segments()[0] & 0xfe00) == 0xfc00  // fc00::/7 (ULA)
                || (v6.segments()[0] & 0xffc0) == 0xfe80  // fe80::/10 (link-local)
                // IPv4-mapped IPv6 (::ffff:a.b.c.d): an attacker writing
                // the target in this form must not slip past the v4 rules.
                || v6.to_ipv4_mapped().is_some_and(is_private_v4)
        }
    }
}

/// IPv4 reserved-range check, shared with the IPv4-mapped-IPv6 branch of
/// [`is_private_ip`].
pub fn is_private_v4(v4: Ipv4Addr) -> bool {
    v4.is_loopback()               // 127.0.0.0/8
        || v4.is_private()         // 10/8, 172.16/12, 192.168/16
        || v4.is_link_local()      // 169.254/16, the cloud metadata range
        || v4.is_broadcast()       // 255.255.255.255
        || v4.is_unspecified()     // 0.0.0.0
        || v4.is_documentation()   // 192.0.2/24, 198.51.100/24, 203.0.113/24
        || v4.is_multicast()       // 224/4
        || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xC0) == 64) // 100.64/10 (CGN)
        || (v4.octets()[0] & 0xf0) == 240 // 240/4 reserved, includes 255/8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserved_ranges_are_refused() {
        for addr in [
            "127.0.0.1",
            "169.254.169.254",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "0.0.0.0",
            "100.64.0.1",
            "255.255.255.255",
            "224.0.0.1",
            "240.0.0.1",
            "::1",
            "::",
            "fc00::1",
            "fe80::1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
        ] {
            assert!(
                is_private_ip(addr.parse().unwrap()),
                "{addr} must be refused"
            );
        }
    }

    #[test]
    fn public_addresses_are_reachable() {
        for addr in ["1.1.1.1", "93.184.216.34", "2606:4700:4700::1111"] {
            assert!(
                !is_private_ip(addr.parse().unwrap()),
                "{addr} must be reachable"
            );
        }
    }
}
