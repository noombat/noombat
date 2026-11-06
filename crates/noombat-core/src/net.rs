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
/// documentation, benchmarking, multicast, broadcast and the reserved
/// IPv4 ranges; for IPv6, loopback, unspecified, unique-local,
/// link-local, site-local, multicast, local-use NAT64, and the mapped,
/// compatible, NAT64 (64:ff9b::/96) and 6to4 forms of a refused IPv4
/// address. Teredo and IPv4-translated forms are not decoded.
pub fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_private_v4(v4),
        IpAddr::V6(v6) => {
            let s = v6.segments();
            let low = Ipv4Addr::new((s[6] >> 8) as u8, s[6] as u8, (s[7] >> 8) as u8, s[7] as u8);
            v6.is_loopback()                              // ::1
                || v6.is_unspecified()                    // ::
                || (s[0] & 0xfe00) == 0xfc00              // fc00::/7 (ULA)
                || (s[0] & 0xffc0) == 0xfe80              // fe80::/10 (link-local)
                || (s[0] & 0xffc0) == 0xfec0              // fec0::/10 (site-local)
                || (s[0] & 0xff00) == 0xff00              // ff00::/8 (multicast)
                || v6.to_ipv4_mapped().is_some_and(is_private_v4) // ::ffff:a.b.c.d
                || (s[..6] == [0; 6] && is_private_v4(low)) // ::a.b.c.d (compatible)
                || (s[..6] == [0x64, 0xff9b, 0, 0, 0, 0] && is_private_v4(low)) // NAT64
                || s[..3] == [0x64, 0xff9b, 1]            // 64:ff9b:1::/48 (local NAT64)
                || (s[0] == 0x2002                        // 2002::/16 (6to4)
                    && is_private_v4(Ipv4Addr::new(
                        (s[1] >> 8) as u8,
                        s[1] as u8,
                        (s[2] >> 8) as u8,
                        s[2] as u8,
                    )))
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
        || v4.octets()[0] == 0     // 0/8, "this network"
        || v4.is_documentation()   // 192.0.2/24, 198.51.100/24, 203.0.113/24
        || (v4.octets()[..3] == [192, 0, 0])                          // 192.0.0/24
        || (v4.octets()[0] == 198 && (v4.octets()[1] & 0xfe) == 18)  // 198.18/15
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
            "0.1.2.3",
            "192.0.0.8",
            "198.18.0.1",
            "198.19.255.255",
            "::7f00:1",
            "64:ff9b::a9fe:a9fe",
            "64:ff9b:1::1",
            "2002:a9fe:a9fe::",
            "fec0::1",
            "ff02::1",
        ] {
            assert!(
                is_private_ip(addr.parse().unwrap()),
                "{addr} must be refused"
            );
        }
    }

    #[test]
    fn public_addresses_are_reachable() {
        for addr in [
            "1.1.1.1",
            "93.184.216.34",
            "198.17.0.1",
            "198.20.0.1",
            "2606:4700:4700::1111",
            "64:ff9b::101:101",
            "2002:101:101::",
        ] {
            assert!(
                !is_private_ip(addr.parse().unwrap()),
                "{addr} must be reachable"
            );
        }
    }
}
