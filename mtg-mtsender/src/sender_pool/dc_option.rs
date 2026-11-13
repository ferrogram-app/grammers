// Copyright 2020 - developers of the `grammers` project.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

use mtg_session::types::DcOption;
use mtg_tl_types as tl;

/// Puts the address of `option` into `dc_option`; `false` if the address does not parse.
pub(super) fn merge_dc_option(dc_option: &mut DcOption, option: &tl::types::DcOption) -> bool {
    if option.ipv6 {
        let Ok(ip) = option.ip_address.parse::<Ipv6Addr>() else {
            return false;
        };
        dc_option.ipv6 = SocketAddrV6::new(ip, option.port as _, 0, 0);
    } else {
        let Ok(ip) = option.ip_address.parse::<Ipv4Addr>() else {
            return false;
        };
        dc_option.ipv4 = SocketAddrV4::new(ip, option.port as _);
        if dc_option.ipv6.ip().to_bits() == 0 {
            dc_option.ipv6 = SocketAddrV6::new(
                dc_option.ipv4.ip().to_ipv6_mapped(),
                dc_option.ipv4.port(),
                0,
                0,
            );
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tl_option(ipv6: bool, ip: &str, port: i32) -> tl::types::DcOption {
        tl::types::DcOption {
            ipv6,
            media_only: false,
            tcpo_only: false,
            cdn: false,
            r#static: true,
            this_port_only: false,
            id: 2,
            ip_address: ip.to_string(),
            port,
            secret: None,
        }
    }

    fn empty() -> DcOption {
        DcOption {
            id: 2,
            ipv4: SocketAddrV4::new(Ipv4Addr::from_bits(0), 0),
            ipv6: SocketAddrV6::new(Ipv6Addr::from_bits(0), 0, 0, 0),
            auth_key: None,
        }
    }

    #[test]
    fn ipv4_option_also_fills_a_missing_ipv6() {
        let mut dc = empty();
        assert!(merge_dc_option(
            &mut dc,
            &tl_option(false, "149.154.167.51", 443)
        ));
        assert_eq!(dc.ipv4, "149.154.167.51:443".parse().unwrap());
        assert_eq!(
            dc.ipv6.ip(),
            &Ipv4Addr::new(149, 154, 167, 51).to_ipv6_mapped()
        );
        assert_eq!(dc.ipv6.port(), 443);
    }

    #[test]
    fn ipv6_option_and_a_known_ipv6_is_kept() {
        let mut dc = empty();
        assert!(merge_dc_option(
            &mut dc,
            &tl_option(true, "2001:67c:4e8:f002::a", 443)
        ));
        assert_eq!(
            dc.ipv6.ip(),
            &"2001:67c:4e8:f002::a".parse::<Ipv6Addr>().unwrap()
        );
        // a later ipv4 option must not overwrite the real ipv6 address
        assert!(merge_dc_option(&mut dc, &tl_option(false, "1.2.3.4", 80)));
        assert_eq!(
            dc.ipv6.ip(),
            &"2001:67c:4e8:f002::a".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(dc.ipv4, "1.2.3.4:80".parse().unwrap());
    }

    #[test]
    fn unparsable_addresses_are_rejected_and_leave_the_option_alone() {
        let mut dc = empty();
        assert!(!merge_dc_option(
            &mut dc,
            &tl_option(false, "not an ip", 443)
        ));
        assert!(!merge_dc_option(&mut dc, &tl_option(true, "1.2.3.4", 443)));
        assert!(!merge_dc_option(&mut dc, &tl_option(false, "2001::1", 443)));
        assert_eq!(dc.ipv4.port(), 0);
        assert_eq!(dc.ipv6.port(), 0);
    }
}
