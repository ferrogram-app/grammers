// Copyright 2020 - developers of the `grammers` project.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

mod tcp;

pub use tcp::NetStream;

/// Represents a socket address which may be proxied.
#[derive(Debug, Clone)]
pub enum ServerAddr {
    /// Socket address whose connection should be proxied.
    #[cfg(feature = "proxy")]
    Proxied {
        /// The server to reach through the proxy.
        address: std::net::SocketAddr,
        /// The proxy URL (`socks5://[user:password@]host:port`).
        proxy: String,
    },
    /// Proxy address for direct connection.
    Tcp {
        /// The server to connect to.
        address: std::net::SocketAddr,
    },
}
