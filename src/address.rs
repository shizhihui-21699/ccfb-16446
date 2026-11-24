//! Canonical peer address representation used by validation tokens.
//!
//! Addresses are normalised so that an IPv4-mapped IPv6 address and the
//! corresponding IPv4 address compare equal.  Transports often observe the
//! same client as either form depending on the socket type; a token issued
//! for one form must be usable for the other.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::str::FromStr;

/// A peer's transport address, normalised for token binding.
///
/// Only `IP address + port` is part of the binding.  IPv6 scope identifiers
/// are deliberately ignored: they are link-local routing hints, not part of
/// the identity a server can validate across a cluster.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PeerAddress {
    ip: IpAddr,
    port: u16,
}

impl PeerAddress {
    /// Create a normalised address.
    pub fn new(ip: IpAddr, port: u16) -> Self {
        Self {
            ip: normalise_ip(ip),
            port,
        }
    }

    /// Create from a [`SocketAddr`].
    pub fn from_socket_addr(addr: SocketAddr) -> Self {
        Self::new(addr.ip(), addr.port())
    }

    /// Create an IPv4 address.
    pub fn v4(ip: Ipv4Addr, port: u16) -> Self {
        Self::new(IpAddr::V4(ip), port)
    }

    /// Create an IPv6 address.
    pub fn v6(ip: Ipv6Addr, port: u16) -> Self {
        Self::new(IpAddr::V6(ip), port)
    }

    /// Normalised IP address.
    pub fn ip(&self) -> IpAddr {
        self.ip
    }

    /// UDP port.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Convert to a standard [`SocketAddr`].  IPv6 scope id is always zero.
    pub fn to_socket_addr(&self) -> SocketAddr {
        match self.ip {
            IpAddr::V4(ip) => SocketAddr::V4(SocketAddrV4::new(ip, self.port)),
            IpAddr::V6(ip) => SocketAddr::V6(SocketAddrV6::new(ip, self.port, 0, 0)),
        }
    }

    pub(crate) fn write_to(&self, out: &mut Vec<u8>) {
        match self.ip {
            IpAddr::V4(ip) => {
                out.push(4);
                out.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                out.push(6);
                out.extend_from_slice(&ip.octets());
            }
        }
        out.extend_from_slice(&self.port.to_be_bytes());
    }

    pub(crate) fn read_from(buf: &[u8], cursor: &mut usize) -> Option<Self> {
        let family = *buf.get(*cursor)?;
        *cursor += 1;
        let ip = match family {
            4 => {
                let octets: [u8; 4] = buf.get(*cursor..*cursor + 4)?.try_into().ok()?;
                *cursor += 4;
                IpAddr::V4(Ipv4Addr::from(octets))
            }
            6 => {
                let octets: [u8; 16] = buf.get(*cursor..*cursor + 16)?.try_into().ok()?;
                *cursor += 16;
                IpAddr::V6(Ipv6Addr::from(octets))
            }
            _ => return None,
        };
        let port = u16::from_be_bytes(buf.get(*cursor..*cursor + 2)?.try_into().ok()?);
        *cursor += 2;
        Some(Self::new(ip, port))
    }
}

impl From<SocketAddr> for PeerAddress {
    fn from(value: SocketAddr) -> Self {
        Self::from_socket_addr(value)
    }
}

impl From<PeerAddress> for SocketAddr {
    fn from(value: PeerAddress) -> Self {
        value.to_socket_addr()
    }
}

impl From<(IpAddr, u16)> for PeerAddress {
    fn from((ip, port): (IpAddr, u16)) -> Self {
        Self::new(ip, port)
    }
}

impl FromStr for PeerAddress {
    type Err = std::net::AddrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        SocketAddr::from_str(s).map(Self::from_socket_addr)
    }
}

impl fmt::Display for PeerAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.ip {
            IpAddr::V4(ip) => write!(f, "{ip}:{}", self.port),
            IpAddr::V6(ip) => write!(f, "[{ip}]:{}", self.port),
        }
    }
}

impl fmt::Debug for PeerAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

fn normalise_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        IpAddr::V4(_) => ip,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalises_ipv4_mapped_addresses() {
        let mapped: Ipv6Addr = "::ffff:192.0.2.7".parse().unwrap();
        let a = PeerAddress::v6(mapped, 4433);
        let b = PeerAddress::v4("192.0.2.7".parse().unwrap(), 4433);
        assert_eq!(a, b);
        assert_eq!(a.ip(), IpAddr::V4("192.0.2.7".parse().unwrap()));
    }

    #[test]
    fn wire_roundtrip() {
        let addrs = [
            PeerAddress::v4(Ipv4Addr::new(127, 0, 0, 1), 1),
            PeerAddress::v6("2001:db8::1".parse().unwrap(), 65535),
        ];
        for addr in addrs {
            let mut out = Vec::new();
            addr.write_to(&mut out);
            let mut cursor = 0;
            assert_eq!(Some(addr), PeerAddress::read_from(&out, &mut cursor));
            assert_eq!(cursor, out.len());
        }
    }

    #[test]
    fn rejects_truncated_wire_address() {
        let mut out = Vec::new();
        PeerAddress::v6("2001:db8::1".parse().unwrap(), 53).write_to(&mut out);
        for len in 0..out.len() {
            let mut cursor = 0;
            assert_eq!(None, PeerAddress::read_from(&out[..len], &mut cursor));
        }
    }
}
