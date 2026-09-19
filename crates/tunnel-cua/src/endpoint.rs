//! The backend endpoint policy: **loopback only**, checked before dispatch.
//!
//! This is the second of the four proofs `<scratchpad>/m5-scoping-and-decisions.md`
//! names that together show the host was untouched. On its own it shows very
//! little — a loopback address on this machine is still *this machine* — and
//! `docs/integrations.md` is blunt about the rest: local-mode computer-server
//! requires **no authentication** when `CONTAINER_NAME` is absent, so loopback
//! binding plus device configuration is **not confinement**. The honest label
//! is **trusted-local backend**: authorization is enforced by the device on the
//! tunnel path only, and any local process can drive the backend directly with
//! no tunnel authorization at all.
//!
//! What the check does buy is that a misconfiguration cannot point this
//! profile at somebody else's machine, and that the address it refuses is
//! refused by a rule with a test, not by a comment.
//!
//! **Never forward relay tokens into CUA, and never advertise upstream cloud
//! auth (`X-API-Key`) as local protection.** Neither is expressible here:
//! [`BackendEndpoint`] carries an address and nothing else.

use std::net::{IpAddr, SocketAddr};

/// A backend endpoint that has passed the loopback check.
///
/// Constructible only through [`BackendEndpoint::new`] or
/// [`BackendEndpoint::from_resolved`], so a value of this type is the evidence
/// that the check ran.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BackendEndpoint {
    address: SocketAddr,
}

/// Why an address may not be used as a CUA backend endpoint.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum EndpointError {
    /// The address is routable off this machine. The refusal that matters.
    NotLoopback,
    /// `0.0.0.0` or `::`. Not loopback, and named separately because it is the
    /// single most common way a configuration means "everywhere" and reads as
    /// "here".
    Unspecified,
    /// Port 0. A backend that has not been bound yet cannot be dispatched to,
    /// and a 0 here is usually a half-initialised configuration.
    ZeroPort,
    /// A hostname resolved to nothing.
    NoAddresses,
}

impl core::fmt::Display for EndpointError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::NotLoopback => "a CUA backend endpoint must be a loopback address",
            Self::Unspecified => "a CUA backend endpoint must not be the unspecified address",
            Self::ZeroPort => "a CUA backend endpoint must name a bound port",
            Self::NoAddresses => "the configured CUA backend host resolved to no addresses",
        })
    }
}

impl std::error::Error for EndpointError {}

impl BackendEndpoint {
    /// Accept `address` only if it is loopback with a bound port.
    ///
    /// IPv4-mapped IPv6 addresses are **canonicalized first**. This is the
    /// case a naive check gets wrong in both directions: `Ipv6Addr::is_loopback`
    /// is true only for `::1`, so `::ffff:127.0.0.1` would be refused (merely
    /// annoying) and — far worse for a different check written the obvious way
    /// — a mapped public address like `::ffff:93.184.216.34` is not `::1` and
    /// is not `127.0.0.0/8` either, so anything comparing against literals
    /// would have to enumerate both forms. Canonicalizing means one rule.
    ///
    /// # Errors
    /// Any [`EndpointError`].
    pub fn new(address: SocketAddr) -> Result<Self, EndpointError> {
        if address.port() == 0 {
            return Err(EndpointError::ZeroPort);
        }
        let ip = canonical(address.ip());
        if ip.is_unspecified() {
            return Err(EndpointError::Unspecified);
        }
        if !ip.is_loopback() {
            return Err(EndpointError::NotLoopback);
        }
        Ok(Self { address })
    }

    /// Accept a resolved hostname only if **every** address it resolved to
    /// passes [`BackendEndpoint::new`].
    ///
    /// Any-of would be the wrong quantifier: a name that resolves to both
    /// `127.0.0.1` and a routable address is a name an attacker with write
    /// access to `/etc/hosts`, or a DNS answer, can steer. All-of, plus a
    /// refusal for the empty set, is the only reading that cannot be steered.
    ///
    /// # Errors
    /// Any [`EndpointError`], including [`EndpointError::NoAddresses`].
    pub fn from_resolved(addresses: &[SocketAddr]) -> Result<Self, EndpointError> {
        let (first, rest) = addresses.split_first().ok_or(EndpointError::NoAddresses)?;
        let endpoint = Self::new(*first)?;
        for address in rest {
            Self::new(*address)?;
        }
        Ok(endpoint)
    }

    #[must_use]
    pub const fn address(&self) -> SocketAddr {
        self.address
    }
}

/// Unwrap an IPv4-mapped IPv6 address to its IPv4 form; leave everything else
/// alone.
fn canonical(ip: IpAddr) -> IpAddr {
    ip.to_canonical()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn v4(a: u8, b: u8, c: u8, d: u8, port: u16) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::new(a, b, c, d), port))
    }

    #[test]
    fn loopback_addresses_with_a_bound_port_are_accepted() {
        for address in [
            v4(127, 0, 0, 1, 1),
            v4(127, 0, 0, 1, 63_790),
            // The whole 127.0.0.0/8 block is loopback, not just .0.1.
            v4(127, 1, 2, 3, 8080),
            SocketAddr::from((Ipv6Addr::LOCALHOST, 8080)),
            // IPv4-mapped loopback: accepted because it is canonicalized.
            SocketAddr::from((Ipv4Addr::LOCALHOST.to_ipv6_mapped(), 8080)),
        ] {
            assert!(
                BackendEndpoint::new(address).is_ok(),
                "{address} should be accepted"
            );
        }
    }

    /// **The guard case.** Delete the `is_loopback` refusal in
    /// [`BackendEndpoint::new`] and this reddens; that is what
    /// `scripts/m5-guard-deletion.py` measures.
    #[test]
    fn non_loopback_targets_are_refused() {
        for address in [
            v4(93, 184, 216, 34, 80),
            v4(10, 0, 0, 5, 8080),
            v4(192, 168, 1, 10, 8080),
            v4(169, 254, 169, 254, 80),
            // Link-local and public IPv6.
            SocketAddr::from((Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1), 8080)),
            SocketAddr::from((Ipv6Addr::new(0x2606, 0x2800, 0, 0, 0, 0, 0, 1), 8080)),
            // The trap: a mapped **public** address. `::1` it is not, and
            // `127.0.0.0/8` it is not either, so a check that compared against
            // literals in either family would have to remember both forms.
            SocketAddr::from((Ipv4Addr::new(93, 184, 216, 34).to_ipv6_mapped(), 80)),
        ] {
            assert_eq!(
                BackendEndpoint::new(address),
                Err(EndpointError::NotLoopback),
                "{address} must be refused as non-loopback"
            );
        }
    }

    #[test]
    fn the_unspecified_address_and_a_zero_port_are_refused_by_name() {
        assert_eq!(
            BackendEndpoint::new(v4(0, 0, 0, 0, 8080)),
            Err(EndpointError::Unspecified)
        );
        assert_eq!(
            BackendEndpoint::new(SocketAddr::from((Ipv6Addr::UNSPECIFIED, 8080))),
            Err(EndpointError::Unspecified)
        );
        assert_eq!(
            BackendEndpoint::new(v4(127, 0, 0, 1, 0)),
            Err(EndpointError::ZeroPort)
        );
    }

    /// The quantifier, which is the part a reviewer should distrust most.
    #[test]
    fn a_resolution_is_accepted_only_when_every_address_is_loopback() {
        assert!(
            BackendEndpoint::from_resolved(&[
                v4(127, 0, 0, 1, 8080),
                SocketAddr::from((Ipv6Addr::LOCALHOST, 8080)),
            ])
            .is_ok()
        );
        assert_eq!(
            BackendEndpoint::from_resolved(&[]),
            Err(EndpointError::NoAddresses)
        );
        // The steerable case: loopback first, routable second. An `any`
        // quantifier would accept this.
        assert_eq!(
            BackendEndpoint::from_resolved(&[v4(127, 0, 0, 1, 8080), v4(93, 184, 216, 34, 8080)]),
            Err(EndpointError::NotLoopback)
        );
        // And the same list the other way round, so the test is not merely
        // observing that the first element decides.
        assert_eq!(
            BackendEndpoint::from_resolved(&[v4(93, 184, 216, 34, 8080), v4(127, 0, 0, 1, 8080)]),
            Err(EndpointError::NotLoopback)
        );
    }
}
