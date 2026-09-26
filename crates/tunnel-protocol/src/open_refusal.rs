//! The fixed set of OPEN refusals a connector sends as `REJECTED`.
//!
//! The connector sends only entries of this table (its refusal helpers take an
//! [`OpenRefusal`], not free text, and an `OpenRefusal` can be neither built
//! nor modified outside this module), and the relay logs a received refusal only
//! by looking it up here (task row M7-C160).  A refusal the table does not
//! contain did not come from the shipped connector, and the relay logs it as
//! `other` plus its length, never its text.

/// One refusal: the wire `code` and `reason`, and a stable, payload-free
/// `category` a relay may log in place of the reason.  The fields are private
/// and only this module constructs values, so code outside it can neither
/// build a refusal nor alter a copy of one: every refusal a connector sends
/// is one of the constants below, unchanged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OpenRefusal {
    code: &'static str,
    reason: &'static str,
    category: &'static str,
}

impl OpenRefusal {
    const fn new(code: &'static str, reason: &'static str, category: &'static str) -> Self {
        Self {
            code,
            reason,
            category,
        }
    }

    /// The wire `REJECTED.code`.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    /// The wire `REJECTED.reason`.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        self.reason
    }

    /// The payload-free category a relay logs in place of the reason.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        self.category
    }
}

pub const CONNECTOR_DRAINING: OpenRefusal =
    OpenRefusal::new("GOAWAY", "connector is draining", "connector_draining");
pub const STREAM_LIMIT: OpenRefusal =
    OpenRefusal::new("RESOURCE_EXHAUSTED", "stream limit reached", "stream_limit");
pub const OPEN_ADMISSION_FULL: OpenRefusal = OpenRefusal::new(
    "RESOURCE_EXHAUSTED",
    "bounded OPEN admission is full",
    "open_admission_full",
);
pub const OPEN_RETENTION_FULL: OpenRefusal = OpenRefusal::new(
    "RESOURCE_EXHAUSTED",
    "parsed OPEN retention is full; start a fresh session",
    "open_retention_full",
);
pub const OPEN_IDEMPOTENCY_FULL: OpenRefusal = OpenRefusal::new(
    "RESOURCE_EXHAUSTED",
    "OPEN idempotency retention is full; start a fresh session",
    "open_idempotency_full",
);
pub const EXPORT_NOT_ALLOWLISTED: OpenRefusal = OpenRefusal::new(
    "EXPORT_DENIED",
    "service is not locally allowlisted",
    "export_not_allowlisted",
);
/// M1 connector: only `echo`.
pub const ECHO_OPERATION_ONLY: OpenRefusal = OpenRefusal::new(
    "OPERATION_DENIED",
    "only the local echo operation is enabled",
    "operation_not_enabled",
);
/// M2 connector: an operation no export enables.
pub const OPERATION_NOT_ENABLED: OpenRefusal = OpenRefusal::new(
    "OPERATION_DENIED",
    "only the local echo operations are enabled",
    "operation_not_enabled",
);
pub const STREAM_ACTIVE: OpenRefusal = OpenRefusal::new(
    "STREAM_EXISTS",
    "stream ID is already active",
    "stream_active",
);
pub const STREAM_ACTIVE_OR_FORGOTTEN: OpenRefusal = OpenRefusal::new(
    "STREAM_EXISTS",
    "stream ID is already active or was already forgotten",
    "stream_active_or_forgotten",
);
pub const STREAM_FORGOTTEN: OpenRefusal = OpenRefusal::new(
    "STREAM_EXISTS",
    "stream ID was already forgotten; start a fresh session",
    "stream_forgotten",
);
pub const OPEN_FORGOTTEN: OpenRefusal = OpenRefusal::new(
    "STALE_REQUEST",
    "OPEN was already forgotten; start a fresh session",
    "open_forgotten",
);
pub const AUTHORIZATION_WINDOW_EXPIRED: OpenRefusal = OpenRefusal::new(
    "AUTHORIZATION_EXPIRED",
    "OPEN authorization window expired before admission",
    "authorization_window_expired",
);
/// M1 connector: a relay CANCEL of a local echo.
pub const ECHO_CANCELLED: OpenRefusal =
    OpenRefusal::new("CANCELLED", "local echo cancelled", "cancelled");

/// Every refusal a connector sends.
pub const ALL: &[OpenRefusal] = &[
    CONNECTOR_DRAINING,
    STREAM_LIMIT,
    OPEN_ADMISSION_FULL,
    OPEN_RETENTION_FULL,
    OPEN_IDEMPOTENCY_FULL,
    EXPORT_NOT_ALLOWLISTED,
    ECHO_OPERATION_ONLY,
    OPERATION_NOT_ENABLED,
    STREAM_ACTIVE,
    STREAM_ACTIVE_OR_FORGOTTEN,
    STREAM_FORGOTTEN,
    OPEN_FORGOTTEN,
    AUTHORIZATION_WINDOW_EXPIRED,
    ECHO_CANCELLED,
];

/// The table's code for `code`, if a connector sends it.
#[must_use]
pub fn known_code(code: &str) -> Option<&'static str> {
    ALL.iter()
        .map(|refusal| refusal.code)
        .find(|known| *known == code)
}

/// The category for exactly this `reason`, if a connector sends it.
#[must_use]
pub fn reason_category(reason: &str) -> Option<&'static str> {
    ALL.iter()
        .find(|refusal| refusal.reason == reason)
        .map(|refusal| refusal.category)
}

#[cfg(test)]
mod tests {
    use super::{ALL, known_code, reason_category};

    #[test]
    fn every_entry_round_trips_and_reasons_are_distinct() {
        for refusal in ALL {
            assert_eq!(known_code(refusal.code), Some(refusal.code));
            assert_eq!(reason_category(refusal.reason), Some(refusal.category));
            assert_eq!(
                ALL.iter()
                    .filter(|other| other.reason == refusal.reason)
                    .count(),
                1,
                "duplicate reason {:?}",
                refusal.reason
            );
        }
        // Every refusal constant is in `ALL`, or the relay would log a real
        // refusal as `other`.
        let source = include_str!("open_refusal.rs");
        let production = source.split("\n#[cfg(test)]\n").next().unwrap_or(source);
        assert_eq!(production.matches(": OpenRefusal =").count(), ALL.len());
        assert_eq!(known_code("goaway"), None);
        assert_eq!(reason_category("connector is draining\n"), None);
    }
}
