//! The `computer.v1` operation allowlist, and what each operation maps to
//! upstream.
//!
//! **Fail closed.** [`Operation::parse`] returns `None` for anything that is
//! not one of this chunk's four read-only names. There is no prefix rule, no
//! case folding, no trimming and no pass-through: a name this table does not
//! carry is never forwarded to a backend, so a backend command that our policy
//! has not reasoned about cannot be reached by spelling it in a request.
//!
//! **Deferral is not the same answer as refusal.** The input operations are a
//! later chunk's work, not a typo, so [`refusal`] distinguishes them. A caller
//! that sends `click` today learns that the operation exists and is not
//! carried yet; a caller that sends `clcik` learns the name is unknown. The
//! two lead to the same outcome — nothing is dispatched — and that is the
//! point: the distinction is diagnostic, never a widening.

/// One read-only `computer.v1` operation.
///
/// The variants are exactly the read-only subset of
/// `docs/integrations.md`'s operation table. Adding a variant here is a
/// deliberate act that `tests/host_untouched.rs` and
/// `crates/tunnel-http-forward/tests/cua_pin.rs` both have opinions about.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Operation {
    /// Local configuration plus the upstream `version` and `/commands`
    /// readings plus an explicit backend probe. Reads nothing from a screen.
    Describe,
    /// One bounded screen capture with its dimensions and capture identity.
    Capture,
    /// Screen geometry.
    ScreenInfo,
    /// Pointer position. Reads the cursor; it never moves it.
    CursorPosition,
}

impl Operation {
    /// Every operation this chunk carries, in the order
    /// `docs/integrations.md` introduces them.
    pub const ALL: [Self; 4] = [
        Self::Describe,
        Self::Capture,
        Self::ScreenInfo,
        Self::CursorPosition,
    ];

    /// The name as it appears in a `computer.v1` request.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Describe => "describe",
            Self::Capture => "capture",
            Self::ScreenInfo => "screen_info",
            Self::CursorPosition => "cursor_position",
        }
    }

    /// Exact match against [`Operation::ALL`], or `None`.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|operation| operation.name() == name)
    }

    /// The canonical `cua-computer-server` command this operation dispatches.
    ///
    /// `None` for [`Operation::Describe`], which is not a single command: it
    /// is local configuration intersected with the `/commands` reading and a
    /// probe. Modelling it as a command would be the config-echo trap wearing
    /// a mapping table.
    ///
    /// Canonical names only. The released server carries twelve aliases
    /// (`click` for `left_click`, `type` for `type_text`, and so on) and
    /// **trims the alias map when a backend narrows the registry**, so an
    /// adapter that sent an alias would work on one backend and fail on
    /// another. See `tunnel_http_forward::cua_pin::ALIASES_NOT_TO_RELY_ON`.
    #[must_use]
    pub const fn upstream_command(self) -> Option<&'static str> {
        match self {
            Self::Describe => None,
            Self::Capture => Some("screenshot"),
            Self::ScreenInfo => Some("get_screen_size"),
            Self::CursorPosition => Some("get_cursor_position"),
        }
    }

    /// The commands [`Operation::Describe`] reads, none of which acts.
    pub const DESCRIBE_READS: &'static [&'static str] = &["version"];

    /// Whether this operation can change anything on the target machine.
    ///
    /// Constantly `false` for every variant in this chunk, and it is a method
    /// rather than a blanket `false` so that chunk 3's input operations have
    /// somewhere to be `true` — and so that a reviewer adding one has to
    /// answer the question rather than inherit an answer.
    #[must_use]
    pub const fn mutates_target(self) -> bool {
        match self {
            Self::Describe | Self::Capture | Self::ScreenInfo | Self::CursorPosition => false,
        }
    }
}

/// Why an operation name was not accepted.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Refusal {
    /// A `computer.v1` operation that exists in the table but is not carried
    /// by this chunk. Nothing is dispatched.
    Deferred(Deferral),
    /// Not a `computer.v1` operation name at all. Nothing is dispatched.
    Unknown,
}

/// The reason a named operation is deferred, and to what.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Deferral {
    /// Synthesises keyboard or pointer input. Deferred to chunk 3 together
    /// with the exclusive input lease, because the double-dispatch question
    /// ("was the click delivered once, twice, or not at all?") cannot be
    /// answered without the lease and the capture-identity carry-forward.
    SynthesisesInput,
    /// Reads structured UI state rather than pixels. Deferred because
    /// `docs/integrations.md` admits it "only when backed by real supported
    /// data", and no backend has been probed for that yet (M5-C02).
    NeedsBackendProbe,
}

/// `computer.v1` operation names that exist in `docs/integrations.md`'s table
/// and are deliberately not carried by chunk 2.
///
/// Recorded by name so a deferral cannot quietly become an omission, and so
/// the guard case for "input operations are not reachable from this chunk" has
/// something concrete to assert against.
pub const DEFERRED_OPERATIONS: &[(&str, Deferral)] = &[
    ("click", Deferral::SynthesisesInput),
    ("double_click", Deferral::SynthesisesInput),
    ("move", Deferral::SynthesisesInput),
    ("drag", Deferral::SynthesisesInput),
    ("scroll", Deferral::SynthesisesInput),
    ("type_text", Deferral::SynthesisesInput),
    ("press_key", Deferral::SynthesisesInput),
    ("hotkey", Deferral::SynthesisesInput),
    ("accessibility_tree", Deferral::NeedsBackendProbe),
];

/// Classify a name this chunk did not accept.
///
/// Only meaningful once [`Operation::parse`] has already returned `None`; it
/// exists to turn that `None` into a diagnostic, never into an admission.
#[must_use]
pub fn refusal(name: &str) -> Refusal {
    DEFERRED_OPERATIONS
        .iter()
        .find(|(deferred, _)| *deferred == name)
        .map_or(Refusal::Unknown, |(_, reason)| Refusal::Deferred(*reason))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_operation_round_trips_through_its_name_and_the_names_are_distinct() {
        let mut names: Vec<&str> = Operation::ALL.iter().map(|op| op.name()).collect();
        let before = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(before, names.len(), "two operations share a name");
        for operation in Operation::ALL {
            assert_eq!(Operation::parse(operation.name()), Some(operation));
        }
    }

    /// The fail-closed rule itself, and the shapes a permissive parser would
    /// have let through.
    #[test]
    fn an_unknown_name_is_refused_with_no_folding_trimming_or_prefixing() {
        for rejected in [
            "",
            " capture",
            "capture ",
            "Capture",
            "CAPTURE",
            "capture\n",
            "captures",
            "capture.v1",
            "screenshot",
            "run_command",
            "../capture",
        ] {
            assert_eq!(
                Operation::parse(rejected),
                None,
                "{rejected:?} must not parse as an operation"
            );
        }
    }

    /// **This is the guard case for "no input operation is reachable from
    /// chunk 2".** It reddens if a variant that synthesises input is added to
    /// [`Operation::ALL`], and it reddens if the deferral table is emptied.
    #[test]
    fn no_deferred_operation_parses_and_every_carried_operation_is_read_only() {
        assert!(
            DEFERRED_OPERATIONS.len() >= 9,
            "the deferral table was truncated; it must keep naming what chunk 3 owes"
        );
        for (name, _) in DEFERRED_OPERATIONS {
            assert_eq!(
                Operation::parse(name),
                None,
                "{name} is deferred and must not parse in this chunk"
            );
            assert!(matches!(refusal(name), Refusal::Deferred(_)));
        }
        for operation in Operation::ALL {
            assert!(
                !operation.mutates_target(),
                "{} mutates the target and cannot be in a read-only chunk",
                operation.name()
            );
        }
        // Non-vacuity: a typo is refused differently from a deferral, so the
        // assertion above is reading the table rather than a blanket refusal.
        assert_eq!(refusal("clcik"), Refusal::Unknown);
        assert_eq!(
            refusal("click"),
            Refusal::Deferred(Deferral::SynthesisesInput)
        );
    }

    /// Every dispatching operation maps to a command the pin actually
    /// allowlists, and `describe` deliberately maps to none.
    #[test]
    fn upstream_commands_are_allowlisted_by_the_pin_and_describe_is_not_a_command() {
        use tunnel_http_forward::cua_pin::ALLOWED_COMMANDS;

        assert_eq!(Operation::Describe.upstream_command(), None);
        for operation in Operation::ALL {
            let Some(command) = operation.upstream_command() else {
                continue;
            };
            assert!(
                ALLOWED_COMMANDS.contains(&command),
                "{} dispatches {command}, which the M5-01 pin does not allowlist",
                operation.name()
            );
        }
        for command in Operation::DESCRIBE_READS {
            assert!(
                ALLOWED_COMMANDS.contains(command),
                "describe reads {command}, which the M5-01 pin does not allowlist"
            );
        }
    }

    /// A deferred operation must not be *silently* absent from the pin's
    /// allowlist either — chunk 3 has to find the command names waiting for it.
    #[test]
    fn every_input_deferral_names_a_command_the_pin_already_knows_about() {
        use tunnel_http_forward::cua_pin::{ALIASES_NOT_TO_RELY_ON, ALLOWED_COMMANDS};

        for (name, reason) in DEFERRED_OPERATIONS {
            if *reason != Deferral::SynthesisesInput {
                continue;
            }
            let known = ALLOWED_COMMANDS.contains(name)
                || ALIASES_NOT_TO_RELY_ON
                    .iter()
                    .any(|(alias, _)| alias == name)
                // `move` and `double_click` are the profile's spellings of
                // `move_cursor` and `double_click`; the table in
                // `docs/integrations.md` maps them.
                || matches!(*name, "move" | "click");
            assert!(
                known,
                "deferred input operation {name} maps to no pinned command"
            );
        }
    }
}
