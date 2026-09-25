//! The `computer.v1` operation allowlist, and what each operation maps to
//! upstream.
//!
//! **Fail closed.** [`Operation::parse`] returns `None` for anything that is
//! not one of the twelve names in this table. There is no prefix rule, no case
//! folding, no trimming and no pass-through: a name this table does not carry
//! is never forwarded to a backend, so a backend command that our policy has
//! not reasoned about cannot be reached by spelling it in a request.
//!
//! **Deferral is not the same answer as refusal.** `accessibility_tree` exists
//! in `docs/integrations.md`'s table and is not carried, so [`refusal`]
//! distinguishes it. A caller that sends it learns that the operation exists
//! and is not carried yet; a caller that sends `clcik` learns the name is
//! unknown. The two lead to the same outcome -- nothing is dispatched -- and
//! that is the point: the distinction is diagnostic, never a widening.
//!
//! # Chunk 3 added the input half, and [`Operation::mutates_target`] is where
//! that shows
//!
//! Eight of the twelve synthesise keyboard or pointer input. They carry three
//! obligations the read-only eight do not, all enforced in [`crate::plan`]:
//! the exclusive input lease ([`crate::lease`]), the capture-identity
//! carry-forward for anything with coordinates ([`crate::capture`]), and the
//! narrower retry rule ([`crate::outcome::Dispatch::retry_is_safe_for`]).
//! `mutates_target` is the single predicate all three read, so an operation
//! added without answering that question inherits nothing.

/// One `computer.v1` operation.
///
/// The variants are exactly `docs/integrations.md`'s operation table, less
/// `accessibility_tree`. Adding a variant here is a deliberate act that
/// `tests/host_untouched.rs` and `crates/tunnel-http-forward/tests/cua_pin.rs`
/// both have opinions about.
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
    /// One pointer click at a capture coordinate. The button selects the
    /// upstream command; see [`Button`].
    Click,
    /// Two clicks the backend delivers as one gesture. **One dispatch, two
    /// click effects** -- which is why a click counter that counts dispatches
    /// reads 1 here and is wrong.
    DoubleClick,
    /// Move the pointer without pressing anything.
    Move,
    /// Press at one capture coordinate, move, release at another.
    Drag,
    /// Scroll by a bounded wheel delta, at the cursor. **No position**: no
    /// pinned backend can express one (M5-C13).
    Scroll,
    /// Type a string. **Never logged, anywhere.** See
    /// [`crate::schema::Keystrokes`].
    TypeText,
    /// Press one named key.
    PressKey,
    /// Press a chord of named keys.
    Hotkey,
}

impl Operation {
    /// Every operation this chunk carries, in the order
    /// `docs/integrations.md` introduces them.
    pub const ALL: [Self; 12] = [
        Self::Describe,
        Self::Capture,
        Self::ScreenInfo,
        Self::CursorPosition,
        Self::Click,
        Self::DoubleClick,
        Self::Move,
        Self::Drag,
        Self::Scroll,
        Self::TypeText,
        Self::PressKey,
        Self::Hotkey,
    ];

    /// The four that read and never act.
    pub const READ_ONLY: [Self; 4] = [
        Self::Describe,
        Self::Capture,
        Self::ScreenInfo,
        Self::CursorPosition,
    ];

    /// The eight that synthesise keyboard or pointer input.
    pub const INPUT: [Self; 8] = [
        Self::Click,
        Self::DoubleClick,
        Self::Move,
        Self::Drag,
        Self::Scroll,
        Self::TypeText,
        Self::PressKey,
        Self::Hotkey,
    ];

    /// The name as it appears in a `computer.v1` request.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Describe => "describe",
            Self::Capture => "capture",
            Self::ScreenInfo => "screen_info",
            Self::CursorPosition => "cursor_position",
            Self::Click => "click",
            Self::DoubleClick => "double_click",
            Self::Move => "move",
            Self::Drag => "drag",
            Self::Scroll => "scroll",
            Self::TypeText => "type_text",
            Self::PressKey => "press_key",
            Self::Hotkey => "hotkey",
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
            // **Not the whole answer for `click`.** The upstream command
            // depends on the button, and [`Button::upstream_command`] is
            // authoritative; this returns the default button's command so that
            // `upstream_command` keeps meaning "a command this operation can
            // dispatch". [`crate::plan::plan`] resolves the real one from the
            // validated parameters, and a test pins the two together.
            Self::Click => Some(Button::DEFAULT.upstream_command()),
            Self::DoubleClick => Some("double_click"),
            Self::Move => Some("move_cursor"),
            Self::Drag => Some("drag"),
            Self::Scroll => Some("scroll"),
            Self::TypeText => Some("type_text"),
            Self::PressKey => Some("press_key"),
            Self::Hotkey => Some("hotkey"),
        }
    }

    /// The commands [`Operation::Describe`] reads, none of which acts.
    pub const DESCRIBE_READS: &'static [&'static str] = &["version"];

    /// Whether this operation can change anything on the target machine.
    ///
    /// **Three rules read this one predicate**, so it is the single place an
    /// operation is classified rather than three places that could disagree:
    /// the exclusive input lease is required exactly when it is true
    /// ([`crate::plan::plan`]); a dispatched operation is non-retryable
    /// exactly when it is true
    /// ([`crate::outcome::Dispatch::retry_is_safe_for`]); and a `failed`
    /// response is rendered non-retryable on the wire exactly when it is true
    /// ([`crate::schema::Response::failed`]).
    ///
    /// An exhaustive `match` rather than a set-membership test, so a reviewer
    /// adding a variant has to answer the question rather than inherit an
    /// answer.
    #[must_use]
    pub const fn mutates_target(self) -> bool {
        match self {
            Self::Describe | Self::Capture | Self::ScreenInfo | Self::CursorPosition => false,
            Self::Click
            | Self::DoubleClick
            | Self::Move
            | Self::Drag
            | Self::Scroll
            | Self::TypeText
            | Self::PressKey
            | Self::Hotkey => true,
        }
    }

    /// Whether this operation names coordinates, and therefore must carry a
    /// capture identity.
    ///
    /// The keyboard operations do not: there is no coordinate to be stale
    /// about. They still require the lease — interleaved typing is exactly
    /// what the lease exists to prevent — which is why this is a second
    /// predicate rather than a synonym for [`Operation::mutates_target`].
    #[must_use]
    pub const fn needs_capture_identity(self) -> bool {
        match self {
            Self::Click | Self::DoubleClick | Self::Move | Self::Drag => true,
            // `scroll` takes wheel amounts only since M5-C13: the pinned
            // backends scroll at the cursor, so there is no coordinate here
            // to be stale about. It still mutates, and still needs the lease.
            Self::Scroll
            | Self::Describe
            | Self::Capture
            | Self::ScreenInfo
            | Self::CursorPosition
            | Self::TypeText
            | Self::PressKey
            | Self::Hotkey => false,
        }
    }
}

/// Which pointer button an [`Operation::Click`] presses.
///
/// Two buttons, because the fixture and
/// [`tunnel_http_forward::cua_pin::ALLOWED_COMMANDS`] carry `left_click` and
/// `right_click` and nothing else. A middle button is not deferred-with-a-plan;
/// it is simply not a command the pinned server registers, so it fails closed
/// like any other unknown name.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Button {
    /// The default when `params` does not name one.
    #[default]
    Left,
    Right,
}

impl Button {
    pub const ALL: [Self; 2] = [Self::Left, Self::Right];

    /// The button used when `params` does not name one.
    pub const DEFAULT: Self = Self::Left;

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Left => "left",
            Self::Right => "right",
        }
    }

    /// Exact match, or `None`. Same fail-closed rule as
    /// [`Operation::parse`]: no folding, no trimming.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|button| button.name() == name)
    }

    /// The canonical command this button dispatches. **Authoritative**, unlike
    /// [`Operation::upstream_command`] for [`Operation::Click`].
    #[must_use]
    pub const fn upstream_command(self) -> &'static str {
        match self {
            Self::Left => "left_click",
            Self::Right => "right_click",
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
    /// Reads structured UI state rather than pixels. Deferred because
    /// `docs/integrations.md` admits it "only when backed by real supported
    /// data", and no backend has been probed for that yet (M5-C02).
    NeedsBackendProbe,
}

/// `computer.v1` operation names that exist in `docs/integrations.md`'s table
/// and are deliberately not carried.
///
/// **Chunk 3 emptied this of its eight input names by carrying them**, which
/// is why [`DEFERRED_OPERATIONS`] is now one entry rather than nine. The
/// guard against that being an *omission* rather than a promotion is
/// `every_operation_in_the_documented_table_is_carried_or_deferred`, which
/// reads the nine names from the document's table and requires each to be one
/// or the other.
///
/// Recorded by name so a deferral cannot quietly become an omission, and so
/// the guard case for "input operations are not reachable from this chunk" has
/// something concrete to assert against.
pub const DEFERRED_OPERATIONS: &[(&str, Deferral)] =
    &[("accessibility_tree", Deferral::NeedsBackendProbe)];

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
    /// have let through. `Click` is spelled out among them because it is now
    /// carried: its *misspellings* must still fail closed.
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
            " click",
            "Click",
            "click ",
            "clicks",
            "left_click",
            "tap",
            "type",
            "key",
            "middle_click",
        ] {
            assert_eq!(
                Operation::parse(rejected),
                None,
                "{rejected:?} must not parse as an operation"
            );
        }
    }

    /// The deferral table still refuses what it names, and a typo is still
    /// refused differently.
    #[test]
    fn no_deferred_operation_parses_and_a_typo_is_refused_differently() {
        assert!(
            !DEFERRED_OPERATIONS.is_empty(),
            "the deferral table was emptied; it must keep naming what is owed"
        );
        for (name, _) in DEFERRED_OPERATIONS {
            assert_eq!(
                Operation::parse(name),
                None,
                "{name} is deferred and must not parse"
            );
            assert!(matches!(refusal(name), Refusal::Deferred(_)));
        }
        assert_eq!(refusal("clcik"), Refusal::Unknown);
        assert_eq!(
            refusal("accessibility_tree"),
            Refusal::Deferred(Deferral::NeedsBackendProbe)
        );
    }

    /// **The guard against a deferral becoming an omission.**
    ///
    /// Chunk 3 promoted eight names out of [`DEFERRED_OPERATIONS`] by carrying
    /// them. Nothing in the shrunken table shows that they were promoted
    /// rather than dropped, so this reads the nine names `docs/integrations.md`
    /// lists and requires each to be carried *or* deferred. Deleting an
    /// operation without deferring it reddens here.
    #[test]
    fn every_operation_in_the_documented_table_is_carried_or_deferred() {
        const DOCUMENTED: &[&str] = &[
            "describe",
            "capture",
            "screen_info",
            "cursor_position",
            "click",
            "double_click",
            "move",
            "drag",
            "scroll",
            "type_text",
            "press_key",
            "hotkey",
            "accessibility_tree",
        ];
        for name in DOCUMENTED {
            let carried = Operation::parse(name).is_some();
            let deferred = matches!(refusal(name), Refusal::Deferred(_));
            assert!(
                carried ^ deferred,
                "{name} is in the documented table but is neither carried nor deferred \
                 (carried={carried}, deferred={deferred})"
            );
        }
        // And the split is the one this chunk claims: twelve carried, one
        // deferred, thirteen documented.
        assert_eq!(Operation::ALL.len(), 12);
        assert_eq!(DEFERRED_OPERATIONS.len(), 1);
        assert_eq!(DOCUMENTED.len(), 13);
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
        // Both buttons too, since `upstream_command` only names the default.
        for button in Button::ALL {
            assert!(
                ALLOWED_COMMANDS.contains(&button.upstream_command()),
                "{} dispatches {}, which the pin does not allowlist",
                button.name(),
                button.upstream_command()
            );
        }
    }

    /// **The canonical-name rule, now that input operations are carried.**
    ///
    /// The released server accepts `click`, `tap`, `type` and `key` as aliases
    /// and trims the alias map when a backend narrows the registry, so an
    /// adapter that sent an alias would work on one backend and fail on
    /// another. Our operation *names* deliberately include `click` and
    /// `type_text`; what must never be an alias is the **command** they
    /// dispatch.
    #[test]
    fn no_operation_dispatches_an_alias_even_when_its_own_name_is_one() {
        use tunnel_http_forward::cua_pin::ALIASES_NOT_TO_RELY_ON;

        let aliases: Vec<&str> = ALIASES_NOT_TO_RELY_ON
            .iter()
            .map(|(alias, _)| *alias)
            .collect();
        for operation in Operation::ALL {
            if let Some(command) = operation.upstream_command() {
                assert!(
                    !aliases.contains(&command),
                    "{} dispatches the alias {command}",
                    operation.name()
                );
            }
        }
        for button in Button::ALL {
            assert!(!aliases.contains(&button.upstream_command()));
        }
        // Non-vacuity: `click` -- an operation name we do carry -- really is
        // one of the aliases, so the loop above is discriminating.
        assert!(aliases.contains(&"click"));
        assert_eq!(Operation::Click.upstream_command(), Some("left_click"));
    }

    /// The two predicates every input rule reads, asserted against the two
    /// published subsets so they cannot drift apart.
    #[test]
    fn the_read_only_and_input_subsets_agree_with_mutates_target() {
        for operation in Operation::READ_ONLY {
            assert!(!operation.mutates_target(), "{}", operation.name());
            assert!(!operation.needs_capture_identity(), "{}", operation.name());
        }
        for operation in Operation::INPUT {
            assert!(operation.mutates_target(), "{}", operation.name());
        }
        assert_eq!(
            Operation::READ_ONLY.len() + Operation::INPUT.len(),
            Operation::ALL.len(),
            "an operation is in neither subset, or in both"
        );
        for operation in Operation::ALL {
            assert_eq!(
                operation.mutates_target(),
                Operation::INPUT.contains(&operation),
                "{} disagrees with the INPUT subset",
                operation.name()
            );
            // A coordinate operation always mutates; the converse is false,
            // and that asymmetry is the point of two predicates.
            if operation.needs_capture_identity() {
                assert!(operation.mutates_target(), "{}", operation.name());
            }
        }
        assert!(Operation::TypeText.mutates_target());
        assert!(
            !Operation::TypeText.needs_capture_identity(),
            "typing has no coordinate to be stale about"
        );
    }

    /// Button names fail closed the same way operation names do.
    #[test]
    fn a_button_name_is_matched_exactly_or_not_at_all() {
        assert_eq!(Button::parse("left"), Some(Button::Left));
        assert_eq!(Button::parse("right"), Some(Button::Right));
        for rejected in ["", "Left", "LEFT", " left", "left ", "middle", "primary"] {
            assert_eq!(Button::parse(rejected), None, "{rejected:?}");
        }
        assert_eq!(Button::DEFAULT, Button::Left);
        assert_eq!(Button::default(), Button::DEFAULT);
    }
}
