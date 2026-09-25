//! The M5-01 pin: which published CUA artifact the `computer.v1` profile is
//! specified against, and the assertions that keep that true.
//!
//! **This module proves that the pin is the pin. It proves nothing about
//! interoperability.** The server has never been installed, imported or
//! executed here, nothing has been sent to a `/cmd` endpoint, and nothing in
//! this repository touches a host's screen or input devices. Every constant
//! below was read out of an artifact that was downloaded and hashed; see
//! `docs/sources.md`, section "just-bash and CUA".
//!
//! Why the pin lives in *this* crate and not a `tunnel-cua` one: `computer.v1`
//! is an [`http-forward/1`] profile carrying its own schema, not a typed
//! gateway of its own, so the artifact that defines the profile's wire shape is
//! pinned beside the codec that will carry it. There is no CUA adapter yet.
//!
//! Three things are asserted rather than asserted-in-a-comment:
//!
//! 1. `tests/cua_pin.rs` reads the real `docs/sources.md` and fails if it stops
//!    recording either digest, the release commit, or the Python requirement.
//!    Deleting the record turns a test red instead of leaving a stale sentence.
//! 2. The same test checks [`ALLOWED_COMMANDS`] against the operation table in
//!    `docs/integrations.md`, so the allowlist and the document cannot drift
//!    apart silently.
//! 3. The digests are re-fetched and re-hashed by `scripts/m5-cua-refetch.sh`,
//!    which downloads all four artifacts and compares. That script is what
//!    the verification pass runs; this module is what it compares against.
//! 4. [`COMMAND_PARAMETERS`] is re-derived from the re-fetched
//!    `handlers/base.py` by `scripts/m5-cua-param-parity.py`, which the same
//!    script invokes. Without it that table would be a transcription this
//!    repository checks against itself, which is what M5-C06 was filed about.
//!
//! [`http-forward/1`]: https://github.com/andymac4182/agent-tunnel/blob/main/docs/http-forwarding.md

/// The pinned PyPI distribution name. The import package is `computer_server`.
pub const DISTRIBUTION: &str = "cua-computer-server";
/// Exact version. No range is pinned: this is the only CUA artifact named.
pub const VERSION: &str = "0.3.46";

/// SHA-256 of `cua_computer_server-0.3.46-py3-none-any.whl`, computed locally
/// from the downloaded file and equal to the `digests.sha256` PyPI reports.
pub const WHEEL_SHA256: &str = "45f551d80054d8f993590b7428e94e7415501dbccdcda2ca5ad4148300883b3f";
/// Size of that wheel in bytes.
pub const WHEEL_BYTES: u64 = 133_851;

/// SHA-256 of `cua_computer_server-0.3.46.tar.gz`, computed the same way.
pub const SDIST_SHA256: &str = "3c434b421aa8f7dadcce5eeb92e186eae8f3c21e3720cc9da840a824e22e5494";
/// Size of that sdist in bytes.
pub const SDIST_BYTES: u64 = 137_685;

/// SHA-256 of `computer_server/main.py`, the one file the profile's wire shape
/// is read from. Identical in the sdist, in the wheel, and at
/// [`RELEASE_COMMIT`] — which is how the release commit's provenance is
/// corroborated, a Python sdist having no `.cargo_vcs_info.json` equivalent.
pub const MAIN_PY_SHA256: &str = "a5986dfc5e43ab3baaa9fa2ab6740dea5d6155e0f32b3f6bb444c9cd8ac9c6e4";

/// The upstream repository.
pub const REPOSITORY: &str = "https://github.com/trycua/cua";
/// The commit the git tag `computer-server-v0.3.46` resolved to. Its
/// `pyproject.toml` declares `version = "0.3.46"`.
pub const RELEASE_COMMIT: &str = "c07d287af35cf37cfcf94290c46db2720ec47822";
/// Path of the distribution's source inside that monorepo.
pub const SOURCE_PATH: &str = "libs/python/computer-server";

/// The development commit `docs/integrations.md` originally cited, read
/// 2026-09-09. Recorded so the reconciliation is not lost: its manifest
/// declares **0.3.45**, yet its `main.py` is byte-identical to the released
/// one, so the method-level line ranges cited from it remain exact for 0.3.46.
/// It is deliberately *not* the pin.
pub const INSPECTED_COMMIT: &str = "bd4c10020cd7cac07c0d19b0f53ba4b007fbcb15";
/// The version that commit's manifest declares — not [`VERSION`].
pub const INSPECTED_VERSION: &str = "0.3.45";

/// `requires-python` as declared by the released `pyproject.toml` and
/// `PKG-INFO`: 3.12 and 3.13 only.
pub const REQUIRES_PYTHON: &str = ">=3.12,<3.14";

/// How the artifacts were obtained, recorded so the verification pass can
/// repeat it exactly.
pub const ACQUISITION: &str = "curl of the two files.pythonhosted.org URLs named in https://pypi.org/pypi/cua-computer-server/json, then shasum -a 256";

/// The media type `POST /cmd` actually returns. **Not** `text/event-stream`
/// and not `application/json`: the released handler passes this literal to
/// `StreamingResponse`.
pub const CMD_MEDIA_TYPE: &str = "text/plain";
/// The framing of each `/cmd` event: `data: <JSON>` followed by a blank line.
pub const CMD_EVENT_PREFIX: &str = "data: ";
/// The framing terminator.
pub const CMD_EVENT_TERMINATOR: &str = "\n\n";

/// A `/cmd` response that reached the body stage always carries HTTP 200, and
/// its payload may still be `{"success": false, ...}` — the success and error
/// payloads are yielded from one generator after the response has begun, so
/// the status is committed before the outcome is known.
///
/// The adapter must therefore read the payload, never the status, to decide
/// whether a command succeeded. Upstream's own
/// `tests/test_auth_availability.py::test_backwards_compat_local_dev_allows_requests`
/// asserts a 200 whose body text contains `success`.
///
/// This is recorded as the released construct that establishes it rather than
/// as a bare `true`, so the constant carries evidence a reader can re-check.
pub const SUCCESS_FALSE_UNDER_200_EVIDENCE: &str = "main.py generate_response yields {\"success\": false, \"error\": ...} into an already-started StreamingResponse";

/// Pre-dispatch failures do **not** use the framing above: a malformed body,
/// a missing or unknown command, and cloud authentication failures are raised
/// as `HTTPException` and arrive as real 400/401 responses with no `data:`
/// event at all. An adapter that only knows how to parse the framed form will
/// mis-report these. These are the statuses the released handler uses.
pub const PRE_DISPATCH_ERROR_STATUSES: &[u16] = &[400, 401];

/// The initial `computer.v1` allowlist, in the order `docs/integrations.md`'s
/// operation table introduces them. Every name here was confirmed present in
/// the released registry; unknown commands fail closed.
///
/// This is an allowlist, not a capability claim. The released server filters
/// its registry through `backend_policy.exposed_command_registry`, which under
/// `CUA_BACKEND=vnc` narrows it to a VNC-remote subset, so what a given backend
/// advertises must be read from `/commands` rather than assumed from this list.
pub const ALLOWED_COMMANDS: &[&str] = &[
    "version",
    "screenshot",
    "get_screen_size",
    "get_cursor_position",
    "left_click",
    "right_click",
    "double_click",
    "move_cursor",
    "drag",
    "scroll",
    "type_text",
    "press_key",
    "hotkey",
    "get_accessibility_tree",
];

/// Command names the released server accepts as aliases for members of
/// [`ALLOWED_COMMANDS`]. Recorded so nobody rediscovers them by accident; the
/// adapter sends canonical names and must not depend on alias resolution,
/// because the released code trims the alias map when the backend narrows the
/// registry.
pub const ALIASES_NOT_TO_RELY_ON: &[(&str, &str)] = &[
    ("click", "left_click"),
    ("tap", "left_click"),
    ("type", "type_text"),
    ("key", "press_key"),
];

/// Env var that makes the released server answer 503 when `CONTAINER_NAME` is
/// unset. A supervising device must read that as "deliberately unavailable",
/// not as a transient fault to retry through.
pub const UNAVAILABLE_FLAG: &str = "UNAVAILABLE_WITHOUT_CONTAINER_NAME";

/// The `/ws` surface is **deferred, with a reason**: the released handler
/// processes commands sequentially and does not echo a request ID, so one
/// in-flight command per socket would be forced and correlation would have to
/// live in the adapter. `/cmd` is the pinned surface.
///
/// Recorded as the phrase `docs/sources.md` must keep, so the deferral cannot
/// quietly become an omission; `tests/cua_pin.rs` checks the document for it.
pub const WEBSOCKET_DEFERRAL_RECORDED_AS: &str = "`/ws` is deferred";

/// `cua-driver` is **not** a published crate, confirmed two ways:
/// `index.crates.io` answers 404 for it and 200 for a control crate, and the
/// JSON API answers 404 for it and 200 for the control once a descriptive
/// `User-Agent` is sent (its 403 is a UA policy, not a host limitation). It is an
/// optional extra of the pinned distribution, declared as the range below, and
/// is reached through the server's own backend handler behind the same `/cmd`
/// surface. No separate driver profile is pinned or planned.
pub const DRIVER_EXTRA_REQUIREMENT: &str = "cua-driver>=0.22.2,<0.23.0";

/// SHA-256 of `computer_server/handlers/base.py`, the abstract handler
/// contract every concrete backend implements and the file
/// [`COMMAND_PARAMETERS`] is transcribed from. Verified identical in the
/// sdist and at [`RELEASE_COMMIT`], the same two ways [`MAIN_PY_SHA256`] is.
///
/// It is pinned separately from `main.py` because the two answer different
/// questions: `main.py` says which command *names* dispatch, `base.py` says
/// what *parameters* each of them takes. M5-C06 existed because only the
/// first had been read.
pub const BASE_PY_SHA256: &str = "4c9aa3926032950ed5fd34b752e29f656090d08096c933e18f0cbbb2af64d169";

/// One allowlisted command's parameter schema, transcribed from the pinned
/// artifact.
///
/// **Why this table has teeth.** The released `/cmd` handler dispatches with
/// `filtered_params = {k: v for k, v in params.items() if k in sig.parameters}`
/// (`main.py`, the `generate_response` closure). A parameter name the handler
/// does not declare is **silently discarded** — no error, no warning, no
/// 400 — and the command then runs with that argument's default, or raises a
/// `TypeError` that arrives as `{"success": false}` inside a 200. So an
/// unknown *command* is loud and an unknown *parameter* is not, which is
/// exactly the asymmetry that made a half-pin dangerous.
pub struct CommandParameters {
    /// The canonical command name, which must appear in [`ALLOWED_COMMANDS`].
    pub command: &'static str,
    /// Parameters with no default: omitting one raises `TypeError` upstream.
    pub required: &'static [&'static str],
    /// Parameters with a default. Omitting one is safe; misspelling one is
    /// silently ignored, which is why they are pinned too.
    pub optional: &'static [&'static str],
}

/// The parameter schema of every member of [`ALLOWED_COMMANDS`], read from
/// `computer_server/handlers/base.py` at [`BASE_PY_SHA256`] — and, for
/// `version`, from the `main.py` registry lambda, which takes none.
///
/// `scripts/m5-cua-refetch.sh` re-fetches that file, re-hashes it, parses the
/// signatures out of it and compares them against this table, so the table is
/// pinned against the upstream source rather than against itself.
///
/// **Two recorded caveats, neither of which this table smooths over:**
///
/// 1. `scroll`'s `x` and `y` are scroll **amounts**, not a cursor position.
///    All six backends treat them that way, though they do not share a body:
///    macOS, Linux and Windows call `self.mouse.scroll(x, y)`; VNC repeats
///    arrow-key presses `abs(y)` (then `abs(x)`) times, because Apple's
///    `_VZVNCServer` does not translate RFB buttons 4-7 into wheel events;
///    Android swipes from the screen centre to `(centre_x + x, centre_y - y)`;
///    and the Cua Driver handler maps the sign to a direction and the
///    magnitude to a count. `main.py`'s own `_scroll_direction_handler`
///    delegates vertically to `scroll_down(clicks)`/`scroll_up(clicks)` and
///    horizontally to `scroll(x_amount * clicks, 0)` with
///    `x_amount = -300` for left and `300` for right. There is no way to
///    scroll *at a point*: the pinned registry exposes no such parameter on
///    any backend.
/// 2. The VNC backend narrows `screenshot` to `screenshot(self)` — no
///    `format`, no `quality`. Sending either is silently dropped there. This
///    table records the abstract contract; a backend may accept a subset, so
///    only `required` is safe to rely on across all six backends.
pub const COMMAND_PARAMETERS: &[CommandParameters] = &[
    CommandParameters {
        command: "version",
        required: &[],
        optional: &[],
    },
    CommandParameters {
        command: "screenshot",
        required: &[],
        optional: &["format", "quality"],
    },
    CommandParameters {
        command: "get_screen_size",
        required: &[],
        optional: &[],
    },
    CommandParameters {
        command: "get_cursor_position",
        required: &[],
        optional: &[],
    },
    CommandParameters {
        command: "left_click",
        required: &[],
        optional: &["x", "y"],
    },
    CommandParameters {
        command: "right_click",
        required: &[],
        optional: &["x", "y"],
    },
    CommandParameters {
        command: "double_click",
        required: &[],
        optional: &["x", "y"],
    },
    CommandParameters {
        command: "move_cursor",
        required: &["x", "y"],
        optional: &[],
    },
    CommandParameters {
        command: "drag",
        required: &["path"],
        optional: &["button", "duration"],
    },
    CommandParameters {
        command: "scroll",
        required: &["x", "y"],
        optional: &[],
    },
    CommandParameters {
        command: "type_text",
        required: &["text"],
        optional: &[],
    },
    CommandParameters {
        command: "press_key",
        required: &["key"],
        optional: &[],
    },
    CommandParameters {
        command: "hotkey",
        required: &["keys"],
        optional: &[],
    },
    CommandParameters {
        command: "get_accessibility_tree",
        required: &[],
        optional: &[],
    },
];

/// Parameter names this repository once sent that the pinned source does not
/// declare, **and whose loss changed what the command did**.
///
/// Each was silently discarded by the released dispatcher; none produced an
/// error anywhere. `drag` lost every endpoint it had and would have raised a
/// `TypeError` for the missing `path`; `scroll` kept `x`/`y` — but those are
/// wheel *amounts* upstream, so it scrolled by the cursor coordinate and
/// dropped the real deltas, silently and wrongly.
///
/// Recorded so the correction cannot be quietly undone, and so a reader who
/// finds one of these names in a diff knows it is a regression rather than a
/// new idea. `docs/tasks.md` M5-C06 has the measurement.
pub const PARAMETERS_NEVER_TO_SEND: &[(&str, &str)] = &[
    ("drag", "start_x"),
    ("drag", "start_y"),
    ("drag", "end_x"),
    ("drag", "end_y"),
    ("scroll", "dx"),
    ("scroll", "dy"),
];

/// Parameter names the adapter sends **knowing** the released dispatcher
/// discards them, because discarding them changes nothing the command does.
///
/// This is deliberately a separate list from [`PARAMETERS_NEVER_TO_SEND`], and
/// the distinction is the whole point of having read the source rather than
/// the command names alone:
///
/// * A discarded name that *changes the action* is a correctness defect and
///   must be removed — `drag`'s endpoints, `scroll`'s deltas.
/// * A discarded name that changes *nothing* is a **capability gap**. No
///   pinned backend declares `display` on `screenshot` or `get_screen_size`;
///   upstream captures whatever `ImageGrab.grab()` returns and reports one
///   screen size, with or without the member. Removing the member would not
///   give the consumer a display selection, so removing it buys nothing.
///
/// So the member stays on the wire and the gap is named here instead of being
/// hidden by a silent omission. **The consumer-visible half is closed
/// (M5-C12):** `tunnel_cua::plan::plan` refuses any index outside
/// `tunnel_cua::schema::SELECTABLE_DISPLAYS` -- only the default -- before
/// dispatch, so what is sent is always `0`. The Lane A fixture still varies
/// its image by display, but a second display is no longer reachable through
/// the facade; the proof-4 control varies the screen's content instead.
pub const PARAMETERS_KNOWINGLY_DISCARDED: &[(&str, &str)] =
    &[("screenshot", "display"), ("get_screen_size", "display")];

/// The sign convention of `scroll`'s vertical amount, pinned beside the names
/// rather than left to a reader (M5-C13): **positive `y` scrolls up.**
///
/// Read from the pinned sdist (SHA-256 [`SDIST_SHA256`]), where three handlers
/// state it: `handlers/macos.py` `scroll` ("positive for up, negative for
/// down"), `handlers/windows.py` `scroll` ("Positive values scroll up"), and
/// `handlers/vnc.py` `_VNCConnection.scroll` ("y>0 = up ... matches macOS
/// native handler convention"). `handlers/linux.py` states no convention, and
/// the Android handler maps the amount onto a swipe (`end_y = center_y - y`),
/// so on those two the direction is **inferred, not stated**, and only a probe
/// (M5-C02) can confirm it. The adapter passes the consumer's `dy` through
/// unchanged, so the consumer-facing convention is this one.
///
/// Each entry is `(file, the phrase that states it)`; `tests/cua_pin.rs`
/// requires `docs/integrations.md` to record the convention.
pub const SCROLL_SIGN_CONVENTION: &[(&str, &str)] = &[
    ("handlers/macos.py", "positive for up, negative for down"),
    ("handlers/windows.py", "Positive values scroll up"),
    ("handlers/vnc.py", "y>0 = up"),
];

/// Look up one allowlisted command's pinned parameter schema.
#[must_use]
pub fn parameters_for(command: &str) -> Option<&'static CommandParameters> {
    COMMAND_PARAMETERS
        .iter()
        .find(|entry| entry.command == command)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is_lower_hex(value: &str, len: usize) -> bool {
        value.len() == len
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }

    #[test]
    fn every_recorded_digest_is_a_lowercase_sha256_and_they_are_distinct() {
        for digest in [WHEEL_SHA256, SDIST_SHA256, MAIN_PY_SHA256, BASE_PY_SHA256] {
            assert!(
                is_lower_hex(digest, 64),
                "not a lowercase sha-256: {digest}"
            );
        }
        // Non-vacuity: a copy-paste that collapsed two artifacts onto one
        // digest would otherwise satisfy the check above.
        assert_ne!(WHEEL_SHA256, SDIST_SHA256);
        assert_ne!(WHEEL_SHA256, MAIN_PY_SHA256);
        assert_ne!(SDIST_SHA256, MAIN_PY_SHA256);
        assert_ne!(BASE_PY_SHA256, MAIN_PY_SHA256);
        assert_ne!(BASE_PY_SHA256, WHEEL_SHA256);
        assert_ne!(BASE_PY_SHA256, SDIST_SHA256);
    }

    #[test]
    fn the_release_commit_is_a_full_hash_and_is_not_the_inspected_one() {
        assert!(is_lower_hex(RELEASE_COMMIT, 40));
        assert!(is_lower_hex(INSPECTED_COMMIT, 40));
        // The whole point of the reconciliation: these are different commits,
        // and the pin is the release one.
        assert_ne!(RELEASE_COMMIT, INSPECTED_COMMIT);
        assert_ne!(VERSION, INSPECTED_VERSION);
    }

    #[test]
    fn the_cmd_framing_is_the_released_one_and_not_sse() {
        assert_eq!(CMD_MEDIA_TYPE, "text/plain");
        assert_ne!(CMD_MEDIA_TYPE, "text/event-stream");
        assert_ne!(CMD_MEDIA_TYPE, "application/json");
        assert_eq!(CMD_EVENT_PREFIX, "data: ");
        assert_eq!(CMD_EVENT_TERMINATOR, "\n\n");
    }

    #[test]
    fn the_allowlist_has_no_duplicates_and_excludes_the_host_surfaces() {
        let mut sorted = ALLOWED_COMMANDS.to_vec();
        sorted.sort_unstable();
        let before = sorted.len();
        sorted.dedup();
        assert_eq!(before, sorted.len(), "duplicate command in the allowlist");

        // The registry also exposes shell, host files, clipboard and window
        // management. Our VFS has its own provider and confinement, so these
        // must never enter the allowlist by drift.
        for refused in [
            "run_command",
            "read_text",
            "write_text",
            "delete_file",
            "set_clipboard",
            "launch",
            "activate_window",
        ] {
            assert!(
                !ALLOWED_COMMANDS.contains(&refused),
                "{refused} is a host-surface command and must stay out of the allowlist"
            );
        }
    }

    #[test]
    fn every_allowlisted_command_has_exactly_one_pinned_parameter_schema() {
        // The pairing is what makes the pin a pin: a command name added to
        // the allowlist without reading its signature, or a schema left
        // behind by a command that was removed, both fail here.
        assert_eq!(
            COMMAND_PARAMETERS.len(),
            ALLOWED_COMMANDS.len(),
            "the parameter table and the command allowlist have drifted apart"
        );
        // A literal, not `ALLOWED_COMMANDS.len()` on both sides: two tables
        // that shrank together would otherwise agree with each other.
        assert_eq!(COMMAND_PARAMETERS.len(), 14);

        for command in ALLOWED_COMMANDS {
            assert!(
                parameters_for(command).is_some(),
                "{command} is allowlisted with no pinned parameter schema"
            );
        }
        for entry in COMMAND_PARAMETERS {
            assert!(
                ALLOWED_COMMANDS.contains(&entry.command),
                "{} has a parameter schema but is not allowlisted",
                entry.command
            );
        }
    }

    #[test]
    fn no_pinned_parameter_is_both_required_and_optional_or_repeated() {
        let mut total = 0_usize;
        for entry in COMMAND_PARAMETERS {
            let mut names: Vec<&str> = entry
                .required
                .iter()
                .chain(entry.optional.iter())
                .copied()
                .collect();
            total += names.len();
            let before = names.len();
            names.sort_unstable();
            names.dedup();
            assert_eq!(
                before,
                names.len(),
                "{} repeats a parameter name across required/optional",
                entry.command
            );
        }
        // Non-vacuity: without this the loop above is satisfied by a table of
        // fourteen commands that all take nothing, which is precisely the
        // "looks pinned and is not" shape M5-C06 was filed about.
        // 2 (screenshot) + 2+2+2 (the three clicks) + 2 (move_cursor)
        // + 3 (drag) + 2 (scroll) + 1+1+1 (text, key, keys) = 18.
        assert_eq!(total, 18, "the pinned parameter names were counted wrong");
    }

    #[test]
    fn the_two_discard_lists_are_disjoint_and_neither_is_empty() {
        // The distinction between them is load-bearing: one names parameters
        // that must be removed, the other names one that is deliberately
        // still sent. A name in both would make the pair meaningless.
        for (command, refused) in PARAMETERS_NEVER_TO_SEND {
            assert!(
                !PARAMETERS_KNOWINGLY_DISCARDED.contains(&(command, refused)),
                "{refused} on {command} is in both discard lists"
            );
        }
        assert_eq!(PARAMETERS_NEVER_TO_SEND.len(), 6);
        assert_eq!(PARAMETERS_KNOWINGLY_DISCARDED.len(), 2);
    }

    #[test]
    fn the_parameters_never_to_send_are_genuinely_absent_from_their_command() {
        for (command, refused) in PARAMETERS_NEVER_TO_SEND
            .iter()
            .chain(PARAMETERS_KNOWINGLY_DISCARDED.iter())
        {
            let entry = parameters_for(command)
                .unwrap_or_else(|| panic!("{command} is not an allowlisted command"));
            assert!(
                !entry.required.contains(refused) && !entry.optional.contains(refused),
                "{refused} is recorded as never-to-send on {command}, \
                 yet the pinned schema declares it"
            );
        }

        // **Positive control for the assertion above.** Every name in that
        // list is absent, so the loop would read exactly the same against a
        // schema that declared nothing at all. These three names *are*
        // declared, and would fail the same check — which is what makes the
        // absences above evidence rather than a vacuous pass.
        for (command, present) in [("drag", "path"), ("scroll", "x"), ("screenshot", "format")] {
            let entry = parameters_for(command).expect("allowlisted");
            assert!(
                entry.required.contains(&present) || entry.optional.contains(&present),
                "{present} should be declared on {command}; the control is broken"
            );
        }
    }

    #[test]
    fn every_alias_resolves_to_a_command_that_is_actually_allowed() {
        for (alias, canonical) in ALIASES_NOT_TO_RELY_ON {
            assert!(
                ALLOWED_COMMANDS.contains(canonical),
                "alias {alias} points at {canonical}, which is not allowlisted"
            );
            assert!(
                !ALLOWED_COMMANDS.contains(alias),
                "{alias} is an alias and must not be sent as a canonical name"
            );
        }
    }
}
