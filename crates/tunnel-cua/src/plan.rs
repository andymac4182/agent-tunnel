//! The pre-dispatch sequence, in the production crate rather than in a test
//! harness.
//!
//! **Why this module exists.** The first review of this chunk observed that
//! the whole validation-ordering contract lived in `Dispatcher`, inside the
//! *fixture* crate, so nothing in `tunnel-cua` encoded the order a real
//! dispatcher must follow. A future device-side facade could have re-derived
//! the order from scratch and got it wrong, and the ordering is the one thing
//! this profile cannot afford to get wrong: every check below happens while
//! nothing has been sent, and the first thing that happens after it may have
//! been seen by a backend.
//!
//! So the order is one function here, [`plan`], and the fixture's dispatcher
//! calls it. [`Planned`] is the only thing that authorizes a send, and its
//! variants are `#[non_exhaustive]` so that a caller outside this crate cannot
//! build one — see [`Planned`] for what that does and does not guarantee.
//!
//! ```text
//!   body --schema::validate_request--> Request      (nothing sent)
//!        --negotiated capability set -> permitted   (nothing sent)
//!        --exclusive input lease     -> held by us  (nothing sent)
//!        --capture identity + bounds -> resolved    (nothing sent)
//!        --operation -> upstream command or local   (nothing sent)
//!   ===================== dispatch boundary =====================
//!   Planned::Dispatch(command, payload)  -- the caller may now send
//!   Planned::AnswerLocally               -- the caller must NOT send
//! ```
//!
//! **Chunk 3 added the third and fourth steps to this function rather than to
//! a second one.** Splitting the input checks into their own entry point would
//! have recreated exactly the defect this module was written to fix: two
//! orderings that a future facade could satisfy one of. So [`plan`] takes a
//! [`SessionContext`], every operation goes through it, and the read-only ones
//! simply never consult the lease -- which is also how
//! `docs/integrations.md`'s "screenshot reads may be shared within the same
//! permitted scope" is implemented: not as an exception, but as an absence.
//!
//! The endpoint check is not a step here because it is not a step anywhere: a
//! [`crate::endpoint::BackendEndpoint`] cannot be constructed from a
//! non-loopback address, so a dispatcher that holds one has already passed it.

use std::collections::BTreeSet;

use serde_json::{Value, json};

use crate::Operation;
use crate::capture::{CaptureIdentity, Captures, Point};
use crate::lease::{GrantRevision, InputLeases, SessionId, TargetSession};
use crate::outcome::{Dispatch, InputRefusal, NotDispatched};
use crate::schema::{self, Params};

/// The device-side state one tunnel session's operations are planned against.
///
/// Everything here is **read-only to [`plan`]**: the lease is not taken as a
/// side effect of an operation, and a capture is not recorded by one. Both
/// mutations are the facade's, and keeping them out of the planner is what
/// makes the planner safe to call speculatively.
///
/// D3 in `<scratchpad>/m5-scoping-and-decisions.md` is why this is a
/// parameter rather than crate state: `http-forward/1` models one exchange,
/// and the lease and the capture carry-forward are state *across* exchanges,
/// which lives in the device-side facade keyed by tunnel session.
pub struct SessionContext<'a> {
    /// The tunnel session the request arrived on. The lease holder.
    pub session: SessionId,
    /// The target OS session this session is driving.
    pub target: &'a TargetSession,
    /// The grant revision the device currently believes this session carries.
    /// See [`crate::lease`] for what that belief can and cannot do today.
    pub grant_revision: GrantRevision,
    /// The device's leases.
    pub leases: &'a InputLeases,
    /// The captures the device has issued.
    pub captures: &'a Captures,
}

/// What the caller should do next, once every pre-dispatch check has passed.
///
/// Outside this crate the only way to obtain one is [`plan`], so a value of
/// this type is evidence that the sequence ran in order.
///
/// # How that is enforced, and a correction
///
/// Both variants are `#[non_exhaustive]`. **An earlier revision of this module
/// claimed `Planned` "has no public constructor" and that `plan` was "the only
/// way to obtain one". Both statements were false**, and review proved it
/// rather than argued it, by compiling a crate outside this workspace that
/// built `Planned::Dispatch { command: "left_click", .. }` — an input command
/// this profile defers and refuses everywhere else. **Rust has no private enum
/// variant**: any code that can name a `pub enum` in a `pub mod` can construct
/// its variants, so the guarantee was decorative for as long as it was merely
/// written down.
///
/// `#[non_exhaustive]` on each variant is what actually buys it. External
/// construction now fails to compile with `E0639`, while [`plan`] keeps
/// building them freely inside this crate. The cost is real and is paid by
/// `tunnel-cua-fixture`: an external `match` on these variants must carry `..`.
///
/// This is enforced by a **compile-fail doctest** rather than by
/// `scripts/m5-guard-deletion.py`. A deletion harness defeats a rule and looks
/// for a red test, and there is no red test for "this does not compile
/// elsewhere" — which is exactly how the false claim survived a suite that was
/// otherwise 37-for-37. A doctest is compiled as its own external crate, so it
/// sees this type the way a consumer does.
///
/// ```compile_fail,E0639
/// use serde_json::json;
/// use tunnel_cua::Operation;
/// use tunnel_cua::plan::Planned;
///
/// // Forging a dispatch for a click. This must not compile -- and chunk 3 is
/// // why it matters far more than it did when `left_click` was merely
/// // deferred: a forged `Planned` now skips the exclusive input lease and the
/// // capture-identity check, not just an allowlist.
/// let forged = Planned::Dispatch {
///     command: "left_click",
///     payload: json!({"x": 100, "y": 200}),
///     operation: Operation::Click,
/// };
/// ```
///
/// The same for the command an unleased agent would most want to forge, with
/// the operation it really belongs to — so the failure cannot be blamed on the
/// mismatched `operation` above.
///
/// ```compile_fail,E0639
/// use serde_json::json;
/// use tunnel_cua::Operation;
/// use tunnel_cua::plan::Planned;
///
/// let forged = Planned::Dispatch {
///     command: "type_text",
///     payload: json!({"text": "sudo rm -rf /"}),
///     operation: Operation::TypeText,
/// };
/// ```
///
/// ```compile_fail,E0639
/// use tunnel_cua::Operation;
/// use tunnel_cua::plan::Planned;
///
/// let forged = Planned::AnswerLocally { operation: Operation::Capture };
/// ```
///
/// The non-vacuity control: the type is still reachable and usable from
/// outside, so the two failures above are about *construction* rather than the
/// doctest being unable to see the crate at all.
///
/// ```
/// use std::collections::BTreeSet;
/// use tunnel_cua::Operation;
/// use tunnel_cua::capture::Captures;
/// use tunnel_cua::lease::{GrantRevision, InputLeases, SessionId, TargetSession};
/// use tunnel_cua::plan::{Planned, SessionContext, plan};
///
/// let target = TargetSession::new("console:1");
/// let leases = InputLeases::new();
/// let captures = Captures::new();
/// let context = SessionContext {
///     session: SessionId::new(1),
///     target: &target,
///     grant_revision: GrantRevision::new(0),
///     leases: &leases,
///     captures: &captures,
/// };
///
/// let body = br#"{"version":"computer.v1","operation":"capture","params":{}}"#;
/// let permitted: BTreeSet<Operation> = [Operation::Capture].into_iter().collect();
/// let planned =
///     plan(body, 4096, &permitted, &context).expect("a granted capture plans a dispatch");
/// match planned {
///     Planned::Dispatch { command, .. } => assert_eq!(command, "screenshot"),
///     Planned::AnswerLocally { .. } => panic!("capture dispatches"),
///     _ => unreachable!(),
/// }
///
/// // And the same context, which holds no lease, refuses a click -- so the
/// // capture above succeeded because reads are shared, not because the
/// // context was permissive.
/// let click = br#"{"version":"computer.v1","operation":"click","params":{"capture":1,"x":0,"y":0}}"#;
/// let permitted: BTreeSet<Operation> = [Operation::Click].into_iter().collect();
/// assert!(plan(click, 4096, &permitted, &context).is_err());
/// ```
#[derive(Clone, Eq, PartialEq)]
pub enum Planned {
    /// Send this command with this payload to the backend.
    #[non_exhaustive]
    Dispatch {
        /// The canonical `cua-computer-server` command name.
        command: &'static str,
        /// The `/cmd` request body.
        payload: Value,
        /// The operation it came from, so a caller need not re-derive it.
        operation: Operation,
    },
    /// Answer from device-side state. **Nothing may be sent.**
    ///
    /// The caller renders this as [`Dispatch::AnsweredLocally`], never as a
    /// dispatch — which is the distinction the first review found this chunk
    /// getting wrong.
    #[non_exhaustive]
    AnswerLocally { operation: Operation },
}

/// **`Debug` is hand-written, and the reason is keystrokes.**
///
/// A derived `Debug` renders `payload` in full, and for `type_text` the
/// payload *is* the text — so `{planned:?}` in a log line would print a
/// password, defeating [`crate::schema::Keystrokes`]'s redaction one layer up.
/// Review caught the claim "never log typed text" being true of the validated
/// parameters and false of the plan built from them.
///
/// This renders the command, the operation and the payload's **size**, which
/// are identifiers and a counter. The payload itself still travels — it is the
/// request body — but nothing formats it.
///
/// ```
/// use std::collections::BTreeSet;
/// use tunnel_cua::Operation;
/// use tunnel_cua::capture::Captures;
/// use tunnel_cua::lease::{GrantRevision, InputLeases, SessionId, TargetSession};
/// use tunnel_cua::plan::{SessionContext, plan};
///
/// let target = TargetSession::new("console:1");
/// let mut leases = InputLeases::new();
/// let session = SessionId::new(1);
/// leases.acquire(&target, session, GrantRevision::new(0)).unwrap();
/// let captures = Captures::new();
/// let context = SessionContext {
///     session,
///     target: &target,
///     grant_revision: GrantRevision::new(0),
///     leases: &leases,
///     captures: &captures,
/// };
///
/// let body = br#"{"version":"computer.v1","operation":"type_text","params":{"text":"hunter2"}}"#;
/// let permitted: BTreeSet<Operation> = [Operation::TypeText].into_iter().collect();
/// let planned = plan(body, 4096, &permitted, &context).expect("a granted type_text plans");
/// let rendered = format!("{planned:?}");
/// assert!(!rendered.contains("hunter2"), "the plan leaked the typed text: {rendered}");
/// assert!(rendered.contains("type_text"), "the command is still legible");
/// ```
impl core::fmt::Debug for Planned {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Dispatch {
                command,
                payload,
                operation,
            } => formatter
                .debug_struct("Planned::Dispatch")
                .field("command", command)
                .field("operation", &operation.name())
                .field(
                    "payload",
                    &format_args!("<{} bytes>", payload.to_string().len()),
                )
                .finish(),
            Self::AnswerLocally { operation } => formatter
                .debug_struct("Planned::AnswerLocally")
                .field("operation", &operation.name())
                .finish(),
        }
    }
}

/// Run every pre-dispatch check, in order.
///
/// # Errors
/// A [`Dispatch::NotDispatched`] naming the first check that refused. Every
/// one of them means the backend was never contacted.
pub fn plan(
    body: &[u8],
    limit: u64,
    permitted: &BTreeSet<Operation>,
    context: &SessionContext<'_>,
) -> Result<Planned, Dispatch> {
    // 1. Schema. A partially parsed command cannot be authorized, so this
    //    takes a complete slice and validates all of it first.
    let request = schema::validate_request(body, limit)
        .map_err(|error| Dispatch::NotDispatched(NotDispatched::Schema(error)))?;

    // 2. The negotiated capability set -- the intersection of local
    //    configuration, upstream backend support and the caller's grant. The
    //    set is handed in already computed, so nothing here can widen it.
    let operation = request.operation();
    if !permitted.contains(&operation) {
        return Err(Dispatch::NotDispatched(NotDispatched::NotPermitted));
    }

    // 3. The exclusive input lease, and 4. the capture identity. Only for
    //    operations that act; a `capture` from a second session is not refused
    //    here, which is the shared-reads half of the contract.
    //
    //    **The lease runs before the capture**, and the order is asserted: an
    //    agent that does not hold input must learn that first, because a
    //    capture refusal would invite it to capture again and retry, which is
    //    the wrong remedy and a busy loop.
    let capture = if operation.mutates_target() {
        context
            .leases
            .check(context.target, context.session, context.grant_revision)
            .map_err(|refusal| {
                Dispatch::NotDispatched(NotDispatched::InputAuthority(InputRefusal::Lease(refusal)))
            })?;
        resolve_capture(operation, request.params(), context)?
    } else {
        None
    };

    // 5. The operation's upstream mapping. `describe` has none: it is answered
    //    from the negotiated set, which is the only honest thing it could be
    //    answered from -- a config echo would be the trap.
    let Some(command) = dispatch_command(operation, request.params()) else {
        return Ok(Planned::AnswerLocally { operation });
    };

    Ok(Planned::Dispatch {
        command,
        payload: command_payload(command, request.params(), capture),
        operation,
    })
}

/// Resolve and bounds-check every capture coordinate an operation carries.
///
/// Returns `None` for an input operation with no coordinates (the keyboard
/// ones), which is not the same as "no check ran": those operations report
/// `false` from [`Operation::needs_capture_identity`], and the debug assertion
/// below is what ties the two together.
fn resolve_capture<'a>(
    operation: Operation,
    params: &Params,
    context: &'a SessionContext<'_>,
) -> Result<Option<&'a CaptureIdentity>, Dispatch> {
    let refuse = |refusal| {
        Dispatch::NotDispatched(NotDispatched::InputAuthority(InputRefusal::Capture(
            refusal,
        )))
    };
    let resolved = match params {
        Params::Click { capture, point, .. }
        | Params::DoubleClick { capture, point }
        | Params::Move { capture, point }
        | Params::Scroll { capture, point, .. } => Some(
            context
                .captures
                .resolve_point(*capture, context.target, *point)
                .map_err(refuse)?,
        ),
        Params::Drag { capture, from, to } => {
            // **Both ends.** A drag that starts inside the capture and ends
            // outside it is a drag off the edge of the image the consumer
            // looked at, and checking only the start is the natural mistake.
            context
                .captures
                .resolve_point(*capture, context.target, *from)
                .map_err(refuse)?;
            Some(
                context
                    .captures
                    .resolve_point(*capture, context.target, *to)
                    .map_err(refuse)?,
            )
        }
        Params::TypeText { .. } | Params::PressKey { .. } | Params::Hotkey { .. } => None,
        Params::Describe
        | Params::Capture { .. }
        | Params::ScreenInfo { .. }
        | Params::CursorPosition => None,
    };
    debug_assert_eq!(
        resolved.is_some(),
        operation.needs_capture_identity(),
        "the parameter shape and needs_capture_identity disagree"
    );
    Ok(resolved)
}

/// The canonical command one validated operation dispatches.
///
/// Separate from [`Operation::upstream_command`] because `click` resolves its
/// command from the **button**, and a mapping that could not see the
/// parameters would have to pick one. `None` only for [`Operation::Describe`].
#[must_use]
pub fn dispatch_command(operation: Operation, params: &Params) -> Option<&'static str> {
    match params {
        Params::Click { button, .. } => Some(button.upstream_command()),
        _ => operation.upstream_command(),
    }
}

/// The `/cmd` request body for one validated operation.
///
/// `capture` is the identity the coordinates were validated against, and it is
/// **used**, not merely carried: [`CaptureIdentity::to_backend_point`] turns
/// capture pixels into the backend's point space. Passing `None` for an
/// operation that has coordinates would send raw pixels, which on a scaled
/// display is a click at the wrong place with no error anywhere -- so the one
/// caller that can supply it ([`plan`]) always does.
#[must_use]
pub fn command_payload(command: &str, params: &Params, capture: Option<&CaptureIdentity>) -> Value {
    let convert = |point: Point| {
        capture.map_or((point.x, point.y), |identity| {
            identity.to_backend_point(point)
        })
    };
    match params {
        Params::Capture { display } | Params::ScreenInfo { display } => {
            json!({"command": command, "params": {"display": display}})
        }
        Params::Describe | Params::CursorPosition => {
            json!({"command": command, "params": {}})
        }
        Params::Click { point, .. }
        | Params::DoubleClick { point, .. }
        | Params::Move { point, .. } => {
            let (x, y) = convert(*point);
            json!({"command": command, "params": {"x": x, "y": y}})
        }
        Params::Drag { from, to, .. } => {
            let (start_x, start_y) = convert(*from);
            let (end_x, end_y) = convert(*to);
            json!({"command": command, "params": {
                "start_x": start_x, "start_y": start_y,
                "end_x": end_x, "end_y": end_y,
            }})
        }
        Params::Scroll { point, dx, dy, .. } => {
            let (x, y) = convert(*point);
            json!({"command": command, "params": {"x": x, "y": y, "dx": dx, "dy": dy}})
        }
        // **The one place `Keystrokes::as_str` is called.** It goes into a
        // request body and nowhere else; nothing formats it.
        Params::TypeText { text } => {
            json!({"command": command, "params": {"text": text.as_str()}})
        }
        Params::PressKey { key } => {
            json!({"command": command, "params": {"key": key.as_str()}})
        }
        Params::Hotkey { keys } => {
            json!({"command": command, "params": {
                "keys": keys.iter().map(crate::schema::Keystrokes::as_str).collect::<Vec<_>>(),
            }})
        }
    }
}

/// Build the `/cmd` body for a discovery command that is not a
/// `computer.v1` operation.
///
/// `version` is the only one this chunk issues, and it is issued during
/// capability discovery rather than on behalf of a consumer request — so it
/// has no [`Request`] and cannot go through [`plan`]. It is a separate,
/// narrower entry point rather than a hole in `plan`'s ordering.
///
/// # Errors
/// The command must be one of [`Operation::DESCRIBE_READS`]; anything else is
/// refused, so this cannot become a way to send an arbitrary command name.
pub fn discovery_payload(command: &str) -> Result<Value, NotDispatched> {
    if !Operation::DESCRIBE_READS.contains(&command) {
        return Err(NotDispatched::Operation(crate::operation::Refusal::Unknown));
    }
    Ok(json!({"command": command, "params": {}}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::{CaptureId, CaptureRefusal, IDENTITY_SCALE_PERCENT};
    use crate::lease::LeaseRefusal;
    use crate::operation::{Deferral, Refusal};
    use crate::schema::SchemaError;

    const SESSION: SessionId = SessionId::new(1);
    const OTHER: SessionId = SessionId::new(2);
    const REVISION: GrantRevision = GrantRevision::new(0);

    fn body(operation: &str, params: Value) -> Vec<u8> {
        json!({
            "version": crate::SCHEMA_VERSION,
            "operation": operation,
            "params": params,
        })
        .to_string()
        .into_bytes()
    }

    fn all() -> BTreeSet<Operation> {
        Operation::ALL.into_iter().collect()
    }

    /// A device with no lease and no capture: what a session looks like before
    /// it has done anything.
    struct World {
        target: TargetSession,
        leases: InputLeases,
        captures: Captures,
    }

    impl World {
        fn new() -> Self {
            Self {
                target: TargetSession::new("console:1"),
                leases: InputLeases::new(),
                captures: Captures::new(),
            }
        }

        /// Give `session` the lease and one current 128x96 capture at 1x.
        fn ready(session: SessionId) -> (Self, CaptureId) {
            let mut world = Self::new();
            world
                .leases
                .acquire(&world.target, session, REVISION)
                .unwrap();
            let identity = world
                .captures
                .record(&world.target, 0, 128, 96, IDENTITY_SCALE_PERCENT)
                .unwrap();
            let id = identity.id();
            (world, id)
        }

        fn context(&self, session: SessionId) -> SessionContext<'_> {
            SessionContext {
                session,
                target: &self.target,
                grant_revision: REVISION,
                leases: &self.leases,
                captures: &self.captures,
            }
        }

        fn plan(
            &self,
            session: SessionId,
            operation: &str,
            params: Value,
        ) -> Result<Planned, Dispatch> {
            plan(
                &body(operation, params),
                4096,
                &all(),
                &self.context(session),
            )
        }
    }

    fn lease_refusal(refusal: LeaseRefusal) -> Result<Planned, Dispatch> {
        Err(Dispatch::NotDispatched(NotDispatched::InputAuthority(
            InputRefusal::Lease(refusal),
        )))
    }

    fn capture_refusal(refusal: CaptureRefusal) -> Result<Planned, Dispatch> {
        Err(Dispatch::NotDispatched(NotDispatched::InputAuthority(
            InputRefusal::Capture(refusal),
        )))
    }

    #[test]
    fn a_dispatching_operation_plans_its_canonical_command_and_payload() {
        let world = World::new();
        for (operation, command, params, expected) in [
            (
                "capture",
                "screenshot",
                json!({"display": 3}),
                json!({"command": "screenshot", "params": {"display": 3}}),
            ),
            (
                "screen_info",
                "get_screen_size",
                json!({}),
                json!({"command": "get_screen_size", "params": {"display": 0}}),
            ),
            (
                "cursor_position",
                "get_cursor_position",
                json!({}),
                json!({"command": "get_cursor_position", "params": {}}),
            ),
        ] {
            let planned = world.plan(SESSION, operation, params).unwrap();
            let Planned::Dispatch {
                command: planned_command,
                payload,
                ..
            } = planned
            else {
                panic!("{operation} should plan a dispatch");
            };
            assert_eq!(planned_command, command);
            assert_eq!(payload, expected);
        }
    }

    /// Every input operation plans the canonical command and the payload
    /// shape, given a lease and a current capture.
    #[test]
    fn every_input_operation_plans_its_canonical_command_and_payload() {
        let (world, capture) = World::ready(SESSION);
        let c = capture.value();
        for (operation, params, command, expected_params) in [
            (
                "click",
                json!({"capture": c, "x": 10, "y": 20}),
                "left_click",
                json!({"x": 10, "y": 20}),
            ),
            (
                "click",
                json!({"capture": c, "x": 10, "y": 20, "button": "right"}),
                "right_click",
                json!({"x": 10, "y": 20}),
            ),
            (
                "double_click",
                json!({"capture": c, "x": 1, "y": 2}),
                "double_click",
                json!({"x": 1, "y": 2}),
            ),
            (
                "move",
                json!({"capture": c, "x": 3, "y": 4}),
                "move_cursor",
                json!({"x": 3, "y": 4}),
            ),
            (
                "drag",
                json!({"capture": c, "x": 1, "y": 2, "to_x": 5, "to_y": 6}),
                "drag",
                json!({"start_x": 1, "start_y": 2, "end_x": 5, "end_y": 6}),
            ),
            (
                "scroll",
                json!({"capture": c, "x": 1, "y": 2, "dx": 0, "dy": -3}),
                "scroll",
                json!({"x": 1, "y": 2, "dx": 0, "dy": -3}),
            ),
            (
                "type_text",
                json!({"text": "hello"}),
                "type_text",
                json!({"text": "hello"}),
            ),
            (
                "press_key",
                json!({"key": "Return"}),
                "press_key",
                json!({"key": "Return"}),
            ),
            (
                "hotkey",
                json!({"keys": ["cmd", "c"]}),
                "hotkey",
                json!({"keys": ["cmd", "c"]}),
            ),
        ] {
            let planned = world.plan(SESSION, operation, params).unwrap();
            let Planned::Dispatch {
                command: planned_command,
                payload,
                ..
            } = planned
            else {
                panic!("{operation} should plan a dispatch");
            };
            assert_eq!(planned_command, command, "{operation}");
            assert_eq!(
                payload,
                json!({"command": command, "params": expected_params}),
                "{operation}"
            );
        }
    }

    /// **The scale carry-forward, where it actually bites.** The planner is
    /// handed a 2x capture; the payload must carry backend points, not the
    /// pixels the consumer sent.
    #[test]
    fn a_scaled_capture_is_converted_before_it_reaches_the_payload() {
        let mut world = World::new();
        world
            .leases
            .acquire(&world.target, SESSION, REVISION)
            .unwrap();
        let scaled = world
            .captures
            .record(&world.target, 0, 256, 192, 200)
            .unwrap();

        let planned = world
            .plan(
                SESSION,
                "click",
                json!({"capture": scaled.id().value(), "x": 100, "y": 80}),
            )
            .unwrap();
        let Planned::Dispatch { payload, .. } = planned else {
            panic!("a click dispatches");
        };
        assert_eq!(
            payload,
            json!({"command": "left_click", "params": {"x": 50, "y": 40}}),
            "the pixel must be divided by the display scale"
        );

        // The control: the same pixel through a 1x capture on another display
        // is unchanged, so the assertion above is reading the scale rather
        // than a constant.
        let unscaled = world
            .captures
            .record(&world.target, 1, 256, 192, IDENTITY_SCALE_PERCENT)
            .unwrap();
        let Planned::Dispatch { payload, .. } = world
            .plan(
                SESSION,
                "click",
                json!({"capture": unscaled.id().value(), "x": 100, "y": 80}),
            )
            .unwrap()
        else {
            panic!("a click dispatches");
        };
        assert_eq!(
            payload,
            json!({"command": "left_click", "params": {"x": 100, "y": 80}})
        );
    }

    /// `describe` never becomes a dispatch.
    #[test]
    fn describe_plans_a_local_answer_and_never_a_command() {
        let world = World::new();
        assert_eq!(
            world.plan(SESSION, "describe", json!({})).unwrap(),
            Planned::AnswerLocally {
                operation: Operation::Describe
            }
        );
        assert_eq!(Operation::Describe.upstream_command(), None);
    }

    /// Order matters, and this is the assertion that pins it.
    #[test]
    fn the_checks_run_in_order_schema_then_capability_then_lease_then_capture() {
        let (world, capture) = World::ready(SESSION);

        // Ungranted and malformed: schema wins.
        assert_eq!(
            plan(b"not json", 4096, &BTreeSet::new(), &world.context(SESSION)),
            Err(Dispatch::NotDispatched(NotDispatched::Schema(
                SchemaError::Json(crate::json::JsonError::NotAnObject)
            )))
        );
        // Well-formed and ungranted: capability refuses.
        assert_eq!(
            plan(
                &body("capture", json!({})),
                4096,
                &BTreeSet::new(),
                &world.context(SESSION)
            ),
            Err(Dispatch::NotDispatched(NotDispatched::NotPermitted))
        );
        // Granted, but the operation is deferred: the schema refuses before
        // the capability set is consulted, so a granted set cannot admit it.
        assert_eq!(
            world.plan(SESSION, "accessibility_tree", json!({})),
            Err(Dispatch::NotDispatched(NotDispatched::Schema(
                SchemaError::Operation(Refusal::Deferred(Deferral::NeedsBackendProbe))
            )))
        );
        // Granted and well-formed, but a malformed body still loses to the
        // schema even for an input operation whose lease is missing.
        let no_lease = World::new();
        assert_eq!(
            no_lease.plan(SESSION, "click", json!({"capture": 1})),
            Err(Dispatch::NotDispatched(NotDispatched::Schema(
                SchemaError::MissingMember { name: "x" }
            ))),
            "the schema runs before the lease"
        );
        // **Lease before capture.** This body names a capture that does not
        // exist *and* the session holds no lease. The lease must be the
        // refusal reported.
        assert_eq!(
            no_lease.plan(SESSION, "click", json!({"capture": 999, "x": 0, "y": 0})),
            lease_refusal(LeaseRefusal::NotHeld)
        );
        // And with the lease held, the same body reports the capture -- so the
        // assertion above is an ordering, not a blanket lease answer.
        assert_eq!(
            world.plan(SESSION, "click", json!({"capture": 999, "x": 0, "y": 0})),
            capture_refusal(CaptureRefusal::Unknown)
        );
        // Sanity: with both in place it plans.
        assert!(
            world
                .plan(
                    SESSION,
                    "click",
                    json!({"capture": capture.value(), "x": 0, "y": 0})
                )
                .is_ok()
        );
    }

    /// **Reads are shared; input is not.** A second session captures freely
    /// against a device whose input lease is held by somebody else, and is
    /// refused for every operation that acts.
    #[test]
    fn a_second_session_may_read_but_may_not_act() {
        let (world, capture) = World::ready(SESSION);

        for read in ["describe", "capture", "screen_info", "cursor_position"] {
            assert!(
                world.plan(OTHER, read, json!({})).is_ok(),
                "{read} must not be gated by the input lease"
            );
        }
        for (operation, params) in [
            ("click", json!({"capture": capture.value(), "x": 0, "y": 0})),
            (
                "double_click",
                json!({"capture": capture.value(), "x": 0, "y": 0}),
            ),
            ("move", json!({"capture": capture.value(), "x": 0, "y": 0})),
            (
                "drag",
                json!({"capture": capture.value(), "x": 0, "y": 0, "to_x": 1, "to_y": 1}),
            ),
            (
                "scroll",
                json!({"capture": capture.value(), "x": 0, "y": 0, "dx": 0, "dy": 1}),
            ),
            ("type_text", json!({"text": "x"})),
            ("press_key", json!({"key": "a"})),
            ("hotkey", json!({"keys": ["a"]})),
        ] {
            assert_eq!(
                world.plan(OTHER, operation, params),
                lease_refusal(LeaseRefusal::HeldByAnotherSession),
                "{operation} must be refused to a session without the lease"
            );
        }
    }

    /// A drag is bounds-checked at **both** ends.
    #[test]
    fn a_drag_that_ends_outside_the_capture_is_refused() {
        let (world, capture) = World::ready(SESSION);
        let c = capture.value();
        assert!(
            world
                .plan(
                    SESSION,
                    "drag",
                    json!({"capture": c, "x": 0, "y": 0, "to_x": 127, "to_y": 95})
                )
                .is_ok()
        );
        assert_eq!(
            world.plan(
                SESSION,
                "drag",
                json!({"capture": c, "x": 0, "y": 0, "to_x": 128, "to_y": 0})
            ),
            capture_refusal(CaptureRefusal::OutsideCapture),
            "the end point is outside a 128x96 capture"
        );
        assert_eq!(
            world.plan(
                SESSION,
                "drag",
                json!({"capture": c, "x": 128, "y": 0, "to_x": 0, "to_y": 0})
            ),
            capture_refusal(CaptureRefusal::OutsideCapture),
            "and so is the start point"
        );
    }

    /// A stale capture is refused for every coordinate operation, and the
    /// current one is not.
    #[test]
    fn a_superseded_capture_refuses_every_coordinate_operation() {
        let (mut world, stale) = World::ready(SESSION);
        let fresh = world
            .captures
            .record(&world.target, 0, 128, 96, IDENTITY_SCALE_PERCENT)
            .unwrap()
            .id();

        for operation in ["click", "double_click", "move"] {
            assert_eq!(
                world.plan(
                    SESSION,
                    operation,
                    json!({"capture": stale.value(), "x": 0, "y": 0})
                ),
                capture_refusal(CaptureRefusal::Superseded),
                "{operation} on a stale capture"
            );
            assert!(
                world
                    .plan(
                        SESSION,
                        operation,
                        json!({"capture": fresh.value(), "x": 0, "y": 0})
                    )
                    .is_ok(),
                "{operation} on the current capture"
            );
        }
    }

    /// The keyboard operations need the lease and **no** capture, which is why
    /// `needs_capture_identity` is a second predicate.
    #[test]
    fn keyboard_operations_need_the_lease_and_no_capture() {
        let mut world = World::new();
        world
            .leases
            .acquire(&world.target, SESSION, REVISION)
            .unwrap();
        assert!(world.captures.is_empty(), "no capture has been issued");

        assert!(
            world
                .plan(SESSION, "type_text", json!({"text": "hello"}))
                .is_ok()
        );
        assert!(
            world
                .plan(SESSION, "press_key", json!({"key": "Return"}))
                .is_ok()
        );
        assert!(
            world
                .plan(SESSION, "hotkey", json!({"keys": ["cmd", "c"]}))
                .is_ok()
        );
        // But a coordinate operation is refused, so the three above are not
        // passing because the capture check is switched off.
        assert_eq!(
            world.plan(SESSION, "click", json!({"capture": 1, "x": 0, "y": 0})),
            capture_refusal(CaptureRefusal::Unknown)
        );
    }

    /// A revoked grant refuses the holder at the point of use. Nothing is
    /// dispatched. See `crate::lease` for the half that stays open.
    #[test]
    fn a_superseded_grant_revision_refuses_an_input_operation() {
        let (world, capture) = World::ready(SESSION);
        let context = SessionContext {
            session: SESSION,
            target: &world.target,
            grant_revision: GrantRevision::new(1),
            leases: &world.leases,
            captures: &world.captures,
        };
        assert_eq!(
            plan(
                &body("click", json!({"capture": capture.value(), "x": 0, "y": 0})),
                4096,
                &all(),
                &context
            ),
            lease_refusal(LeaseRefusal::GrantRevoked)
        );
        // A read from the same revoked session still works: the lease is not
        // consulted for reads, and revocation is the relay's to enforce there.
        assert!(
            plan(&body("capture", json!({})), 4096, &all(), &context).is_ok(),
            "reads are not gated by the lease"
        );
    }

    /// Every refusal the planner can produce is a `NotDispatched`.
    #[test]
    fn every_planner_refusal_is_not_dispatched() {
        let (world, capture) = World::ready(SESSION);
        let c = capture.value();
        for (operation, params) in [
            ("capture", json!({"display": 999})),
            ("clcik", json!({})),
            ("capture", json!({"quality": 90})),
            ("click", json!({"capture": c, "x": 1000, "y": 0})),
            ("click", json!({"capture": 404, "x": 0, "y": 0})),
            (
                "click",
                json!({"capture": c, "x": 0, "y": 0, "button": "middle"}),
            ),
            ("type_text", json!({"text": ""})),
            ("press_key", json!({"key": "a b"})),
            ("hotkey", json!({"keys": []})),
            (
                "scroll",
                json!({"capture": c, "x": 0, "y": 0, "dx": 99999, "dy": 0}),
            ),
        ] {
            match world.plan(SESSION, operation, params.clone()) {
                Err(Dispatch::NotDispatched(_)) => {}
                other => panic!("expected a NotDispatched for {operation} {params}, got {other:?}"),
            }
        }
        for body in [b"".to_vec(), b"[]".to_vec()] {
            match plan(&body, 4096, &all(), &world.context(SESSION)) {
                Err(Dispatch::NotDispatched(_)) => {}
                other => panic!("expected a NotDispatched, got {other:?}"),
            }
        }
    }

    /// The discovery entry point cannot be used to send an arbitrary command.
    #[test]
    fn discovery_admits_only_the_commands_describe_reads() {
        assert_eq!(
            discovery_payload("version").unwrap(),
            json!({"command": "version", "params": {}})
        );
        for refused in [
            "screenshot",
            "left_click",
            "run_command",
            "get_screen_size",
            "type_text",
            "",
        ] {
            assert!(
                discovery_payload(refused).is_err(),
                "{refused} must not be reachable through discovery"
            );
        }
        // Non-vacuity: the allowed set really is read from the operation table.
        assert_eq!(Operation::DESCRIBE_READS, &["version"]);
    }

    /// **Nothing a planner produces carries the typed text into a diagnostic.**
    ///
    /// `Planned` derives `Debug` and its payload is a `serde_json::Value`, so
    /// the *payload* necessarily holds the text -- that is the request body.
    /// What must never happen is the text reaching a log through the validated
    /// parameters, which is the value a facade would naturally format.
    #[test]
    fn the_validated_parameters_never_render_the_typed_text() {
        let request =
            schema::validate_request(&body("type_text", json!({"text": "hunter2"})), 4096).unwrap();
        let rendered = format!("{request:?}");
        assert!(
            !rendered.contains("hunter2"),
            "the request Debug leaked the typed text: {rendered}"
        );
        assert!(rendered.contains("redacted"), "{rendered}");

        let key =
            schema::validate_request(&body("press_key", json!({"key": "F13"})), 4096).unwrap();
        assert!(!format!("{key:?}").contains("F13"));
    }
}
