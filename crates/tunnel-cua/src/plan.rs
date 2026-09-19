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
//! calls it. There is deliberately **no way to reach the backend without a
//! [`Planned`]**, and `Planned` has no public constructor.
//!
//! ```text
//!   body --schema::validate_request--> Request      (nothing sent)
//!        --negotiated capability set -> permitted   (nothing sent)
//!        --operation -> upstream command or local   (nothing sent)
//!   ===================== dispatch boundary =====================
//!   Planned::Dispatch(command, payload)  -- the caller may now send
//!   Planned::AnswerLocally               -- the caller must NOT send
//! ```
//!
//! The endpoint check is not a step here because it is not a step anywhere: a
//! [`crate::endpoint::BackendEndpoint`] cannot be constructed from a
//! non-loopback address, so a dispatcher that holds one has already passed it.

use std::collections::BTreeSet;

use serde_json::{Value, json};

use crate::Operation;
use crate::outcome::{Dispatch, NotDispatched};
use crate::schema::{self, Params};

/// What the caller should do next, once every pre-dispatch check has passed.
///
/// No public constructor: the only way to obtain one is [`plan`], so a value
/// of this type is the evidence that the sequence ran in order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Planned {
    /// Send this command with this payload to the backend.
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
    AnswerLocally { operation: Operation },
}

/// Run every pre-dispatch check, in order.
///
/// # Errors
/// A [`Dispatch::NotDispatched`] naming the first check that refused. Every
/// one of them means the backend was never contacted.
pub fn plan(body: &[u8], limit: u64, permitted: &BTreeSet<Operation>) -> Result<Planned, Dispatch> {
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

    // 3. The operation's upstream mapping. `describe` has none: it is answered
    //    from the negotiated set, which is the only honest thing it could be
    //    answered from -- a config echo would be the trap.
    let Some(command) = operation.upstream_command() else {
        return Ok(Planned::AnswerLocally { operation });
    };

    Ok(Planned::Dispatch {
        command,
        payload: command_payload(command, request.params()),
        operation,
    })
}

/// The `/cmd` request body for one validated operation.
#[must_use]
pub fn command_payload(command: &str, params: &Params) -> Value {
    match params {
        Params::Capture { display } | Params::ScreenInfo { display } => {
            json!({"command": command, "params": {"display": display}})
        }
        Params::Describe | Params::CursorPosition => {
            json!({"command": command, "params": {}})
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
    use crate::operation::{Deferral, Refusal};
    use crate::schema::SchemaError;

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

    #[test]
    fn a_dispatching_operation_plans_its_canonical_command_and_payload() {
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
            let planned = plan(&body(operation, params), 4096, &all()).unwrap();
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

    /// `describe` never becomes a dispatch. This is the ordering half of the
    /// fix for the review's first finding: the planner refuses to hand a
    /// caller anything sendable for it.
    #[test]
    fn describe_plans_a_local_answer_and_never_a_command() {
        assert_eq!(
            plan(&body("describe", json!({})), 4096, &all()).unwrap(),
            Planned::AnswerLocally {
                operation: Operation::Describe
            }
        );
        // And there is no command to send: the mapping itself is `None`.
        assert_eq!(Operation::Describe.upstream_command(), None);
    }

    /// Order matters, and this is the assertion that pins it: a body that is
    /// both unparseable *and* names an ungranted operation must report the
    /// schema failure, because the schema runs first.
    #[test]
    fn the_checks_run_in_order_schema_then_capability() {
        // Ungranted and malformed: schema wins.
        assert_eq!(
            plan(b"not json", 4096, &BTreeSet::new()),
            Err(Dispatch::NotDispatched(NotDispatched::Schema(
                SchemaError::Json(crate::json::JsonError::NotAnObject)
            )))
        );
        // Well-formed and ungranted: capability refuses.
        assert_eq!(
            plan(&body("capture", json!({})), 4096, &BTreeSet::new()),
            Err(Dispatch::NotDispatched(NotDispatched::NotPermitted))
        );
        // Well-formed, granted set irrelevant, operation deferred: the schema
        // refuses before the capability set is even consulted, so a granted
        // set cannot admit an input operation.
        assert_eq!(
            plan(&body("click", json!({})), 4096, &all()),
            Err(Dispatch::NotDispatched(NotDispatched::Schema(
                SchemaError::Operation(Refusal::Deferred(Deferral::SynthesisesInput))
            )))
        );
    }

    /// Every refusal the planner can produce is a `NotDispatched`. Nothing
    /// above the boundary may produce a `Completion`.
    #[test]
    fn every_planner_refusal_is_not_dispatched() {
        for body in [
            b"".to_vec(),
            b"[]".to_vec(),
            body("capture", json!({"display": 999})),
            body("clcik", json!({})),
            body("capture", json!({"quality": 90})),
        ] {
            match plan(&body, 4096, &all()) {
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
}
