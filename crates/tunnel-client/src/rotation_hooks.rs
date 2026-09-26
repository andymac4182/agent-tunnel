//! Test-only rotation holds (task row M6-06), compiled only with the
//! `test-hooks` feature.
//!
//! The shutdown gate (`crates/tunnel-relay/tests/m6_shutdown_phases_process.rs`)
//! must stop the client and the relay while a data rotation is **in** a given
//! phase, and a rotation passes through most phases in milliseconds. So a
//! `test-hooks` build reads `TUNNEL_CLIENT_TEST_HOLD`, a comma-separated list
//! of inbound control message kinds (`ROTATE_QUIESCE`, `ROTATE_FROZEN`, ...)
//! the connector drops unprocessed, plus `candidate-dial`, which withholds the
//! rotation's candidate data socket. Both state machines then wait at that
//! step until the overlap deadline, which is what makes a phase pinnable.
//!
//! **The shipped binary has none of this.** Without the feature `holds` is a
//! constant `false` and the variable is never read, so no environment value
//! can change a production connector's protocol behaviour. Every hold that
//! fires prints one stderr line naming the kind, so a run can show it engaged.

// M6-06 review: the hook must never reach a shipped build. Release builds
// turn `debug_assertions` off, so a release build with the feature is refused
// at compile time; `scripts/m6-release-artifact.py`'s `cli` check also scans
// every bundled binary for the variable's name.
#[cfg(all(feature = "test-hooks", not(debug_assertions)))]
compile_error!(
    "the `test-hooks` feature is for debug test builds only; never build a release with it"
);

#[cfg(feature = "test-hooks")]
mod enabled {
    use std::{
        collections::BTreeSet,
        sync::{Mutex, OnceLock},
    };

    fn configured() -> &'static BTreeSet<String> {
        static HOLDS: OnceLock<BTreeSet<String>> = OnceLock::new();
        HOLDS.get_or_init(|| {
            std::env::var("TUNNEL_CLIENT_TEST_HOLD")
                .unwrap_or_default()
                .split(',')
                .map(str::trim)
                .filter(|kind| !kind.is_empty())
                .map(str::to_owned)
                .collect()
        })
    }

    /// Whether this step is held; reports each held kind once.
    pub(crate) fn holds(kind: &str) -> bool {
        if !configured().contains(kind) {
            return false;
        }
        static REPORTED: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());
        if let Ok(mut reported) = REPORTED.lock()
            && reported.insert(kind.to_owned())
        {
            eprintln!("tunnel-client: test hook holding {kind}");
        }
        true
    }
}

#[cfg(feature = "test-hooks")]
pub(crate) use enabled::holds;

/// Without the `test-hooks` feature nothing is ever held.
#[cfg(not(feature = "test-hooks"))]
#[inline]
pub(crate) fn holds(_kind: &str) -> bool {
    false
}
