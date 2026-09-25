#![forbid(unsafe_code)]
//! A deterministic synthetic CUA backend, bound to `127.0.0.1:0`, with an
//! **authoritative in-memory ledger** of everything it was asked to do.
//!
//! **No screen, no input device, no network beyond loopback, no real backend.**
//! `cua-computer-server` has still never been installed, imported or executed
//! in this repository. This fixture reproduces the wire shapes that
//! `tunnel_http_forward::cua_pin` recorded from the released 0.3.46 source —
//! `data: <JSON>\n\n` framing with `text/plain`, a 200 that can carry
//! `success: false`, unframed 400/401 `HTTPException`s, and the 503 that
//! `UNAVAILABLE_WITHOUT_CONTAINER_NAME` produces — so that
//! `tunnel_cua::outcome` can be exercised against them. **It is not evidence
//! that the real server behaves this way.** It is evidence that our classifier
//! behaves correctly if it does.
//!
//! # Why the ledger lives here and not in the harness
//!
//! `<scratchpad>/m5-scoping-and-decisions.md` names the defect: *a counter
//! that counts dispatches rather than effects*. A counter in the test harness
//! increments where the harness **believes** it dispatched, which proves only
//! what the harness believed. It cannot tell "the command happened once" from
//! "it happened twice and one attempt was not recorded", and that is the exact
//! question the fault-injection tests ask.
//!
//! So [`Ledger`] is written **by the server task, at the moment the command is
//! accepted**, and it is read back out afterwards. It is the authority; the
//! client's opinion is the thing under test.
//!
//! # Fault injection happens *after* the ledger entry exists
//!
//! The other named defect is *"unknown outcome" that is really "not
//! dispatched"*. Every [`Fault`] that simulates a lost answer records the
//! ledger entry **first** and then breaks the response, so a test can assert
//! both halves of the distinction against the same run:
//!
//! | Fault | Ledger entries | What the client must conclude |
//! | --- | --- | --- |
//! | [`Fault::None`] | 1 | dispatched, ok |
//! | [`Fault::SuccessFalse`] | 1 | dispatched, failed |
//! | [`Fault::TruncateAfterLedger`] | **1** | dispatched, **unknown** |
//! | [`Fault::DropAfterLedger`] | **1** | dispatched, **unknown** |
//! | [`Fault::HangAfterLedger`] | **1** | dispatched, **unknown** (once something ends it) |
//! | [`Fault::PreDispatchRejection`] | **0** | **not dispatched** |
//! | [`Fault::Unavailable`] | **0** | **not dispatched** |
//!
//! The two rows with zero entries and the three with one entry are what make
//! the distinction checkable rather than asserted.
//!
//! [`Fault::HangAfterLedger`] is chunk 4's addition and is the only one whose
//! outcome is decided by something **outside** this fixture: the exchange is
//! left outstanding, so a supervisor restarting the backend is what ends it.
//! That is what makes "the supervisor restarted a hung backend and the click
//! did not land twice" measurable, and it is why the ledger can carry a
//! **journal** -- a count that survives the restart is the only kind that can
//! answer the question.
//!
//! # The process helpers
//!
//! Chunk 4 also gives this crate a binary. `tunnel-cua-fixture backend` is the
//! supervised backend itself, publishing its loopback address and starting an
//! **in-group helper** -- the shape that makes a process-group kill worth
//! having, a worker that does not read stdin and has no way to notice the
//! supervisor going away. `detach-host` starts a descendant that deliberately
//! **leaves** the group, and `supervise` is a real supervisor in a process a
//! test can `SIGKILL`. `crates/tunnel-cua-fixture/tests/process_residue.rs`
//! is what reads the process table.
//!
//! # The click counter counts **effects**, not dispatches
//!
//! The other named trap is *a click counter that counts dispatches rather than
//! effects*. [`LedgerEntry::pointer_clicks`] is written from the command name
//! the fixture accepted, and `double_click` records **2**. So
//! [`Ledger::pointer_clicks`] and [`Ledger::len`] disagree for exactly the
//! command where a dispatch counter would be wrong, and
//! `crates/tunnel-cua-fixture/tests/input_lease.rs` uses that disagreement as
//! its control: one `double_click` exchange, one ledger entry, **two** clicks.
//! A counter the harness incremented could not produce that number.
//!
//! [`LedgerEntry::typed_characters`] is a count and never the text. **The
//! fixture does not store typed text anywhere**, which is why a test asserts
//! on lengths: `AGENTS.md` keeps keystrokes out of diagnostics, and an
//! in-memory ledger a panic message prints is a diagnostic.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub mod client;
pub mod process;

/// The backend's `/cmd` path, as the pin records it.
pub const CMD_PATH: &str = "/cmd";
/// The backend's command-listing path.
pub const COMMANDS_PATH: &str = "/commands";

/// The media type the released `/cmd` handler passes to `StreamingResponse`.
/// Not `text/event-stream` and not `application/json`.
pub const CMD_MEDIA_TYPE: &str = "text/plain";

/// The synthetic screen this fixture reports and captures.
pub const SCREEN_WIDTH: u16 = 128;
/// The synthetic screen height.
pub const SCREEN_HEIGHT: u16 = 96;
/// The marker seed for display 0 with unchanged content. A content change
/// (`CaptureScaleKnob::set_content`) adds its offset, so two captures either
/// side of it have identical length and entirely different markers.
pub const IMAGE_SEED: u32 = 0x5EED_0001;
/// The synthetic cursor position.
pub const CURSOR: (u32, u32) = (17, 23);
/// The version string this fixture reports.
pub const FIXTURE_VERSION: &str = "0.3.46-synthetic";
/// The longest a [`Fault::HangAfterLedger`] exchange is held open.
///
/// Finite so a fixture process nobody restarts still exits. Long enough that
/// no test could mistake the timeout for the restart: a hang that ended on
/// its own inside a test would make the restart look like the cause of an
/// outcome it did not produce.
pub const HANG_LIFETIME: std::time::Duration = std::time::Duration::from_secs(300);

/// One thing the backend was asked to do, recorded at the moment it was
/// accepted — **before** any fault is applied.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LedgerEntry {
    /// The canonical command name as it arrived.
    pub command: String,
    /// The `display` parameter, when the command carried one.
    pub display: Option<u32>,
    /// The `x`/`y` the command arrived with, in the **backend's** coordinate
    /// space. This is what makes the display-scale carry-forward measurable
    /// end to end rather than only in a unit test: the device converts, and
    /// this records what actually arrived.
    pub point: Option<(u32, u32)>,
    /// How many pointer clicks this command **performs** — not how many
    /// commands were sent. `double_click` is 2.
    pub pointer_clicks: u32,
    /// How many characters this command typed. A count, never the text.
    pub typed_characters: usize,
}

impl LedgerEntry {
    #[must_use]
    pub fn new(command: &str, display: Option<u32>) -> Self {
        Self {
            command: command.to_owned(),
            display,
            point: None,
            pointer_clicks: pointer_clicks_for(command),
            typed_characters: 0,
        }
    }

    #[must_use]
    pub const fn with_point(mut self, point: Option<(u32, u32)>) -> Self {
        self.point = point;
        self
    }

    #[must_use]
    pub const fn with_typed_characters(mut self, characters: usize) -> Self {
        self.typed_characters = characters;
        self
    }
}

/// How many clicks one backend command performs.
///
/// **Read from the command name, at the fixture, at the moment the command is
/// accepted.** A `double_click` is two clicks delivered by one command, which
/// is precisely the case a counter of dispatches gets wrong.
#[must_use]
pub fn pointer_clicks_for(command: &str) -> u32 {
    match command {
        "left_click" | "right_click" => 1,
        "double_click" => 2,
        _ => 0,
    }
}

/// The authoritative record of what the backend was asked to do.
///
/// # The journal, and why a supervised restart needs one
///
/// An in-memory ledger dies with the backend process. That is fine for every
/// test that does not restart one, and **useless for the test that matters
/// most in chunk 4**: "the supervisor restarted a hung backend and the click
/// did not land twice" is a claim about a count that spans two backend
/// processes. A fresh in-memory ledger after a restart reads zero, so the
/// count would trivially not have increased and the measurement would be of
/// nothing at all.
///
/// So a ledger can be given a **journal**: an append-only file, written by
/// the backend process at the same moment the in-memory entry is recorded —
/// which is **before** any fault is applied, exactly as the in-memory record
/// is. [`Ledger::journal_entries`] reads it back, so a test counts effects
/// across every generation of the backend rather than only the surviving one.
///
/// It stores a **count** of typed characters and never the text, like the
/// in-memory entry, because a file on disk is at least as much of a
/// diagnostic as a panic message.
#[derive(Clone, Debug, Default)]
pub struct Ledger {
    entries: Arc<Mutex<Vec<LedgerEntry>>>,
    journal: Option<Arc<std::path::PathBuf>>,
}

impl Ledger {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A ledger that also appends every entry to `journal`.
    #[must_use]
    pub fn with_journal(journal: std::path::PathBuf) -> Self {
        Self {
            entries: Arc::default(),
            journal: Some(Arc::new(journal)),
        }
    }

    fn record(&self, entry: LedgerEntry) {
        // The journal is written **first**. If the process is killed between
        // the two, the durable record over-reports rather than under-reports,
        // and over-reporting is the safe direction for a count whose job is to
        // catch a duplicated effect.
        self.append(&entry);
        self.entries
            .lock()
            .expect("the ledger mutex is never poisoned by fixture code")
            .push(entry);
    }

    fn append(&self, entry: &LedgerEntry) {
        use std::io::Write as _;
        let Some(journal) = &self.journal else { return };
        let (x, y) = match entry.point {
            Some((x, y)) => (x.to_string(), y.to_string()),
            None => ("-".to_owned(), "-".to_owned()),
        };
        let display = entry
            .display
            .map_or_else(|| "-".to_owned(), |value| value.to_string());
        let line = format!(
            "{}\t{display}\t{x}\t{y}\t{}\t{}\n",
            entry.command, entry.pointer_clicks, entry.typed_characters
        );
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(journal.as_path())
        {
            let _ = file.write_all(line.as_bytes());
            let _ = file.flush();
        }
    }

    /// Read a journal back, in order.
    ///
    /// A missing file is an empty journal: a backend that was never started
    /// recorded nothing, which is a real answer rather than an error.
    ///
    /// # Panics
    /// If a line in the journal is malformed. That is the fixture writing
    /// something it cannot read, which must never be silently skipped: a
    /// dropped line is a missed effect, and a missed effect is precisely the
    /// defect this journal exists to catch.
    #[must_use]
    pub fn journal_entries(journal: &std::path::Path) -> Vec<LedgerEntry> {
        let text = std::fs::read_to_string(journal).unwrap_or_default();
        text.lines()
            .filter(|line| !line.is_empty())
            .map(|line| {
                let fields: Vec<&str> = line.split('\t').collect();
                assert_eq!(fields.len(), 6, "malformed journal line: {line:?}");
                let number = |field: &str| field.parse::<u32>().ok();
                LedgerEntry {
                    command: fields[0].to_owned(),
                    display: number(fields[1]),
                    point: number(fields[2]).zip(number(fields[3])),
                    pointer_clicks: number(fields[4])
                        .expect("the journal always writes a click count"),
                    typed_characters: fields[5]
                        .parse()
                        .expect("the journal always writes a typed-character count"),
                }
            })
            .collect()
    }

    /// **How many pointer clicks every generation of this backend performed**,
    /// read from a journal rather than from memory.
    ///
    /// The cross-restart answer to "did the click happen once?".
    #[must_use]
    pub fn journal_pointer_clicks(journal: &std::path::Path) -> u32 {
        Self::journal_entries(journal)
            .iter()
            .map(|entry| entry.pointer_clicks)
            .sum()
    }

    /// Every entry, in order.
    #[must_use]
    pub fn entries(&self) -> Vec<LedgerEntry> {
        self.entries
            .lock()
            .expect("the ledger mutex is never poisoned by fixture code")
            .clone()
    }

    /// How many times `command` was accepted.
    ///
    /// Counts **what the fixture saw**, never what a caller believes it sent.
    #[must_use]
    pub fn count(&self, command: &str) -> usize {
        self.entries()
            .iter()
            .filter(|entry| entry.command == command)
            .count()
    }

    /// Total entries — **the number of commands accepted**, which is
    /// deliberately not the number of clicks performed.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries().len()
    }

    /// **How many pointer clicks this backend actually performed.**
    ///
    /// The answer to "did the click happen once?". It is not
    /// [`Ledger::len`] and it is not a count of `left_click` entries: one
    /// `double_click` command contributes 2, so a harness that counted its own
    /// dispatches would report 1 where this reports 2.
    #[must_use]
    pub fn pointer_clicks(&self) -> u32 {
        self.entries()
            .iter()
            .map(|entry| entry.pointer_clicks)
            .sum()
    }

    /// How many characters were typed. A count; the text is never stored.
    #[must_use]
    pub fn typed_characters(&self) -> usize {
        self.entries()
            .iter()
            .map(|entry| entry.typed_characters)
            .sum()
    }

    /// The backend coordinates of every command that carried them, in order.
    #[must_use]
    pub fn points(&self) -> Vec<(u32, u32)> {
        self.entries()
            .iter()
            .filter_map(|entry| entry.point)
            .collect()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A pathological behaviour the fixture can be told to perform for one
/// command name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Fault {
    /// Behave correctly.
    None,
    /// Record the ledger entry, then answer 200 with framed `success: false`.
    /// The trap: a classifier reading the status calls this a success.
    SuccessFalse,
    /// Record the ledger entry, then answer 200 with a `data: ` prefix and no
    /// terminator. The command **was** dispatched; the answer is lost.
    TruncateAfterLedger,
    /// Record the ledger entry, then close the connection with no response at
    /// all. Dispatched, and the outcome is unknown.
    DropAfterLedger,
    /// Answer a pre-dispatch `HTTPException` — a real 400 or 401 with **no**
    /// `data:` framing — and record **nothing**. Never dispatched.
    PreDispatchRejection { status: u16 },
    /// Answer 503, as `UNAVAILABLE_WITHOUT_CONTAINER_NAME` does, and record
    /// nothing. Deliberately unavailable, never dispatched.
    Unavailable,
    /// Record the ledger entry, then answer 200 with a framed payload that has
    /// **no `success` member at all**. Absent is not true.
    SuccessAbsent,
    /// Record the ledger entry, then **answer nothing and hold the connection
    /// open** until [`HANG_LIFETIME`] expires.
    ///
    /// The hung backend a supervisor exists to restart. It is deliberately
    /// different from [`Fault::DropAfterLedger`]: that one ends the exchange
    /// itself, so the outcome is decided before any supervisor could act. This
    /// one leaves the exchange outstanding, so a restart is what ends it, and
    /// the effect the backend already performed is recorded in the journal
    /// before the restart happens. That ordering is the whole point -- a fault
    /// injected before the ledger entry would make "the effect happened once"
    /// unmeasurable.
    ///
    /// The lifetime is bounded so a fixture process that nobody restarts still
    /// exits: an unbounded hang would leave a process behind on every failed
    /// test run.
    HangAfterLedger,
    /// Record the ledger entry, then answer 200 with a framed payload that
    /// **looks like a successful capture** but whose `success` is `false` —
    /// the `{"success": True, **result}` shape the pin records, after the
    /// merge.
    ///
    /// **This cannot be byte-distinct from [`Fault::SuccessFalse`] in the way
    /// that matters, and the first review was right to say so.** The envelope
    /// merge happens inside the *server*: by the time anything reaches a
    /// socket there is exactly one `success` member, and a client cannot tell
    /// an overriding handler result from a plain failure. That is the whole
    /// hazard — there is no wire signal to key on — so the fault differs in
    /// the only way it can, by carrying a success-shaped payload (`image`,
    /// dimensions, no `error`) instead of an error string. What the test
    /// built on it shows is narrower than "the override is detected": it is
    /// that a payload which reads as a success in every other respect is still
    /// classified as a failure on the strength of `success` alone.
    ResultOverridesEnvelope,
}

/// What the fixture answers, per command name.
#[derive(Clone, Debug, Default)]
pub struct Faults {
    by_command: Arc<Mutex<HashMap<String, Fault>>>,
}

impl Faults {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Make `command` behave pathologically. Applies to every later request
    /// for that command until changed.
    pub fn set(&self, command: &str, fault: Fault) {
        self.by_command
            .lock()
            .expect("the fault mutex is never poisoned by fixture code")
            .insert(command.to_owned(), fault);
    }

    fn get(&self, command: &str) -> Fault {
        self.by_command
            .lock()
            .expect("the fault mutex is never poisoned by fixture code")
            .get(command)
            .copied()
            .unwrap_or(Fault::None)
    }
}

/// The command names this fixture registers.
///
/// Deliberately a **superset** of what `computer.v1` dispatches in this
/// chunk, including the input commands, so that "the profile refuses an input
/// operation" is a statement about the profile rather than about the fixture
/// being unable to answer. A fixture that simply had no `left_click` would
/// make the allowlist test vacuous.
pub const REGISTERED_COMMANDS: &[&str] = &[
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
];

/// What the fixture's `version` response says about capture authority.
///
/// **`None` is the default, and it is the faithful one.** The released 0.3.46
/// server made `desktop_capture_authorized` conditional on `hasattr`, so on
/// the supported 0.22.x SDK it **omits the key entirely**. A fixture that
/// emitted `false` by default would make every absent-is-not-denied test
/// vacuous.
///
/// `Some(false)` exists so the `Denied` arm of
/// [`tunnel_cua::capability::CaptureAuthority`] can be exercised at all. No
/// real backend has been observed emitting it here; task row M5-C03 records
/// that arm as **modelled, not measured**.
#[derive(Clone, Debug, Default)]
pub struct CaptureAuthorityKnob {
    value: Arc<Mutex<Option<bool>>>,
}

impl CaptureAuthorityKnob {
    /// Emit `desktop_capture_authorized` with this value, or omit the key
    /// entirely for `None`.
    pub fn set(&self, value: Option<bool>) {
        *self
            .value
            .lock()
            .expect("the knob mutex is never poisoned by fixture code") = value;
    }

    fn get(&self) -> Option<bool> {
        *self
            .value
            .lock()
            .expect("the knob mutex is never poisoned by fixture code")
    }
}

/// What scale this fixture's `screenshot` reports, and therefore how large
/// the image it returns is.
///
/// **It exists so the display-scale carry-forward is exercised at a value
/// where it is not the identity.** At 100 the conversion from capture pixels
/// to backend points is `x -> x`, so a test that only ever ran at 100 could
/// not tell a device that applies the scale from one that forwards the pixel
/// unchanged. At 200 the fixture serves a 256x192 image of its 128x96 screen,
/// and a click at pixel (100, 80) must arrive at (50, 40).
///
/// **The scale is not on the wire, and that is the point of M5-C14.** No
/// pinned backend reports a scale, so the fixture no longer does either: at
/// 200 it serves a 256x192 PNG and says nothing else, exactly as a real 2x
/// display would. A device that assumed 1x would click at (100, 80); the
/// device must be *told* the scale (`DeviceState::declare_scale_percent`) or
/// refuse the coordinate.
///
/// It also carries the screen's **content**: a seed offset, so a test can
/// change what is on the screen without changing its geometry. That is what
/// the proof-4 control uses since M5-C12 made a second display unreachable.
#[derive(Clone, Debug)]
pub struct CaptureScaleKnob {
    percent: Arc<Mutex<u32>>,
    content: Arc<Mutex<u32>>,
}

impl Default for CaptureScaleKnob {
    fn default() -> Self {
        Self {
            percent: Arc::new(Mutex::new(tunnel_cua::capture::IDENTITY_SCALE_PERCENT)),
            content: Arc::new(Mutex::new(0)),
        }
    }
}

impl CaptureScaleKnob {
    /// Serve captures at this scale, as a percentage. 100 is 1x.
    pub fn set(&self, percent: u32) {
        *self
            .percent
            .lock()
            .expect("the knob mutex is never poisoned by fixture code") = percent;
    }

    /// Change what is on the synthetic screen: later captures are seeded with
    /// `IMAGE_SEED + display + offset`. Geometry is unchanged, so two captures
    /// either side of a change have identical length and different markers.
    pub fn set_content(&self, offset: u32) {
        *self
            .content
            .lock()
            .expect("the knob mutex is never poisoned by fixture code") = offset;
    }

    fn get(&self) -> u32 {
        *self
            .percent
            .lock()
            .expect("the knob mutex is never poisoned by fixture code")
    }

    fn content(&self) -> u32 {
        *self
            .content
            .lock()
            .expect("the knob mutex is never poisoned by fixture code")
    }
}

/// A running fixture backend.
pub struct FixtureBackend {
    address: SocketAddr,
    ledger: Ledger,
    faults: Faults,
    capture_authority: CaptureAuthorityKnob,
    capture_scale: CaptureScaleKnob,
    handle: tokio::task::JoinHandle<()>,
}

impl FixtureBackend {
    /// Bind to `127.0.0.1:0` and start serving.
    ///
    /// Loopback and an ephemeral port are not configurable: there is no
    /// argument that could bind this anywhere else, so a test cannot
    /// accidentally publish it.
    ///
    /// # Errors
    /// If the loopback bind fails.
    pub async fn start() -> std::io::Result<Self> {
        Self::start_with(Ledger::new()).await
    }

    /// Bind to `127.0.0.1:0` and start serving, recording into `ledger`.
    ///
    /// Used by the supervised `backend` mode, whose ledger carries a journal
    /// so effects can be counted across a restart.
    ///
    /// # Errors
    /// If the loopback bind fails.
    pub async fn start_with(ledger: Ledger) -> std::io::Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let address = listener.local_addr()?;
        let faults = Faults::new();
        let capture_authority = CaptureAuthorityKnob::default();
        let capture_scale = CaptureScaleKnob::default();
        let handle = tokio::spawn(serve(
            listener,
            ledger.clone(),
            faults.clone(),
            capture_authority.clone(),
            capture_scale.clone(),
        ));
        Ok(Self {
            address,
            ledger,
            faults,
            capture_authority,
            capture_scale,
            handle,
        })
    }

    #[must_use]
    pub const fn address(&self) -> SocketAddr {
        self.address
    }

    /// The authoritative record of what this backend was asked to do.
    #[must_use]
    pub const fn ledger(&self) -> &Ledger {
        &self.ledger
    }

    #[must_use]
    pub const fn faults(&self) -> &Faults {
        &self.faults
    }

    /// What this backend's `version` response says about capture authority.
    #[must_use]
    pub const fn capture_authority(&self) -> &CaptureAuthorityKnob {
        &self.capture_authority
    }

    /// What scale this backend's captures report.
    #[must_use]
    pub const fn capture_scale(&self) -> &CaptureScaleKnob {
        &self.capture_scale
    }

    /// Stop serving.
    pub fn stop(self) {
        self.handle.abort();
    }
}

async fn serve(
    listener: TcpListener,
    ledger: Ledger,
    faults: Faults,
    capture_authority: CaptureAuthorityKnob,
    capture_scale: CaptureScaleKnob,
) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        let ledger = ledger.clone();
        let faults = faults.clone();
        let capture_authority = capture_authority.clone();
        let capture_scale = capture_scale.clone();
        tokio::spawn(async move {
            let _ =
                handle_connection(stream, ledger, faults, capture_authority, capture_scale).await;
        });
    }
}

/// One HTTP/1.1 exchange, hand-written so the pathological answers are
/// expressible.
async fn handle_connection(
    mut stream: TcpStream,
    ledger: Ledger,
    faults: Faults,
    capture_authority: CaptureAuthorityKnob,
    capture_scale: CaptureScaleKnob,
) -> std::io::Result<()> {
    let Some((path, body)) = read_request(&mut stream).await? else {
        return Ok(());
    };
    match path.as_str() {
        COMMANDS_PATH => {
            // **The released shape** (M5-C27): `commands` is an object keyed
            // by command name, each value carrying that command's `params`,
            // beside an `aliases` object -- measured on the pinned 0.3.46
            // server in the Linux guest (`probe-native.json`). This fixture
            // used to send a bare array, which the released server never
            // does, so a device reading only arrays negotiated nothing
            // against the real backend while every Lane A test passed.
            let commands: serde_json::Map<String, serde_json::Value> = REGISTERED_COMMANDS
                .iter()
                .map(|name| ((*name).to_owned(), json!({"params": []})))
                .collect();
            let listing = json!({"commands": commands, "aliases": {}});
            write_response(
                &mut stream,
                200,
                "application/json",
                listing.to_string().as_bytes(),
            )
            .await
        }
        CMD_PATH => {
            handle_cmd(
                &mut stream,
                &ledger,
                &faults,
                &capture_authority,
                &capture_scale,
                &body,
            )
            .await
        }
        _ => {
            write_response(
                &mut stream,
                404,
                "application/json",
                b"{\"detail\":\"Not Found\"}",
            )
            .await
        }
    }
}

async fn handle_cmd(
    stream: &mut TcpStream,
    ledger: &Ledger,
    faults: &Faults,
    capture_authority: &CaptureAuthorityKnob,
    capture_scale: &CaptureScaleKnob,
    body: &[u8],
) -> std::io::Result<()> {
    // Shape 3: a malformed body is a pre-dispatch `HTTPException`, unframed.
    let Ok(request) = serde_json::from_slice::<Value>(body) else {
        return unframed_error(stream, 400, "Invalid JSON body").await;
    };
    let Some(command) = request.get("command").and_then(Value::as_str) else {
        return unframed_error(stream, 400, "Missing command").await;
    };
    if !REGISTERED_COMMANDS.contains(&command) {
        // The released server raises this before dispatch too, which is why
        // it carries no framing.
        return unframed_error(stream, 400, "Unknown command").await;
    }
    let display = request
        .pointer("/params/display")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok());
    let coordinate = |name: &str| {
        request
            .pointer(&format!("/params/{name}"))
            .and_then(Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
    };
    // **`drag` carries a path, not a pair of named endpoints.** The released
    // signature is `drag(path: List[Tuple[int, int]], ...)` -- see
    // `tunnel_http_forward::cua_pin::COMMAND_PARAMETERS` -- so the point this
    // command acts at first is `path[0]`, and the old `start_x`/`start_y`
    // spelling would have been discarded by the real dispatcher without a
    // word. `scroll` deliberately has no point: upstream's `x`/`y` there are
    // wheel amounts, so a scroll records no coordinate at all.
    let path_start = || {
        let first = request.pointer("/params/path/0")?.as_array()?;
        let axis = |index: usize| {
            first
                .get(index)
                .and_then(Value::as_u64)
                .and_then(|value| u32::try_from(value).ok())
        };
        Some((axis(0)?, axis(1)?))
    };
    let point = match (coordinate("x"), coordinate("y")) {
        (Some(x), Some(y)) if command != "scroll" => Some((x, y)),
        _ => path_start(),
    };
    // A count, never the text. Nothing in this fixture stores typed text.
    let typed_characters = request
        .pointer("/params/text")
        .and_then(Value::as_str)
        .map_or(0, |text| text.chars().count());

    let fault = faults.get(command);

    // The two faults that mean "never dispatched" return **before** the ledger
    // entry. Everything below this line has an entry, which is the whole
    // mechanism by which a test can tell the two apart.
    match fault {
        Fault::PreDispatchRejection { status } => {
            return unframed_error(stream, status, "Rejected before dispatch").await;
        }
        Fault::Unavailable => {
            return unframed_error(stream, 503, "Service Unavailable").await;
        }
        _ => {}
    }

    ledger.record(
        LedgerEntry::new(command, display)
            .with_point(point)
            .with_typed_characters(typed_characters),
    );

    match fault {
        Fault::DropAfterLedger => {
            // No response at all. The command was dispatched; the answer is
            // gone. `shutdown` rather than a plain drop, so the client sees a
            // clean EOF rather than racing the socket close.
            stream.shutdown().await
        }
        Fault::TruncateAfterLedger => {
            // The prefix arrives and the terminator never does.
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\ndata: {\"success\": tr",
                )
                .await?;
            stream.shutdown().await
        }
        Fault::SuccessFalse => {
            framed(
                stream,
                json!({"success": false, "error": "synthetic failure"}),
            )
            .await
        }
        Fault::SuccessAbsent => framed(stream, json!({"width": SCREEN_WIDTH})).await,
        Fault::HangAfterLedger => {
            // The entry exists; the answer never comes. Whatever ends this
            // connection -- a supervisor killing the backend, or the bound
            // lifetime -- the command was already dispatched.
            tokio::time::sleep(HANG_LIFETIME).await;
            stream.shutdown().await
        }
        Fault::ResultOverridesEnvelope => {
            // `{"success": True, **result}` with a result carrying its own
            // `success`: on the wire there is one member, and it is the
            // handler's. Everything else here is success-shaped, so only
            // `success` distinguishes it.
            framed(
                stream,
                json!({
                    "success": false,
                    "image_data": encode_base64(&synthetic_png(
                        u32::from(SCREEN_WIDTH),
                        u32::from(SCREEN_HEIGHT),
                        &[],
                    )),
                    "format": tunnel_cua::image::PNG_FORMAT,
                }),
            )
            .await
        }
        Fault::None => {
            framed(
                stream,
                success_payload(
                    command,
                    display,
                    capture_authority.get(),
                    capture_scale.get(),
                    capture_scale.content(),
                ),
            )
            .await
        }
        Fault::PreDispatchRejection { .. } | Fault::Unavailable => unreachable!("returned above"),
    }
}

/// The successful result for each read-only command.
fn success_payload(
    command: &str,
    display: Option<u32>,
    capture_authority: Option<bool>,
    capture_scale: u32,
    content: u32,
) -> Value {
    let display = display.unwrap_or(0);
    match command {
        "version" => {
            // `desktop_capture_authorized` is **absent by default**, which is
            // what the released server does on the supported 0.22.x SDK.
            // Emitting it unconditionally would make every
            // absent-is-not-denied test vacuous.
            let mut payload = json!({
                "success": true,
                "version": FIXTURE_VERSION,
                "desktop_unlocked": true,
            });
            if let Some(authorized) = capture_authority
                && let Some(object) = payload.as_object_mut()
            {
                object.insert(
                    tunnel_cua::capability::CAPTURE_AUTHORITY_MEMBER.to_owned(),
                    Value::Bool(authorized),
                );
            }
            payload
        }
        // **The released shapes, member for member (M5-C14).** Every pinned
        // handler answers `get_screen_size` with `{"size": {"width",
        // "height"}}` and `get_cursor_position` with `{"position": {"x",
        // "y"}}`. The fixture used to flatten both, which no backend does.
        "get_screen_size" => json!({
            "success": true,
            "size": {"width": SCREEN_WIDTH, "height": SCREEN_HEIGHT},
        }),
        "get_cursor_position" => json!({
            "success": true,
            "position": {"x": CURSOR.0, "y": CURSOR.1},
        }),
        "screenshot" => {
            let seed = IMAGE_SEED.wrapping_add(display).wrapping_add(content);
            // The image is the screen at the reported scale, so `width` and
            // `height` are always the image's own pixel dimensions. A device
            // that read them as points would place every coordinate wrong on a
            // scaled display, which is the failure the carry-forward exists to
            // stop.
            let scale = u16::try_from(capture_scale / tunnel_cua::capture::IDENTITY_SCALE_PERCENT)
                .unwrap_or(1)
                .max(1);
            let width = SCREEN_WIDTH * scale;
            let height = SCREEN_HEIGHT * scale;
            let image = tunnel_cua::marker::encode(width, height, seed)
                .expect("the fixture's own dimensions are valid");
            // **The released shape, and nothing else (M5-C14).** macOS, Linux,
            // Windows and Android answer `{success, image_data, format}`:
            // base64 PNG bytes and the format name. There is no `width`, no
            // `height` and no scale -- this fixture used to send all three,
            // which is why a device reading them looked correct here and
            // issued no identity at all against a released backend.
            //
            // The PNG is a real container: signature, a valid `IHDR` with a
            // correct CRC (so the device reads the dimensions the way it must
            // from a real capture), the marker in a private ancillary chunk,
            // and `IEND`. It has no `IDAT`, so it is not a decodable picture
            // -- and a real capture has no marker chunk, so it fails proof 4.
            //
            // **The seed is deliberately not on the wire.** A test must know
            // what it asked for and derive the seed itself; see
            // `marker::verify`.
            json!({
                "success": true,
                "image_data": encode_base64(&synthetic_png(
                    u32::from(width),
                    u32::from(height),
                    &image,
                )),
                "format": tunnel_cua::image::PNG_FORMAT,
            })
        }
        // Every other registered command is an input command. The fixture
        // records it and answers, so that a test which *did* reach one would
        // see it in the ledger -- which is how "the profile never dispatches
        // an input command" is a measurement rather than an assumption.
        _ => json!({"success": true, "synthetic": command}),
    }
}

/// The private ancillary PNG chunk that carries the synthetic marker.
///
/// Lowercase first letter: ancillary, so a PNG reader may skip it. Lowercase
/// second: private. Uppercase third: the reserved bit, as the specification
/// requires. Lowercase fourth: safe to copy.
pub const MARKER_CHUNK: [u8; 4] = *b"tnMk";

/// Wrap a synthetic marker in a PNG container: signature, `IHDR` (8-bit RGB),
/// the marker in [`MARKER_CHUNK`], `IEND`. Every chunk carries a correct CRC.
#[must_use]
pub fn synthetic_png(width: u32, height: u32, marker: &[u8]) -> Vec<u8> {
    let mut png = tunnel_cua::image::PNG_SIGNATURE.to_vec();
    let mut ihdr = Vec::with_capacity(13);
    ihdr.extend_from_slice(&width.to_be_bytes());
    ihdr.extend_from_slice(&height.to_be_bytes());
    // Bit depth 8, colour type 2 (RGB), deflate, adaptive filtering, no
    // interlace.
    ihdr.extend_from_slice(&[8, 2, 0, 0, 0]);
    push_chunk(&mut png, *b"IHDR", &ihdr);
    push_chunk(&mut png, MARKER_CHUNK, marker);
    push_chunk(&mut png, *b"IEND", &[]);
    png
}

fn push_chunk(png: &mut Vec<u8>, kind: [u8; 4], data: &[u8]) {
    let length = u32::try_from(data.len()).expect("a synthetic chunk fits in u32");
    png.extend_from_slice(&length.to_be_bytes());
    let start = png.len();
    png.extend_from_slice(&kind);
    png.extend_from_slice(data);
    let crc = tunnel_cua::image::crc32(&png[start..]);
    png.extend_from_slice(&crc.to_be_bytes());
}

/// The marker a capture's `image_data` carries, or `None` if it is not a PNG
/// holding exactly one [`MARKER_CHUNK`] with a correct CRC.
///
/// A real capture fails here: it is a PNG with no marker chunk.
#[must_use]
pub fn marker_from_image_data(image_data: &str) -> Option<Vec<u8>> {
    let png = tunnel_cua::image::decode_base64(image_data)?;
    let mut rest = png.strip_prefix(&tunnel_cua::image::PNG_SIGNATURE[..])?;
    let mut found = None;
    while !rest.is_empty() {
        let length = usize::try_from(u32::from_be_bytes(rest.get(..4)?.try_into().ok()?)).ok()?;
        let kind = rest.get(4..8)?;
        let data = rest.get(8..8 + length)?;
        let crc = u32::from_be_bytes(rest.get(8 + length..12 + length)?.try_into().ok()?);
        if tunnel_cua::image::crc32(&rest[4..8 + length]) != crc {
            return None;
        }
        if kind == MARKER_CHUNK {
            if found.is_some() {
                return None;
            }
            found = Some(data.to_vec());
        }
        rest = &rest[12 + length..];
    }
    found
}

/// Standard base64 with padding, so the fixture emits `image_data` exactly as
/// the released handlers do (`base64.b64encode(...).decode()`).
#[must_use]
pub fn encode_base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for group in bytes.chunks(3) {
        let value = (u32::from(group[0]) << 16)
            | (u32::from(*group.get(1).unwrap_or(&0)) << 8)
            | u32::from(*group.get(2).unwrap_or(&0));
        for position in 0..4 {
            if position <= group.len() {
                let index = (value >> (18 - 6 * position)) & 0x3f;
                out.push(char::from(ALPHABET[index as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Write one `data: <JSON>\n\n` event under a 200, with `text/plain` — the
/// released shape.
async fn framed(stream: &mut TcpStream, payload: Value) -> std::io::Result<()> {
    let body = format!("data: {payload}\n\n");
    write_response(stream, 200, CMD_MEDIA_TYPE, body.as_bytes()).await
}

/// A real `HTTPException`: a JSON `detail` body with **no** `data:` framing.
async fn unframed_error(stream: &mut TcpStream, status: u16, detail: &str) -> std::io::Result<()> {
    let body = json!({"detail": detail}).to_string();
    write_response(stream, status, "application/json", body.as_bytes()).await
}

async fn write_response(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        503 => "Service Unavailable",
        _ => "Status",
    };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await?;
    stream.shutdown().await
}

/// The largest request this fixture will read, so a malformed one cannot grow
/// without bound.
const MAX_REQUEST: usize = 1 << 20;

/// Read one HTTP/1.1 request; return its path and body.
async fn read_request(stream: &mut TcpStream) -> std::io::Result<Option<(String, Vec<u8>)>> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        if let Some(index) = find(&buffer, b"\r\n\r\n") {
            break index;
        }
        if buffer.len() > MAX_REQUEST {
            return Ok(None);
        }
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Ok(None);
        }
        buffer.extend_from_slice(&chunk[..read]);
    };
    let head = String::from_utf8_lossy(&buffer[..header_end]).into_owned();
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let path = request_line
        .split_whitespace()
        .nth(1)
        .unwrap_or("/")
        .split('?')
        .next()
        .unwrap_or("/")
        .to_owned();
    let length: usize = lines
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().ok())?
        })
        .unwrap_or(0);
    if length > MAX_REQUEST {
        return Ok(None);
    }
    let mut body = buffer[header_end + 4..].to_vec();
    while body.len() < length {
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..read]);
    }
    body.truncate(length);
    Ok(Some((path, body)))
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
