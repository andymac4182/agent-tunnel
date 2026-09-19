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
//! | [`Fault::PreDispatchRejection`] | **0** | **not dispatched** |
//! | [`Fault::Unavailable`] | **0** | **not dispatched** |
//!
//! The two rows with zero entries and the two with one entry are what make the
//! distinction checkable rather than asserted.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub mod client;

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
/// The marker seed for display 0. Display *n* uses `IMAGE_SEED + n`, so two
/// displays produce images of identical length and entirely different markers.
pub const IMAGE_SEED: u32 = 0x5EED_0001;
/// The synthetic cursor position.
pub const CURSOR: (u32, u32) = (17, 23);
/// The version string this fixture reports.
pub const FIXTURE_VERSION: &str = "0.3.46-synthetic";

/// One thing the backend was asked to do, recorded at the moment it was
/// accepted — **before** any fault is applied.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LedgerEntry {
    /// The canonical command name as it arrived.
    pub command: String,
    /// The `display` parameter, when the command carried one.
    pub display: Option<u32>,
}

impl LedgerEntry {
    #[must_use]
    pub fn new(command: &str, display: Option<u32>) -> Self {
        Self {
            command: command.to_owned(),
            display,
        }
    }
}

/// The authoritative record of what the backend was asked to do.
#[derive(Clone, Debug, Default)]
pub struct Ledger {
    entries: Arc<Mutex<Vec<LedgerEntry>>>,
}

impl Ledger {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn record(&self, entry: LedgerEntry) {
        self.entries
            .lock()
            .expect("the ledger mutex is never poisoned by fixture code")
            .push(entry);
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

    /// Total entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries().len()
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
    /// Record the ledger entry, then answer 200 with framed JSON in which the
    /// handler's own result carries `success: false`, overriding the envelope
    /// — the `{"success": True, **result}` shape the pin records.
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

/// A running fixture backend.
pub struct FixtureBackend {
    address: SocketAddr,
    ledger: Ledger,
    faults: Faults,
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
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let address = listener.local_addr()?;
        let ledger = Ledger::new();
        let faults = Faults::new();
        let handle = tokio::spawn(serve(listener, ledger.clone(), faults.clone()));
        Ok(Self {
            address,
            ledger,
            faults,
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

    /// Stop serving.
    pub fn stop(self) {
        self.handle.abort();
    }
}

async fn serve(listener: TcpListener, ledger: Ledger, faults: Faults) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        let ledger = ledger.clone();
        let faults = faults.clone();
        tokio::spawn(async move {
            let _ = handle_connection(stream, ledger, faults).await;
        });
    }
}

/// One HTTP/1.1 exchange, hand-written so the pathological answers are
/// expressible.
async fn handle_connection(
    mut stream: TcpStream,
    ledger: Ledger,
    faults: Faults,
) -> std::io::Result<()> {
    let Some((path, body)) = read_request(&mut stream).await? else {
        return Ok(());
    };
    match path.as_str() {
        COMMANDS_PATH => {
            let listing = json!({"commands": REGISTERED_COMMANDS});
            write_response(
                &mut stream,
                200,
                "application/json",
                listing.to_string().as_bytes(),
            )
            .await
        }
        CMD_PATH => handle_cmd(&mut stream, &ledger, &faults, &body).await,
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

    ledger.record(LedgerEntry::new(command, display));

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
        Fault::ResultOverridesEnvelope => {
            // `{"success": True, **result}` with a result carrying its own
            // `success`: on the wire there is one member, and it is the
            // handler's.
            framed(stream, json!({"success": false, "image": "synthetic"})).await
        }
        Fault::None => framed(stream, success_payload(command, display)).await,
        Fault::PreDispatchRejection { .. } | Fault::Unavailable => unreachable!("returned above"),
    }
}

/// The successful result for each read-only command.
fn success_payload(command: &str, display: Option<u32>) -> Value {
    let display = display.unwrap_or(0);
    match command {
        "version" => json!({
            "success": true,
            "version": FIXTURE_VERSION,
            // `desktop_capture_authorized` is **deliberately absent**, which is
            // what the released server does on the supported 0.22.x SDK.
            // Adding it here would make every absent-is-not-false test vacuous.
            "desktop_unlocked": true,
        }),
        "get_screen_size" => json!({
            "success": true,
            "width": SCREEN_WIDTH,
            "height": SCREEN_HEIGHT,
        }),
        "get_cursor_position" => json!({
            "success": true,
            "x": CURSOR.0,
            "y": CURSOR.1,
        }),
        "screenshot" => {
            let seed = IMAGE_SEED.wrapping_add(display);
            let image = tunnel_cua::marker::encode(SCREEN_WIDTH, SCREEN_HEIGHT, seed)
                .expect("the fixture's own dimensions are valid");
            json!({
                "success": true,
                "width": SCREEN_WIDTH,
                "height": SCREEN_HEIGHT,
                "seed": seed,
                // Hex rather than base64, so the fixture needs no encoder
                // dependency and a test can decode it with `from_hex` below.
                "image_hex": to_hex(&image),
            })
        }
        // Every other registered command is an input command. The fixture
        // records it and answers, so that a test which *did* reach one would
        // see it in the ledger -- which is how "the profile never dispatches
        // an input command" is a measurement rather than an assumption.
        _ => json!({"success": true, "synthetic": command}),
    }
}

/// Lowercase hex, so a synthetic image can travel in JSON without a base64
/// dependency.
#[must_use]
pub fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from_digit(u32::from(byte >> 4), 16).expect("a nibble is a hex digit"));
        out.push(char::from_digit(u32::from(byte & 0x0f), 16).expect("a nibble is a hex digit"));
    }
    out
}

/// The inverse of [`to_hex`].
#[must_use]
pub fn from_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(text.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let high = char::from(pair[0]).to_digit(16)?;
        let low = char::from(pair[1]).to_digit(16)?;
        out.push(u8::try_from(high * 16 + low).ok()?);
    }
    Some(out)
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
