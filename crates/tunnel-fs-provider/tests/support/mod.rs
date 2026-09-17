//! Fixtures for the gate-4 dispatcher tests.
//!
//! Every fixture is synthetic and lives inside a temporary directory the test
//! created; nothing here reads, writes or links anything outside it. There is no
//! socket, no relay, no Redis and no clock: the live authorization arrives
//! through [`TestAuthority`], which a test moves by hand, so a recheck is proven
//! by the answer it produces rather than by waiting for one.

#![cfg(unix)]
#![allow(dead_code)]

use std::cell::Cell;
use std::fs;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicU32, Ordering};

use tunnel_fs_core::{Capability, CapabilitySet, FeatureSet, Limits, PathBounds, VirtualPath};
use tunnel_fs_host::ExportRoot;
use tunnel_fs_ninep::{Frame, Message, NOFID, NONUNAME, NOTAG, Qid};
use tunnel_fs_provider::{Authority, Authorization, Outbound, Provider, default_limits};

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// The revision every fixture session is admitted at.
pub const REVISION: u64 = 7;

/// An authorization a test moves by hand.
#[derive(Clone)]
pub struct TestAuthority {
    inner: Rc<Cell<Authorization>>,
}

impl TestAuthority {
    pub fn new(grant: CapabilitySet) -> Self {
        Self {
            inner: Rc::new(Cell::new(Authorization {
                revision: REVISION,
                grant,
                fresh: true,
            })),
        }
    }

    /// Advance the grant revision, which must close the session.
    pub fn advance_revision(&self) {
        let mut live = self.inner.get();
        live.revision += 1;
        self.inner.set(live);
    }

    /// Let the authorization snapshot expire, which must close the session.
    pub fn expire(&self) {
        let mut live = self.inner.get();
        live.fresh = false;
        self.inner.set(live);
    }

    /// Narrow the grant without moving the revision.
    pub fn narrow(&self, grant: CapabilitySet) {
        let mut live = self.inner.get();
        live.grant = grant;
        self.inner.set(live);
    }
}

impl Authority for TestAuthority {
    fn current(&self) -> Authorization {
        self.inner.get()
    }
}

/// A temporary export root, removed when it drops.
pub struct Fixture {
    base: PathBuf,
}

impl Fixture {
    pub fn new() -> Self {
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let base = std::env::temp_dir().join(format!("tfsp-{}-{unique}", std::process::id()));
        fs::create_dir_all(base.join("export")).expect("create export root");
        Self { base }
    }

    pub fn export(&self) -> PathBuf {
        self.base.join("export")
    }

    pub fn inside(&self, relative: &str) -> PathBuf {
        self.export().join(relative.trim_start_matches('/'))
    }

    pub fn dir(&self, relative: &str) {
        fs::create_dir_all(self.inside(relative)).expect("create fixture directory");
    }

    pub fn file(&self, relative: &str, contents: &[u8]) {
        let at = self.inside(relative);
        if let Some(parent) = at.parent() {
            fs::create_dir_all(parent).expect("create fixture parent");
        }
        fs::write(at, contents).expect("write fixture file");
    }

    pub fn remove(&self, relative: &str) {
        let at = self.inside(relative);
        if at.is_dir() {
            fs::remove_dir_all(at).expect("remove fixture directory");
        } else {
            fs::remove_file(at).expect("remove fixture file");
        }
    }

    pub fn base_path(&self) -> &Path {
        &self.base
    }

    /// Open a provider over this export.
    pub fn provider(&self, grant: CapabilitySet) -> (Provider<TestAuthority>, TestAuthority) {
        self.provider_with(grant, FeatureSet::NONE, default_limits())
    }

    pub fn provider_with(
        &self,
        grant: CapabilitySet,
        features: FeatureSet,
        limits: Limits,
    ) -> (Provider<TestAuthority>, TestAuthority) {
        let authority = TestAuthority::new(grant);
        let root = ExportRoot::open(&self.export(), grant, features, limits.path_bounds())
            .expect("open export root");
        let provider =
            Provider::new(root, limits, authority.clone()).expect("a non-empty grant admits");
        (provider, authority)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}

// ---------------------------------------------------------------- capabilities

pub fn read_and_list() -> CapabilitySet {
    CapabilitySet::from_slice(&[Capability::Read, Capability::List])
}

pub fn list_only() -> CapabilitySet {
    CapabilitySet::from_slice(&[Capability::List])
}

pub fn read_only() -> CapabilitySet {
    CapabilitySet::from_slice(&[Capability::Read])
}

pub fn full_grant() -> CapabilitySet {
    CapabilitySet::from_slice(&[
        Capability::Read,
        Capability::Write,
        Capability::List,
        Capability::Delete,
    ])
}

pub fn bounds() -> PathBounds {
    default_limits().path_bounds()
}

pub fn vpath(text: &str) -> VirtualPath {
    VirtualPath::parse(text, bounds()).expect("valid virtual path")
}

// ------------------------------------------------------------------ driving

/// Feed one request and drain the provider's queue.
///
/// The two halves are deliberately separate in the provider — a request is
/// admitted, then queued, then performed after the authorization recheck — so
/// this helper exists for the many tests that do not care about the gap. The
/// tests that *do* care drive `accept` and `step` themselves.
pub fn exchange(provider: &mut Provider<TestAuthority>, frame: Frame) -> Vec<Outbound> {
    let mut out = provider.accept(&frame);
    while provider.has_work() {
        let produced = provider.step();
        // **This helper stands in for the connector, so it settles the mutation
        // ledger the way the connector does.** A reply that reaches the carrier
        // is an acknowledgement; without this the ledger would stay open for
        // every mutation these tests perform and `Provider::close` would report
        // all of them `unknown`, which is the opposite of what an ordinary
        // exchange means. The tests that are *about* an undelivered reply drive
        // `accept` and `step` themselves and decline to confirm, which is
        // exactly the shape a dropped consumer has.
        if produced.iter().any(|out| matches!(out, Outbound::Frame(_))) {
            provider.confirm_effect_delivered();
        }
        out.extend(produced);
    }
    out
}

/// The single frame an exchange produced, or a panic naming what it produced.
pub fn one_frame(out: Vec<Outbound>) -> Frame {
    assert_eq!(out.len(), 1, "expected exactly one outbound: {out:?}");
    match out.into_iter().next().expect("one outbound") {
        Outbound::Frame(frame) => *frame,
        Outbound::Close(code) => panic!("expected a frame, got a close: {code}"),
    }
}

/// The close code an exchange produced.
pub fn one_close(out: Vec<Outbound>) -> tunnel_fs_core::SessionErrorCode {
    assert_eq!(out.len(), 1, "expected exactly one outbound: {out:?}");
    match out.into_iter().next().expect("one outbound") {
        Outbound::Close(code) => code,
        Outbound::Frame(frame) => panic!("expected a close, got a frame: {frame:?}"),
    }
}

/// The error code an `Rlerror` carried.
pub fn error_code(frame: &Frame) -> tunnel_fs_core::FsErrorCode {
    match &frame.message {
        Message::Rlerror { code } => *code,
        other => panic!("expected an Rlerror, got {other:?}"),
    }
}

// ------------------------------------------------------------------ requests

pub fn tversion(msize: u32) -> Frame {
    Frame::new(
        NOTAG,
        Message::Tversion {
            msize,
            version: tunnel_fs_ninep::DIALECT.to_owned(),
        },
    )
}

pub fn tattach(tag: u16, fid: u32) -> Frame {
    Frame::new(
        tag,
        Message::Tattach {
            fid,
            afid: NOFID,
            uname: String::new(),
            aname: String::new(),
            n_uname: NONUNAME,
        },
    )
}

pub fn twalk(tag: u16, fid: u32, newfid: u32, names: &[&str]) -> Frame {
    Frame::new(
        tag,
        Message::Twalk {
            fid,
            newfid,
            names: names.iter().map(|name| (*name).to_owned()).collect(),
        },
    )
}

pub fn tlopen(tag: u16, fid: u32, flags: u32) -> Frame {
    Frame::new(tag, Message::Tlopen { fid, flags })
}

pub fn tread(tag: u16, fid: u32, offset: u64, count: u32) -> Frame {
    Frame::new(tag, Message::Tread { fid, offset, count })
}

pub fn treaddir(tag: u16, fid: u32, offset: u64, count: u32) -> Frame {
    Frame::new(tag, Message::Treaddir { fid, offset, count })
}

pub fn tgetattr(tag: u16, fid: u32, request_mask: u64) -> Frame {
    Frame::new(tag, Message::Tgetattr { fid, request_mask })
}

pub fn tclunk(tag: u16, fid: u32) -> Frame {
    Frame::new(tag, Message::Tclunk { fid })
}

pub fn tflush(tag: u16, oldtag: u16) -> Frame {
    Frame::new(tag, Message::Tflush { oldtag })
}

// -------------------------------------------------------- gate 5's requests

pub fn tlcreate(tag: u16, fid: u32, name: &str, flags: u32, mode: u32) -> Frame {
    Frame::new(
        tag,
        Message::Tlcreate {
            fid,
            name: name.to_owned(),
            flags,
            mode,
            gid: 0,
        },
    )
}

pub fn twrite(tag: u16, fid: u32, offset: u64, data: &[u8]) -> Frame {
    Frame::new(
        tag,
        Message::Twrite {
            fid,
            offset,
            data: data.to_vec(),
        },
    )
}

pub fn tmkdir(tag: u16, dfid: u32, name: &str, mode: u32) -> Frame {
    Frame::new(
        tag,
        Message::Tmkdir {
            dfid,
            name: name.to_owned(),
            mode,
            gid: 0,
        },
    )
}

pub fn tunlinkat(tag: u16, dirfid: u32, name: &str, flags: u32) -> Frame {
    Frame::new(
        tag,
        Message::Tunlinkat {
            dirfid,
            name: name.to_owned(),
            flags,
        },
    )
}

pub fn trenameat(tag: u16, olddirfid: u32, oldname: &str, newdirfid: u32, newname: &str) -> Frame {
    Frame::new(
        tag,
        Message::Trenameat {
            olddirfid,
            oldname: oldname.to_owned(),
            newdirfid,
            newname: newname.to_owned(),
        },
    )
}

pub fn tremove(tag: u16, fid: u32) -> Frame {
    Frame::new(tag, Message::Tremove { fid })
}

pub fn tsymlink(tag: u16, fid: u32, name: &str, target: &str) -> Frame {
    Frame::new(
        tag,
        Message::Tsymlink {
            fid,
            name: name.to_owned(),
            target: target.to_owned(),
            gid: 0,
        },
    )
}

pub fn treadlink(tag: u16, fid: u32) -> Frame {
    Frame::new(tag, Message::Treadlink { fid })
}

pub fn tlink(tag: u16, dfid: u32, fid: u32, name: &str) -> Frame {
    Frame::new(
        tag,
        Message::Tlink {
            dfid,
            fid,
            name: name.to_owned(),
        },
    )
}

/// A `Tsetattr` naming only a new size.
pub fn tsetattr_size(tag: u16, fid: u32, size: u64) -> Frame {
    tsetattr(tag, fid, tunnel_fs_ninep::flags::SETATTR_SIZE, 0, size)
}

/// A `Tsetattr` naming only a new mode.
pub fn tsetattr_mode(tag: u16, fid: u32, mode: u32) -> Frame {
    tsetattr(tag, fid, tunnel_fs_ninep::flags::SETATTR_MODE, mode, 0)
}

/// A `Tsetattr` naming an **explicit** modification time.
///
/// Both mask bits: the field bit and its `_SET` companion. Without the second
/// the same request means `touch`, which is a different case and has its own
/// helper spelling in the test that uses it.
pub fn tsetattr_mtime(tag: u16, fid: u32, seconds: u64, nanoseconds: u64) -> Frame {
    Frame::new(
        tag,
        Message::Tsetattr {
            fid,
            valid: tunnel_fs_ninep::flags::SETATTR_MTIME
                | tunnel_fs_ninep::flags::SETATTR_MTIME_SET,
            mode: 0,
            uid: 0,
            gid: 0,
            size: 0,
            atime_sec: 0,
            atime_nsec: 0,
            mtime_sec: seconds,
            mtime_nsec: nanoseconds,
        },
    )
}

pub fn tsetattr(tag: u16, fid: u32, valid: u32, mode: u32, size: u64) -> Frame {
    Frame::new(
        tag,
        Message::Tsetattr {
            fid,
            valid,
            mode,
            uid: 0,
            gid: 0,
            size,
            atime_sec: 0,
            atime_nsec: 0,
            mtime_sec: 0,
            mtime_nsec: 0,
        },
    )
}

/// The count an `Rwrite` acknowledged.
pub fn written(frame: &Frame) -> u32 {
    match &frame.message {
        Message::Rwrite { count } => *count,
        other => panic!("expected an Rwrite, got {other:?}"),
    }
}

/// A grant with `write` and `delete` but neither `read` nor `list`.
///
/// The shape the contract's own `Twalk` disclosure note describes: it can reach
/// a name and change it, and it can observe nothing about it but a qid.
pub fn write_and_delete() -> CapabilitySet {
    CapabilitySet::from_slice(&[Capability::Write, Capability::Delete])
}

/// The features a write-serving export advertises in these tests.
///
/// `atomicRename` because `Trenameat` needs it, `exclusiveCreate` because this
/// implementation's create is always exclusive, and `symlinks` because the
/// symbolic-link cases need it. **`hardLinks` is deliberately absent**: with it
/// on, the `st_nlink` write refusal switches off, and that refusal is one of the
/// things gate 5 has to prove is reachable on a real write.
pub fn write_features() -> FeatureSet {
    FeatureSet::NONE
        .with(tunnel_fs_core::Feature::AtomicRename)
        .with(tunnel_fs_core::Feature::ExclusiveCreate)
        .with(tunnel_fs_core::Feature::Symlinks)
}

/// Negotiate and attach, returning the root qid.
pub fn handshake(provider: &mut Provider<TestAuthority>, root_fid: u32) -> Qid {
    let reply = one_frame(exchange(provider, tversion(65_536)));
    assert!(matches!(reply.message, Message::Rversion { .. }));
    let reply = one_frame(exchange(provider, tattach(1, root_fid)));
    match reply.message {
        Message::Rattach { qid } => qid,
        other => panic!("expected Rattach, got {other:?}"),
    }
}
