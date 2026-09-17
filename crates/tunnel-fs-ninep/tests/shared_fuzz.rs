//! This crate's verdicts on the shared generated corpus.
//!
//! `docs/testing.md` asks for the incremental Rust and TypeScript codecs to be
//! fuzzed with the **same** corpus, with accepted values and rejection
//! behaviour compared.  Gate 3's residue records, correctly, that its 43 golden
//! fixtures are not that: nothing is generated, and neither codec is ever run
//! against input the other produced a verdict on.
//!
//! The corpus is generated in one place — `packages/client/fuzz/corpus.ts`,
//! deterministically from a seed the corpus file records — and both codecs are
//! run against it.  This test is the Rust half: it reads
//! `packages/client/fuzz/corpus.jsonl`, decodes every case, renders what it
//! accepted in a canonical form, and compares the whole result against the
//! checked-in `packages/client/fuzz/rust-verdicts.jsonl`.  The TypeScript half
//! reads the same corpus, produces its own verdicts, and compares them against
//! this file's output; a disagreement fails there.
//!
//! To rewrite the verdicts after a deliberate change:
//!
//! ```text
//! AGENT_TUNNEL_FUZZ_WRITE=1 cargo test -p tunnel-fs-ninep --test shared_fuzz
//! ```
//!
//! and then read the diff.  An ordinary run cannot rewrite the evidence it
//! checks, which is the same rule the golden fixtures follow.
//!
//! **One alignment is deliberate and is named rather than hidden.** This crate
//! decodes an `Rreaddir` to its unparsed block and leaves the inner array to
//! [`tunnel_fs_ninep::parse_entries`]; the TypeScript parses it inside the
//! decoder.  The harness calls `parse_entries` here, so the comparison is
//! between the same decision rather than between two different amounts of work.
//! Both answers are framing failures answered with a 1002 close either way.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use tunnel_fs_ninep::{
    CodecError, DirEntry, FrameDecoder, Message, Qid, decode_exact, parse_entries,
};

/// Where the corpus and the verdicts live: `packages/client/fuzz/`.
fn fuzz_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../packages/client/fuzz")
        .canonicalize()
        .expect("packages/client/fuzz must exist")
}

/* ------------------------------------------------------------------ *
 * A corpus line, parsed without a serializer.
 * ------------------------------------------------------------------ */

#[derive(Debug)]
struct Case {
    id: u64,
    msize: u32,
    /// One buffer for the consumer rule; several pushes for the stream rule.
    chunks: Vec<Vec<u8>>,
    stream: bool,
}

/// The value of `"key":` in one JSON object line, as raw text.
fn raw_field<'line>(line: &'line str, key: &str) -> Option<&'line str> {
    let needle = format!("\"{key}\":");
    let start = line.find(&needle)? + needle.len();
    Some(&line[start..])
}

fn number_field(line: &str, key: &str) -> Option<u64> {
    let rest = raw_field(line, key)?;
    let end = rest
        .find(|character: char| !character.is_ascii_digit())
        .unwrap_or(rest.len());
    rest[..end].parse().ok()
}

fn string_field(line: &str, key: &str) -> Option<String> {
    let rest = raw_field(line, key)?.strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(rest[..end].to_owned())
}

fn string_array_field(line: &str, key: &str) -> Option<Vec<String>> {
    let rest = raw_field(line, key)?.strip_prefix('[')?;
    let end = rest.find(']')?;
    let body = &rest[..end];
    if body.is_empty() {
        return Some(Vec::new());
    }
    Some(
        body.split(',')
            .map(|item| item.trim().trim_matches('"').to_owned())
            .collect(),
    )
}

fn unhex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2), "hex must be byte-aligned");
    (0..text.len() / 2)
        .map(|index| {
            u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).expect("hex digit pair")
        })
        .collect()
}

fn read_corpus() -> Vec<Case> {
    let text = fs::read_to_string(fuzz_dir().join("corpus.jsonl")).expect("corpus.jsonl");
    let mut lines = text.lines();
    let header = lines.next().expect("corpus header");
    assert!(
        header.contains("agent-tunnel.9p.v1 shared codec corpus"),
        "the first line names the corpus and its seed",
    );
    lines
        .map(|line| {
            let id = number_field(line, "id").expect("id");
            let msize = u32::try_from(number_field(line, "msize").expect("msize")).expect("msize");
            let stream = string_field(line, "transport").as_deref() == Some("stream");
            let chunks = if stream {
                string_array_field(line, "chunks")
                    .expect("chunks")
                    .iter()
                    .map(|chunk| unhex(chunk))
                    .collect()
            } else {
                vec![unhex(&string_field(line, "bytes").expect("bytes"))]
            };
            Case {
                id,
                msize,
                chunks,
                stream,
            }
        })
        .collect()
}

/* ------------------------------------------------------------------ *
 * The canonical rendering, written out by hand.
 * ------------------------------------------------------------------ *
 *
 * `packages/client/fuzz/canonical.ts` renders the same line from the other
 * side's own types.  Two hand-written renderers is the point: a shared one
 * would be a third implementation both sides trusted, and a field either codec
 * dropped would then be dropped from the comparison as well.
 */

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn text(value: &str) -> String {
    format!("h:{}", hex(value.as_bytes()))
}

fn qid(value: Qid) -> String {
    format!("q:{}:{}:{}", value.kind.bits(), value.version, value.path)
}

fn entries(values: &[DirEntry]) -> String {
    let rendered: Vec<String> = values
        .iter()
        .map(|entry| {
            format!(
                "{}|{}|{}",
                qid(entry.qid),
                entry.offset,
                text(entry.name.as_str())
            )
        })
        .collect();
    format!("[{}]", rendered.join(","))
}

#[expect(
    clippy::too_many_lines,
    reason = "one arm per message type; splitting it would hide the wire order this renders"
)]
fn canonical(tag: u16, message: &Message) -> Result<String, CodecError> {
    let mut out = String::new();
    let name = format!("{:?}", message.message_type());
    let _ = write!(out, "{name} tag={tag}");
    match message {
        Message::Rlerror { code } => {
            let _ = write!(out, " ecode={}", code.errno());
        }
        Message::Tversion { msize, version } | Message::Rversion { msize, version } => {
            let _ = write!(out, " msize={msize} version={}", text(version));
        }
        Message::Tattach {
            fid,
            afid,
            uname,
            aname,
            n_uname,
        } => {
            let _ = write!(
                out,
                " fid={fid} afid={afid} uname={} aname={} n_uname={n_uname}",
                text(uname),
                text(aname)
            );
        }
        Message::Rattach { qid: value }
        | Message::Rsymlink { qid: value }
        | Message::Rmkdir { qid: value } => {
            let _ = write!(out, " qid={}", qid(*value));
        }
        Message::Tflush { oldtag } => {
            let _ = write!(out, " oldtag={oldtag}");
        }
        Message::Twalk { fid, newfid, names } => {
            let rendered: Vec<String> = names.iter().map(|name| text(name)).collect();
            let _ = write!(
                out,
                " fid={fid} newfid={newfid} wnames=[{}]",
                rendered.join(",")
            );
        }
        Message::Rwalk { qids } => {
            let rendered: Vec<String> = qids.iter().map(|value| qid(*value)).collect();
            let _ = write!(out, " wqids=[{}]", rendered.join(","));
        }
        Message::Tlopen { fid, flags } => {
            let _ = write!(out, " fid={fid} flags={flags}");
        }
        Message::Rlopen { qid: value, iounit } | Message::Rlcreate { qid: value, iounit } => {
            let _ = write!(out, " qid={} iounit={iounit}", qid(*value));
        }
        Message::Tlcreate {
            fid,
            name,
            flags,
            mode,
            gid,
        } => {
            let _ = write!(
                out,
                " fid={fid} name={} flags={flags} mode={mode} gid={gid}",
                text(name)
            );
        }
        Message::Tsymlink {
            fid,
            name,
            target,
            gid,
        } => {
            let _ = write!(
                out,
                " fid={fid} name={} target={} gid={gid}",
                text(name),
                text(target)
            );
        }
        Message::Treadlink { fid } | Message::Tclunk { fid } | Message::Tremove { fid } => {
            let _ = write!(out, " fid={fid}");
        }
        Message::Rreadlink { target } => {
            let _ = write!(out, " target={}", text(target));
        }
        Message::Tgetattr { fid, request_mask } => {
            let _ = write!(out, " fid={fid} request_mask={request_mask}");
        }
        Message::Rgetattr(attributes) => {
            let _ = write!(
                out,
                " valid={} qid={} mode={} uid={} gid={} nlink={} rdev={} size={} blksize={} blocks={} atime_sec={} atime_nsec={} mtime_sec={} mtime_nsec={} ctime_sec={} ctime_nsec={} btime_sec={} btime_nsec={} gen={} data_version={}",
                attributes.valid,
                qid(attributes.qid),
                attributes.mode,
                attributes.uid,
                attributes.gid,
                attributes.nlink,
                attributes.rdev,
                attributes.size,
                attributes.blksize,
                attributes.blocks,
                attributes.atime_sec,
                attributes.atime_nsec,
                attributes.mtime_sec,
                attributes.mtime_nsec,
                attributes.ctime_sec,
                attributes.ctime_nsec,
                attributes.btime_sec,
                attributes.btime_nsec,
                attributes.generation,
                attributes.data_version,
            );
        }
        Message::Tsetattr {
            fid,
            valid,
            mode,
            uid,
            gid,
            size,
            atime_sec,
            atime_nsec,
            mtime_sec,
            mtime_nsec,
        } => {
            let _ = write!(
                out,
                " fid={fid} valid={valid} mode={mode} uid={uid} gid={gid} size={size} atime_sec={atime_sec} atime_nsec={atime_nsec} mtime_sec={mtime_sec} mtime_nsec={mtime_nsec}"
            );
        }
        Message::Treaddir { fid, offset, count } | Message::Tread { fid, offset, count } => {
            let _ = write!(out, " fid={fid} offset={offset} count={count}");
        }
        Message::Rreaddir { data } => {
            let _ = write!(out, " entries={}", entries(&parse_entries(data)?));
        }
        Message::Tlink { dfid, fid, name } => {
            let _ = write!(out, " dfid={dfid} fid={fid} name={}", text(name));
        }
        Message::Tmkdir {
            dfid,
            name,
            mode,
            gid,
        } => {
            let _ = write!(
                out,
                " dfid={dfid} name={} mode={mode} gid={gid}",
                text(name)
            );
        }
        Message::Trename { fid, dfid, name } => {
            let _ = write!(out, " fid={fid} dfid={dfid} name={}", text(name));
        }
        Message::Trenameat {
            olddirfid,
            oldname,
            newdirfid,
            newname,
        } => {
            let _ = write!(
                out,
                " olddirfid={olddirfid} oldname={} newdirfid={newdirfid} newname={}",
                text(oldname),
                text(newname)
            );
        }
        Message::Tunlinkat {
            dirfid,
            name,
            flags,
        } => {
            let _ = write!(out, " dirfid={dirfid} name={} flags={flags}", text(name));
        }
        Message::Rread { data } => {
            let _ = write!(out, " data=h:{}", hex(data));
        }
        Message::Twrite { fid, offset, data } => {
            let _ = write!(out, " fid={fid} offset={offset} data=h:{}", hex(data));
        }
        Message::Rwrite { count } => {
            let _ = write!(out, " count={count}");
        }
        Message::Rflush
        | Message::Rsetattr
        | Message::Rlink
        | Message::Rrename
        | Message::Rrenameat
        | Message::Runlinkat
        | Message::Rclunk
        | Message::Rremove => {}
    }
    Ok(out)
}

/// The refusal name, without the payload an error may carry.
///
/// The field an unparseable string names and the opcode byte an unknown type
/// carries are diagnostics, not wire behaviour; comparing them would compare
/// two error vocabularies rather than two codecs.
fn refusal(error: CodecError) -> &'static str {
    match error {
        CodecError::FrameBelowHeader => "FrameBelowHeader",
        CodecError::FrameAboveMsize => "FrameAboveMsize",
        CodecError::FrameAboveCeiling => "FrameAboveCeiling",
        CodecError::TruncatedBody => "TruncatedBody",
        CodecError::TrailingBytes => "TrailingBytes",
        CodecError::UnknownMessageType(_) => "UnknownMessageType",
        CodecError::MessageTypeNotInProfile(_) => "MessageTypeNotInProfile",
        CodecError::UnexpectedDirection(_) => "UnexpectedDirection",
        CodecError::StringNotUtf8(_) => "StringNotUtf8",
        CodecError::StringTooLong(_) => "StringTooLong",
        CodecError::CountAboveMsize => "CountAboveMsize",
        CodecError::TooManyWalkNames => "TooManyWalkNames",
        CodecError::NotagNotPermitted => "NotagNotPermitted",
        CodecError::NotagRequired => "NotagRequired",
        CodecError::NofidNotPermitted => "NofidNotPermitted",
        CodecError::QidTypeNotInProfile => "QidTypeNotInProfile",
        CodecError::ErrnoNotInVocabulary => "ErrnoNotInVocabulary",
        CodecError::MalformedDirEntry => "MalformedDirEntry",
    }
}

/// One verdict line, in the JSON shape both sides read.
fn verdict(case: &Case) -> String {
    let id = case.id;
    if case.stream {
        let mut decoder = FrameDecoder::with_msize(case.msize);
        let mut values: Vec<String> = Vec::new();
        for chunk in &case.chunks {
            let mut input = chunk.as_slice();
            loop {
                match decoder.decode(&mut input) {
                    Ok(Some(frame)) => match canonical(frame.tag, &frame.message) {
                        Ok(value) => values.push(value),
                        Err(error) => {
                            return stream_line(id, &values, Some(refusal(error)));
                        }
                    },
                    Ok(None) => break,
                    Err(error) => {
                        return stream_line(id, &values, Some(refusal(error)));
                    }
                }
            }
        }
        return stream_line(id, &values, None);
    }
    let bytes = case.chunks.first().expect("one buffer");
    match decode_exact(bytes, case.msize).and_then(|frame| canonical(frame.tag, &frame.message)) {
        Ok(value) => format!("{{\"id\":{id},\"verdict\":\"accept\",\"value\":\"{value}\"}}"),
        Err(error) => format!(
            "{{\"id\":{id},\"verdict\":\"refuse\",\"reason\":\"{}\"}}",
            refusal(error)
        ),
    }
}

fn stream_line(id: u64, values: &[String], reason: Option<&str>) -> String {
    let rendered: Vec<String> = values.iter().map(|value| format!("\"{value}\"")).collect();
    let reason = reason.map_or_else(|| "null".to_owned(), |text| format!("\"{text}\""));
    format!(
        "{{\"id\":{id},\"verdict\":\"stream\",\"values\":[{}],\"reason\":{reason}}}",
        rendered.join(",")
    )
}

#[test]
fn rust_verdicts_on_the_shared_corpus_are_current() {
    let corpus = read_corpus();
    assert!(
        corpus.len() > 1000,
        "a corpus this small would prove little: {} cases",
        corpus.len()
    );
    let produced: String = corpus
        .iter()
        .map(|case| verdict(case) + "\n")
        .collect::<Vec<String>>()
        .concat();
    let path = fuzz_dir().join("rust-verdicts.jsonl");
    if std::env::var_os("AGENT_TUNNEL_FUZZ_WRITE").is_some() {
        fs::write(&path, &produced).expect("write verdicts");
        return;
    }
    let checked_in = fs::read_to_string(&path).expect("rust-verdicts.jsonl");
    if checked_in != produced {
        let first = checked_in
            .lines()
            .zip(produced.lines())
            .position(|(left, right)| left != right);
        panic!(
            "the checked-in Rust verdicts are stale; first differing line is {first:?}. \
             Rewrite with AGENT_TUNNEL_FUZZ_WRITE=1 and read the diff."
        );
    }
}

/// Every message type in the profile is reached by the corpus.
///
/// A corpus that never built a `Tsetattr` would agree with the other side about
/// `Tsetattr` for free, so the coverage is asserted rather than assumed.
#[test]
fn the_corpus_reaches_most_of_the_profile() {
    let corpus = read_corpus();
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    for case in &corpus {
        let bytes = case.chunks.first().expect("one buffer");
        if let Ok(frame) = decode_exact(bytes, case.msize) {
            *seen
                .entry(format!("{:?}", frame.message_type()))
                .or_default() += 1;
        }
    }
    assert!(
        seen.len() >= 35,
        "the corpus decoded only {} distinct message types: {seen:?}",
        seen.len()
    );
}
