# `@agent-tunnel/client`

The shared TypeScript filesystem client named in
[`docs/architecture.md`](../../docs/architecture.md) (`packages/client`) and in
[`docs/filesystem-adapters.md`](../../docs/filesystem-adapters.md). **Only the
9P2000.L codec exists so far.** There is no descriptor fetch, no WebSocket, no
`connectFilesystem`, no lifecycle and no adapter: those are the rest of
implementation gate 6 of [`docs/filesystem-api.md`](../../docs/filesystem-api.md).

## What this is for

Implementation gate 3 shipped 43 byte-exact 9P2000.L fixtures under
`crates/tunnel-fs-ninep/fixtures/` and recorded, explicitly, that they were
shared with a TypeScript client "only in the sense that they exist, are checked
in and are documented — **no second implementation has read them**".

`src/ninep/` is that second implementation. It was written from the 9P2000.L
definition (the diod dialect reference and the Linux v9fs bit values named in
[`docs/sources.md`](../../docs/sources.md)) and from the contract, **not**
transliterated from `crates/tunnel-fs-ninep`. A transliteration would agree with
the Rust by construction and prove nothing; this only has value because it can
disagree.

It reads the fixtures **in place**, from the crate's own directory. They are not
copied, so the two implementations cannot drift apart silently: a change to the
Rust fixtures is a change to this suite's input.

## Running it

```sh
cd packages/client
npm test
```

That is the whole command. It needs **no install and no network**: there are
zero runtime dependencies, and Node runs the TypeScript directly by type
stripping. Node 24.21.0 is pinned in `.node-version`, with `engines` requiring
`>=24.0.0`.

Type checking is separate and is the only thing that needs an install:

```sh
npm ci && npm run typecheck
```

`typescript` and `@types/node` are exact-pinned dev-only dependencies with a
committed `package-lock.json`. They are deliberately kept out of `npm test` so
the cross-check itself stays runnable with nothing fetched.

## What it checks

**Every fixture, four ways.** Each of the 43 is decoded and compared field by
field against `test/expected.ts` — a hand-written table of what the fixture
README and the contract say that message carries; re-encoded from the decode and
compared byte for byte; encoded from the hand-written table *alone*, so a decoder
bug cannot cancel an encoder bug; and refused one byte short and with one byte of
trailing padding.

The two halves catch opposite failures. A round trip alone would agree with the
fixture even if two same-width fields were transposed; only naming the intended
values catches that. Naming the values alone would miss a decoder that reads a
field the encoder does not write back.

**The contract's pinned boundaries**, so far as they are expressible without a
socket: `msize` negotiation at 255/256/65,536/65,537; the three size checks in
their fixed order, including the consequence that at `msize` 65,536 a frame one
byte above reports the *ceiling* rather than the negotiated bound; a frame
exactly at `msize` and one byte above at four `msize` values in both directions;
`count[4]` leaving room for its own framing, at the limit and one beyond, for
`Tread`, `Treaddir` and `Rwrite` at three `msize` values, through `encode` and
`decodeExact` rather than a helper; `MAXWELEM` at 16 and 17 with the declared
count checked before anything is reserved; the `NOTAG` rules on encode and
decode; all 215 non-profile opcodes; the closed fourteen-code `Rlerror`
vocabulary; all 256 qid type bytes; and malformed-frame rejection — truncation at
every cut, trailing bytes, two messages in one binary message, a declared size
disagreeing with the buffer, a short buffer judged by its own declared size, and
the stream decoder latching its first framing error.

**The `.L` flag and mask sets**, in `src/ninep/profile.ts` rather than in the
codec, because they are answered with an `Rlerror` on the request's own tag and
not with a close. See the Result section.

**Writer range checks**: every integer refused above its field's width rather
than silently truncated, and every field accepted at its exact width.

**Field layout, independent of the fixtures**: `Rgetattr`, `Tsetattr` and
`Tattach` encoded with all-distinct sentinels and asserted byte by byte at the
offsets the 9P2000.L definition gives, covering the same-valued field pairs no
fixture comparison on either side can distinguish.

**The UTF-8 refusal**, by field and never by substitution: five invalid
sequences (lone continuation, unfinished sequence, overlong, surrogate half, a
byte never valid in UTF-8) against a request name, an `Rreadlink` target and a
name inside an `Rreaddir` block, asserting that no string is returned at all —
and, separately, that a legitimately encoded U+FFFD *does* decode, so the
refusal is not an unreachable path. Plus a check that `Rread` data is left alone
because it is content, not text.

**The whole corpus as a tunnel byte stream**, decoded whole, at every single
split point and one byte at a time, with every message deep-compared against the
expectation table at every cut, and the retained-byte bound asserted after the
first push, where the decoder is genuinely holding a partial frame.

## Result

The two implementations agree on all 43 fixtures, in both directions, field for
field and byte for byte.

**Two differences were found. One is a diagnostic; the other was wire-visible
and is fixed.**

**Wire-visible: where a denied `.L` flag is refused.** This client first checked
the `Tlopen` flag set and the `Tsetattr`/`Tgetattr`/`Tunlinkat` masks *inside*
the codec, where every failure is a `NinepError` — which this client's own
taxonomy defines as a framing failure answered by closing with 1002. In
`crates/tunnel-fs-ninep` those checks live in `session.rs`, not the codec: a
`Tlopen` carrying `O_CREAT` decodes cleanly and the session answers
`Rlerror(ENOTSUP)` on its own tag and **stays open**. The contract names "a flag
the profile denies" among the refusals a correct client can recover from, so the
Rust is right and this side would have torn down a session carrying other
outstanding tags. Fixed by layering: the codec now decodes `flags[4]` and the
mask words as opaque integers, and the rules moved to `src/ninep/profile.ts`
behind a separate `ProfileRefusal` type that carries the errno an `Rlerror`
would. A test asserts a denied flag decodes cleanly and that its refusal is not
a `NinepError`.

**Diagnostic only: two reserved opcode slots.** This implementation first
classified `Tlerror` (6) and `Terror` (106) as known-but-not-in-profile opcodes;
the Rust's `KNOWN_OUTSIDE_PROFILE` holds 25 entries and omits both. The Rust is
right — 6 and 106 are reserved numbering slots beside `Rlerror` (7) and `Rerror`
(107), not messages any peer can send, so answering "you reached for a real
opcode the profile denies" would name a message that does not exist. Both codecs
refuse such a frame and both close with 1002. This side was aligned and the
reasoning kept on the constant rather than the difference erased.

### Defects found in this implementation

All were in the TypeScript; none in the Rust codec or in the fixtures.

* **The `count[4]` framing rule was documented and unenforced.** `checkReadCount`
  existed, was exported, was described in this README and in the task row — and
  was never called from the codec. A `Tread` with `count` 0xffffffff decoded at
  `msize` 4096, a `Treaddir` with `count` 4096 was accepted at `msize` 4096, and
  an `Rwrite` acknowledging 0xffffffff bytes was accepted at `msize` 256. The
  Rust refuses all three at both ends. It is now applied in `encode` and in
  `decodeExact`/`FrameDecoder` with `msize` threaded through, for `Tread` and
  `Treaddir` at overhead 11 and `Rwrite` at overhead 23, and tested at the limit
  and one beyond through the real entry points rather than a helper.
* **`Writer` truncated out-of-range integers silently.** `u32(2 ** 32)`,
  `u32(-1)`, `u16(70000)`, `u64(-1n)` and a qid version of `2 ** 32` all
  encoded, so `encode(x)` could decode to something other than `x` and a
  `Tclunk` with `fid: -1` quietly became `NOFID`. That also hollowed out the
  "encoded from the expectation table alone" argument, since a table entry wrong
  *above* a field's width would still match the fixture. Every integer write is
  now range-checked and throws a typed `FieldOutOfRange` naming the field.
* **The split-point test compared only message counts.** It asserted
  `messages.length` per cut and never content, so a subarray or byteOffset bug
  yielding wrong-but-complete frames would have passed while this README claimed
  the corpus "decodes identically at every single split point". It now deep-equals
  every message against the expectation table at every cut, and asserts the
  retained-byte bound after the *first* push, where the decoder is genuinely
  mid-frame rather than empty.
* **`name` was used as both the message-type discriminator and the 9P `name[s]`
  field**, silently overwriting the discriminator on the eight messages carrying
  both. The discriminator is now `kind`.
* Three hand-transcription errors in `test/expected.ts` and the boundary
  expectations, described under "How the expectation table was built" below.

### How the expectation table was built

`test/expected.ts` was transcribed **by hand from the fixtures' own hex bytes**,
laid out against the field order in the 9P2000.L definition, with the fixture
headers and `fixtures/README.md` supplying the type, tag, length and the
properties the bytes pin. It was **not** read from
`crates/tunnel-fs-ninep/tests/common/mod.rs`, which was never opened, and not
dumped from this decoder's output. It coincides with the Rust fixture source
because the bytes are the same bytes.

It is a hand transcription and four entries were wrong on the first run
(`Tsetattr`'s `size` read as 4 where the bytes say 1024; the wide name's UTF-16
and code-point counts each off by one; and a flag-check ordering expectation).
That bounds what the table proves: a careful reading of the bytes, not a source
independent of them.

**It cannot catch a transposition between two fields holding the same value in
the fixture** — `Rgetattr`'s `uid` and `gid` are both 1000, `Tsetattr`'s are both
0, its `atimeNsec` and `mtimeNsec` are both 0, `Tattach`'s `uname` and `aname`
are both empty. Such a swap is invisible here *and* in the Rust's own fixture
comparison. `boundaries.test.ts` therefore carries fixture-independent layout
tests that encode `Rgetattr`, `Tsetattr` and `Tattach` with all-distinct
sentinels and assert the bytes at the offsets the spec gives.

## What is not proven here

Everything gate 3 already listed as needing a socket or a clock, plus the rest of
gate 6: `connectFilesystem`, the descriptor fetch, the authenticated WSS upgrade,
the session state machine on this side, and the four native adapters
(`@agent-tunnel/files-sdk`, `@agent-tunnel/mastra`, `@agent-tunnel/just-bash`,
`@agent-tunnel/ai-sdk`) against their pinned published packages and real relay
and device sockets. Shared *fuzzing* of one corpus against both codecs, with
accepted values compared, is also still open: this suite fuzzes neither codec, it
compares them on a fixed corpus and on the contract's named boundaries.

All fixture values are synthetic, as `fixtures/README.md` records.
