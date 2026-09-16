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
`count[4]` leaving room for its own framing; `MAXWELEM` at 16 and 17 with the
declared count checked before anything is reserved; the `NOTAG` rules on encode
and decode; all 215 non-profile opcodes; the closed fourteen-code `Rlerror`
vocabulary; all 256 qid type bytes; the `.L` flag and mask sets; and
malformed-frame rejection — truncation at every cut, trailing bytes, two messages
in one binary message, a declared size disagreeing with the buffer, and the
stream decoder latching its first framing error.

**The UTF-8 refusal**, by field and never by substitution: five invalid
sequences (lone continuation, unfinished sequence, overlong, surrogate half, a
byte never valid in UTF-8) against a request name, an `Rreadlink` target and a
name inside an `Rreaddir` block, with an assertion that U+FFFD never appears,
and a check that `Rread` data is left alone because it is content, not text.

**The whole corpus as a tunnel byte stream**, decoded whole, at every single
split point, and one byte at a time, with the retained-byte bound asserted.

## Result

The two implementations agree on all 43 fixtures, in both directions, field for
field and byte for byte.

One difference was found, and it is a difference of *diagnostic*, not of wire
format. This implementation first classified `Tlerror` (6) and `Terror` (106) as
known-but-not-in-profile opcodes; the Rust's `KNOWN_OUTSIDE_PROFILE` holds 25
entries and omits both. The Rust is right — 6 and 106 are reserved numbering
slots beside `Rlerror` (7) and `Rerror` (107), not messages any peer can send,
so answering "you reached for a real opcode the profile denies" would name a
message that does not exist. Both codecs refuse such a frame and both close with
1002. This side was aligned and the reasoning kept on the constant rather than
the difference erased.

Four defects were found in **this** implementation while the cross-check was
being brought up, all before any fixture was trusted: `name` was used as both
the message-type discriminator and the 9P `name[s]` field, which silently
overwrote the discriminator on the eight messages carrying both (the
discriminator is now `kind`), and three hand-transcription errors in
`test/expected.ts` and the boundary expectations. None were defects in the Rust
codec or in the fixtures.

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
