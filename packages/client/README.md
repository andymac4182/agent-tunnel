# `@agent-tunnel/client`

The shared TypeScript filesystem client named in
[`docs/architecture.md`](../../docs/architecture.md) (`packages/client`) and in
[`docs/filesystem-adapters.md`](../../docs/filesystem-adapters.md).

It is now a client, not only a codec: `connectFilesystem`, the descriptor fetch
with its `grantRevision` header, an authenticated WebSocket upgrade written out
so it can set `Authorization`, the consumer-side 9P session with its tags, fids,
flush and close codes, and the bytes and limits of the [shared client
API](../../docs/filesystem-api.md#shared-client-api). **The four native
adapters are here too**, as export subpaths rather than as four published
packages: `@agent-tunnel/client/files-sdk`, `/mastra`, `/just-bash` and
`/ai-sdk`. Each depends on its framework **by type only**, so this package still
has zero runtime dependencies and `npm test` still runs with `node_modules`
deleted. The seventh component of implementation gate 6 — the AI SDK live
directory tools, `createFilesystemTools` on the `/ai-sdk` subpath — is here too
(task row M4-63).

**All four adapters have now run against a real local relay and device** — once,
locally, through `scripts/adapters-demo.sh` ([docs/demo/adapters.md](../../docs/demo/adapters.md),
task row M4-64), which lends one shared client to `Files`, `Bash`, a Mastra
`Agent` and the AI SDK `generateText` loop and checks every result against the
exported host directory. That is a demo with a checker, not a harness gate: it
is not in CI and holds no session across a rotation.

**What the package's own tests do not prove.** Every socket in this
package's tests is a loopback socket to a harness in `test/harness/`, which
speaks the wire and is not the Rust provider. Nothing here is evidence of
interoperability with `crates/tunnel-relay` or `crates/tunnel-fs-provider`, and
the gate is explicit that it cannot be: "compilation against a source interface
or a fake in-memory adapter is insufficient to claim remote compatibility".

## What is in it

| Module | What it owns |
| --- | --- |
| `src/ninep/` | The independent 9P2000.L codec (below) |
| `src/descriptor.ts` | The `agent-tunnel.fs.v1` descriptor, its validation and the HTTP failure vocabulary |
| `src/websocket.ts` | RFC 6455's client half, written out: no dependency can set `Authorization` |
| `src/session.ts` | The consumer session: lifecycle, tags, fids, flush, close codes, **outcome classification** |
| `src/paths.ts` | The virtual path namespace, refusing exactly what gate 1 refuses |
| `src/filesystem.ts` | `connectFilesystem`, the API methods, the composite operations and the budgets |
| `src/adapters/files-sdk.ts` | `createFilesAdapter`: `files-sdk` 2.4.0's `Adapter<Raw>`, the object view |
| `src/adapters/mastra.ts` | `TunnelMastraFilesystem`: `@mastra/core` 1.65.0's `WorkspaceFilesystem`, with both timestamp policies |
| `src/adapters/just-bash.ts` | `TunnelJustBashFilesystem`: `just-bash` 3.4.2's `IFileSystem`, plus `drainOperationFailures()` |
| `src/adapters/ai-sdk.ts` | `createFilesApi`: `@ai-sdk/provider` 4.0.11's `FilesV4`, managed references over one upload directory |
| `src/adapters/ai-sdk-tools.ts` | `createFilesystemTools`: an `ai` 7.0.94 `ToolSet` — `list_directory`, bounded `read_file`, `stat`, and `write_file` only when the grant advertises it — with hand-written Standard Schema inputs, abort propagation and model-visible `outcome`/`retrySafe` (re-exported from `/ai-sdk`) |
| `demo/` | `adapters-demo.ts`, the consumer of `scripts/adapters-demo.sh`, and `scripted-model.ts`, a deterministic `MockLanguageModelV4` for agent demos with no LLM |
| `src/adapters/outcomes.ts`, `keys.ts` | What the adapters share: the outcome vocabulary, and object keys |

The outcome classification is the obligation gate 5 named for this side: there
is no wire field for an outcome, so a client derives one from its own dispatch
and reply history. A request whose bytes never reached the transport is
`not_started`; a dispatched read that never answered is `failed`; a dispatched
**mutation** that never answered is `unknown`, whatever close code ended the
session, because the device may have performed it and no code on the wire says
which.

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

So are the four frameworks — `files-sdk` 2.4.0, `@mastra/core` 1.65.0,
`just-bash` 3.4.2, `ai` 7.0.94 and `@ai-sdk/provider` 4.0.11 — as exact dev
**and** peer dependencies. `typecheck` is where the adapters are checked against
their own declarations, which is the contract compilation
[`docs/testing.md`](../../docs/testing.md) asks for: every adapter source imports
the upstream types and is annotated with the upstream interface, with no `any`,
no assertion onto an upstream type and no suppressed error.

```sh
npm run test:peers
```

registers each adapter with the real thing that consumes it — `new Files({
adapter })`, `new Workspace({ filesystem })`, `new Bash({ fs })`,
`ai.uploadFile({ api })` — against the same loopback harness. It needs the
install and is therefore **not** part of `npm test`.

Two things a consumer has to know, both found by running the real packages:
`createFilesAdapter` takes the consumer's own `FilesError` class, because
`files-sdk`'s retry gate rebuilds a foreign error as a *retryable* one — it must
come from the **same module instance** as the `Files` it is passed to, and the
adapter cannot verify that, so a second installed copy makes every failure
including an `unknown` mutation retryable with nothing reporting it; and a
`Bash` over this filesystem needs `defenseInDepth: { excludeViolationTypes:
['setTimeout'] }`, because just-bash blocks the global for the duration of a
script and this client arms a timer for every request deadline.

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
* Four hand-transcription errors: three in `test/expected.ts` and one in the
  boundary expectations, described under "How the expectation table was built"
  below.

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

## Shared fuzzing

`fuzz/` generates 4,096 cases deterministically from one seed and both codecs
produce a verdict on every one: they must accept and agree, or both refuse.
`crates/tunnel-fs-ninep/tests/shared_fuzz.rs` is the Rust half and checks in its
verdicts; `npm test` regenerates the corpus from the seed, recomputes this
side's verdicts and compares. The two verdict files are byte-identical.

The corpus weights `NOTAG` for the version opcodes and draws `Rlerror` from an
errno pool, so all 41 message types are decoded. Agreement there is a weaker
result than it looks: both codecs decode an `Rversion`'s `msize` without judging
it, so it shows the rule is in **neither** codec, not that it belongs in a
session — and the Rust is the server end, with no consumer-side `Rversion` rule
to compare against.

```sh
node fuzz/generate.ts --seed 0x1 --cases 1024   # explore another seed
cargo test -p tunnel-fs-ninep --test shared_fuzz # re-derive the Rust verdicts
```

It found four disagreements, all in this implementation, all fixed and all
recorded in `docs/filesystem-api.md`'s gate-3 residue: frames discarded when a
later frame in the same push failed, a declared size checked at seven bytes
where the Rust checks at four, `Tversion`'s negotiation values judged inside the
codec, and two checks taken after a later field had been read.

The first two are in `FrameDecoder`, which is the **stream** rule — and this
client does not use it: a consumer decodes one message per WebSocket binary
message with `decodeExact`. They would be visible to a stream consumer this
package does not have. The fixes are right; the claim that they were visible on
this client's own socket path would not be.

## What is not proven here

* **Any relay and any device.** No test in this package has spoken to one. The
  transport is exercised against a loopback harness, which is a peer and not the
  product — and whose 9P layer is this package's own codec, so it is a second
  opinion about WebSocket framing only.
* **A graceful close.** `close()` rejects what is pending and closes the socket;
  it sends no `Tflush` and clunks no fid. The session ends either way, but an
  orderly shutdown is a different thing.
* **Addressing a host name this namespace refuses.** A POSIX host may hold a file
  called `notes.` or `CON`; the device lists it, gate 1 refuses it on every host
  so an export does not change meaning with the serving OS, and no path this
  client will send can name it. A recursive `remove` of the directory holding one
  therefore removes what it can and reports `EINVAL` naming that child.
* **TLS.** Every test endpoint is `http://127.0.0.1`, through the contract's own
  loopback development harness, which this client requires to be asked for
  explicitly and refuses for any non-loopback host.
* **A rotating device tunnel**, a cross-relay hop, a real grant, a real
  revocation, and every clock the contract names: this client enforces its own
  request deadline, and the device enforces none.
* **The four native adapters against a relay or a device, in a test.** They
  compile against their pinned published packages' own declarations and run
  against the real `Files`, `Workspace`, `Agent`, `Bash`, `generateText` and
  `ai.uploadFile` — but over the same loopback harness, so the same sentence
  applies. The relay-and-device evidence is the demo above (M4-64), which is
  run by hand; only the Mastra adapter is inside a harness gate
  (`verify-m4-fs-client-e2e`, M4-15).
* **The AI SDK live directory tools against a real model.** `createFilesystemTools`
  is tested for its schemas, bounds, abort propagation and model-visible
  outcomes, and driven by the real `generateText` with a scripted model; what a
  real model does with a `retrySafe: false` result is untested.
* **Aggregate budgets across borrowers.** The demo lends one client to all four
  adapters in sequence; no test closes one borrower while another has live fids,
  or drives two at once against the shared budget.

## Package scripts

| Script | What it does | Needs an install |
| --- | --- | --- |
| `npm test` | The offline suite | no |
| `npm run lint` | The invariants above, mechanically: no `any`, no suppressed error, framework imports type-only, no `console` in `src/`, zero runtime dependencies, exact pins that the lockfile resolves | no |
| `npm run typecheck` | `tsc` over `src/`, `test/`, `demo/`, `fuzz/` and `scripts/` | yes |
| `npm run build` | `tsconfig.build.json`: `src/` to `dist/` as JavaScript plus declarations, relative `.ts` imports rewritten | yes |
| `npm run test:peers` | Each adapter handed to its real framework over the loopback harness | yes |
| `npm run check` | All of the above, in that order | yes |
| `npm run demo:adapters` | `scripts/adapters-demo.sh`: the four adapters through a local relay and device | yes, plus cargo, docker, openssl |

All fixture values are synthetic, as `fixtures/README.md` records.
