# 9P2000.L golden fixtures

Byte-exact wire fixtures for the `agent-tunnel.9p.v1` profile, produced by
`crates/tunnel-fs-ninep` and **intended to be shared with the TypeScript
client** when it is written (implementation gate 6 of
[`docs/filesystem-api.md`](../../../docs/filesystem-api.md)). They are checked
in so that a change to the wire format is a visible diff rather than an
incidental one, and `tests/golden.rs` compares them in both directions.

## Format

One message per file, `<name>.hex`. Every file begins with `#` comment lines
naming the message type, its opcode, the tag and the byte length, then the
message's bytes as lowercase hex, 32 bytes per line. `index.txt` lists every
`.hex` file, one per line; a test asserts the index and the directory agree, and
that every message type in the profile has a fixture.

A reader in any language needs three rules: strip `#` lines, strip whitespace,
parse hex pairs. The result is the complete 9P message including its
`size[4] type[1] tag[2]` header.

## What the bytes pin

* **Little-endian** integers throughout, at the widths 9P2000.L gives them.
  `Rgetattr` and the offsets in `Tread`/`Twrite`/`Treaddir` are 64-bit; a
  JavaScript client must decode those as `BigInt`, and `rgetattr.hex` and
  `tread.hex` both carry a value above 2^32 so a client that used a `number`
  would fail here rather than in production.
* **`string[s]` is a 16-bit BYTE count** of UTF-8, not a character count.
  `twalk.hex`, `rreaddir.hex` and several others carry a name with a two-byte
  and a four-byte code point in it, so an implementation that counted UTF-16
  units would produce a different length.
* **`qid[13]`** is `type[1] version[4] path[8]`, and the profile emits only
  `QTFILE` (0x00), `QTDIR` (0x80) and `QTSYMLINK` (0x02).
* **`Rreaddir`'s payload** is a packed array of
  `qid[13] offset[8] type[1] name[s]` records with no count of its own; the
  block ends when the declared `count` does, and a block that ends part-way
  through a record is malformed.
* **`Rlerror` carries a Linux errno**, whatever host serves the export, and the
  vocabulary is closed to the fourteen codes in `tunnel_fs_core::FsErrorCode`.

## Regenerating

```text
cargo test -p tunnel-fs-ninep --test golden -- --ignored regenerate
```

Then read the diff. The regeneration test is `#[ignore]`d so an ordinary run
cannot rewrite the evidence it is supposed to check.

## Provenance

Every value in these fixtures is synthetic. No path, file name, link target or
byte string here came from a real filesystem.
