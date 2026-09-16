/**
 * Protocol constants for the `agent-tunnel.9p.v1` profile.
 *
 * Every value here was written from the 9P2000.L definition (the diod
 * `protocol.md` dialect reference and the Linux v9fs headers named in
 * `docs/sources.md`) and from `docs/filesystem-api.md`. Nothing was copied
 * from `crates/tunnel-fs-ninep`: this file only has value as a cross-check if
 * it can disagree with it.
 */

/** The reserved tag. `Tversion`/`Rversion` require it; nothing else may use it. */
export const NOTAG = 0xffff;
/** The reserved fid. Only `Tattach`'s `afid` may carry it in this profile. */
export const NOFID = 0xffffffff;
/** The reserved numeric uid for `Tattach`. */
export const NONUNAME = 0xffffffff;

/** `size[4] type[1] tag[2]`. */
export const HEADER_BYTES = 7;

/** The profile's absolute ceiling on one 9P message, from `docs/filesystem-api.md`. */
export const MSIZE_CEILING = 65536;
/** The profile's floor on a negotiated `msize`. */
export const MSIZE_FLOOR = 256;

/** The dialect string this profile speaks, and the only one it accepts. */
export const VERSION = '9P2000.L';

/** 9P's `MAXWELEM`: the most names one `Twalk` may carry. */
export const MAXWELEM = 16;

/**
 * A counted reply's framing cost beyond its data: `size[4] type[1] tag[2]
 * count[4]`. A `Tread` or `Treaddir` asking for `count` bytes implies a reply
 * of `count + 11`.
 */
export const COUNTED_REPLY_OVERHEAD = HEADER_BYTES + 4;

/**
 * A `Twrite`'s framing cost beyond its data: the header plus `fid[4]
 * offset[8] count[4]`. An `Rwrite` may not acknowledge more bytes than a
 * `Twrite` could have carried in the first place.
 */
export const WRITE_REQUEST_OVERHEAD = HEADER_BYTES + 16;

/** The 41 message types of the profile, name to opcode. */
export const MESSAGE_TYPES = {
  Rlerror: 7,
  Tlopen: 12,
  Rlopen: 13,
  Tlcreate: 14,
  Rlcreate: 15,
  Tsymlink: 16,
  Rsymlink: 17,
  Trename: 20,
  Rrename: 21,
  Treadlink: 22,
  Rreadlink: 23,
  Tgetattr: 24,
  Rgetattr: 25,
  Tsetattr: 26,
  Rsetattr: 27,
  Treaddir: 40,
  Rreaddir: 41,
  Tlink: 70,
  Rlink: 71,
  Tmkdir: 72,
  Rmkdir: 73,
  Trenameat: 74,
  Rrenameat: 75,
  Tunlinkat: 76,
  Runlinkat: 77,
  Tversion: 100,
  Rversion: 101,
  Tattach: 104,
  Rattach: 105,
  Tflush: 108,
  Rflush: 109,
  Twalk: 110,
  Rwalk: 111,
  Tread: 116,
  Rread: 117,
  Twrite: 118,
  Rwrite: 119,
  Tclunk: 120,
  Rclunk: 121,
  Tremove: 122,
  Rremove: 123,
} as const;

export type MessageName = keyof typeof MESSAGE_TYPES;

/** Opcode to name, derived so the two tables cannot drift. */
export const NAME_BY_OPCODE = new Map<number, MessageName>(
  (Object.keys(MESSAGE_TYPES) as MessageName[]).map((name) => [MESSAGE_TYPES[name], name]),
);

/**
 * 9P and 9P2000.L opcodes that exist in the protocol but are outside this
 * profile. Refusing these differently from an opcode that is not a 9P opcode
 * at all is static protocol knowledge and discloses nothing about an export.
 *
 * **Cross-check note.** This list first held 27 entries, adding `Tlerror` (6)
 * and `Terror` (106); the Rust codec's `KNOWN_OUTSIDE_PROFILE` holds 25 and
 * omits both. That is the one classification the two implementations read
 * differently, and the Rust is right: 6 and 106 are *reserved numbering slots*
 * beside `Rlerror` (7) and `Rerror` (107), not opcodes any peer can send, so
 * answering "you reached for a real opcode the profile denies" would name a
 * message that does not exist. Both codecs refuse such a frame and both close
 * with 1002; only the diagnostic differed. Aligned here, with the reasoning
 * kept rather than the difference erased.
 */
export const KNOWN_OPCODES_NOT_IN_PROFILE = new Map<number, string>([
  [8, 'Tstatfs'],
  [9, 'Rstatfs'],
  [18, 'Tmknod'],
  [19, 'Rmknod'],
  [30, 'Txattrwalk'],
  [31, 'Rxattrwalk'],
  [32, 'Txattrcreate'],
  [33, 'Rxattrcreate'],
  [50, 'Tfsync'],
  [51, 'Rfsync'],
  [52, 'Tlock'],
  [53, 'Rlock'],
  [54, 'Tgetlock'],
  [55, 'Rgetlock'],
  [102, 'Tauth'],
  [103, 'Rauth'],
  [107, 'Rerror'],
  [112, 'Topen'],
  [113, 'Ropen'],
  [114, 'Tcreate'],
  [115, 'Rcreate'],
  [124, 'Tstat'],
  [125, 'Rstat'],
  [126, 'Twstat'],
  [127, 'Rwstat'],
]);

/** The three qid type bytes the profile emits. A bit outside them is refused. */
export const QTFILE = 0x00;
export const QTSYMLINK = 0x02;
export const QTDIR = 0x80;
export const QID_TYPES = new Set([QTFILE, QTSYMLINK, QTDIR]);

/** `dirent` type bytes, which an `Rreaddir` record carries beside its qid. */
export const DT_DIR = 4;
export const DT_REG = 8;
export const DT_LNK = 10;

/**
 * The one dirent byte each qid type implies. `docs/filesystem-api.md` requires
 * the two to agree rather than preferring one, so this is a bijection.
 */
export const DIRENT_BY_QID_TYPE = new Map<number, number>([
  [QTFILE, DT_REG],
  [QTDIR, DT_DIR],
  [QTSYMLINK, DT_LNK],
]);

/**
 * The closed `Rlerror` vocabulary: the fourteen codes of
 * `tunnel_fs_core::FsErrorCode`, as the Linux `.L` errno numbers an `Rlerror`
 * carries whatever host serves the export.
 */
export const ERRNO_BY_NAME = {
  EPERM: 1,
  ENOENT: 2,
  EACCES: 13,
  EEXIST: 17,
  EXDEV: 18,
  ENOTDIR: 20,
  EISDIR: 21,
  EINVAL: 22,
  EFBIG: 27,
  EROFS: 30,
  ENAMETOOLONG: 36,
  ENOTEMPTY: 39,
  ELOOP: 40,
  ENOTSUP: 95,
} as const;

export type ErrnoName = keyof typeof ERRNO_BY_NAME;

export const ERRNO_NAME_BY_NUMBER = new Map<number, ErrnoName>(
  (Object.keys(ERRNO_BY_NAME) as ErrnoName[]).map((name) => [ERRNO_BY_NAME[name], name]),
);

/** Linux open flags, written out. Their values are Linux's on every host. */
export const O_ACCMODE = 0o3;
export const O_RDONLY = 0o0;
export const O_WRONLY = 0o1;
export const O_RDWR = 0o2;
export const O_CREAT = 0o100;
export const O_EXCL = 0o200;
export const O_TRUNC = 0o1000;
export const O_APPEND = 0o2000;
export const O_DIRECTORY = 0o200000;
export const O_NOFOLLOW = 0o400000;

/**
 * The only flag bits `Tlopen` accepts. `O_CREAT`/`O_EXCL` are absent because
 * creation is `Tlcreate`; `O_NOFOLLOW` is present because the resolver applies
 * it unconditionally, so honouring a client that asks for it widens nothing.
 */
export const TLOPEN_FLAG_MASK = O_ACCMODE | O_TRUNC | O_APPEND | O_DIRECTORY | O_NOFOLLOW;

/** `Tsetattr` mask bits. */
export const SETATTR_MODE = 0x0001;
export const SETATTR_UID = 0x0002;
export const SETATTR_GID = 0x0004;
export const SETATTR_SIZE = 0x0008;
export const SETATTR_ATIME = 0x0010;
export const SETATTR_MTIME = 0x0020;
export const SETATTR_CTIME = 0x0040;
export const SETATTR_ATIME_SET = 0x0080;
export const SETATTR_MTIME_SET = 0x0100;

/** `uid`, `gid` and `ctime` are excluded: unsupported ownership fields. */
export const TSETATTR_VALID_MASK =
  SETATTR_MODE |
  SETATTR_SIZE |
  SETATTR_ATIME |
  SETATTR_MTIME |
  SETATTR_ATIME_SET |
  SETATTR_MTIME_SET;

/** `Tgetattr` request-mask bits. */
export const GETATTR_MODE = 0x00000001;
export const GETATTR_NLINK = 0x00000002;
export const GETATTR_UID = 0x00000004;
export const GETATTR_GID = 0x00000008;
export const GETATTR_RDEV = 0x00000010;
export const GETATTR_ATIME = 0x00000020;
export const GETATTR_MTIME = 0x00000040;
export const GETATTR_CTIME = 0x00000080;
export const GETATTR_INO = 0x00000100;
export const GETATTR_SIZE = 0x00000200;
export const GETATTR_BLOCKS = 0x00000400;
export const GETATTR_BTIME = 0x00000800;
export const GETATTR_GEN = 0x00001000;
export const GETATTR_DATA_VERSION = 0x00002000;
export const GETATTR_BASIC = 0x000007ff;
export const GETATTR_ALL = 0x00003fff;

/** `Tunlinkat` accepts only this flag. */
export const AT_REMOVEDIR = 0x200;
