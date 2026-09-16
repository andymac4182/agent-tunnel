/**
 * Two error kinds, because the profile answers them two different ways, and
 * the distinction is the whole point of keeping them apart.
 *
 * [`NinepError`] is a **framing or well-formedness failure**, which
 * `docs/filesystem-api.md` answers by closing the WebSocket with 1002 — never
 * with an `Rlerror`, because the tag that would correlate the reply is part of
 * the frame that failed to decode.
 *
 * [`ProfileRefusal`] is a **request the session refuses while staying open**,
 * answered with an `Rlerror` on the request's own tag. The contract names "a
 * flag the profile denies" in exactly this group. Answering one of these with a
 * close would take down a session carrying other outstanding tags.
 *
 * The first version of this file had only the framing kind, and put the `.L`
 * flag and mask checks in it. That was a wire-visible disagreement with the
 * Rust — see `docs/filesystem-api.md`'s gate-3 residue — and this split is the
 * fix.
 *
 * The reason is a closed string union rather than free text so a test can
 * assert *which* rule refused an input, which is the whole point of a second
 * implementation: "it threw" is not a cross-check.
 */

export type NinepErrorReason =
  | 'HeaderFloor'
  | 'OverCeiling'
  | 'OverMsize'
  | 'TruncatedBody'
  | 'TrailingBytes'
  | 'SizeDisagreesWithBuffer'
  | 'UnknownMessageType'
  | 'MessageTypeNotInProfile'
  | 'NotagRequired'
  | 'NotagForbidden'
  | 'InvalidUtf8'
  | 'QidType'
  | 'DirentTypeDisagreesWithQid'
  | 'ErrnoNotInVocabulary'
  | 'TooManyWalkElements'
  | 'UnsupportedVersion'
  | 'MsizeBelowFloor'
  | 'CountAboveMsize'
  | 'MalformedDirentBlock'
  | 'FieldOutOfRange'
  | 'FieldTooLarge'
  | 'TagOutOfRange'
  | 'DecoderLatched';

/** A framing or well-formedness failure. Answered by closing with 1002. */
export class NinepError extends Error {
  readonly reason: NinepErrorReason;
  /** The field that failed, where the failure is attributable to one. */
  readonly field: string | undefined;

  constructor(reason: NinepErrorReason, field?: string) {
    super(field === undefined ? reason : `${reason} (${field})`);
    this.name = 'NinepError';
    this.reason = reason;
    this.field = field;
  }
}

export function fail(reason: NinepErrorReason, field?: string): never {
  throw new NinepError(reason, field);
}

/** Why a well-formed request is nonetheless refused by the profile. */
export type ProfileRefusalReason = 'FlagNotInProfile' | 'MaskNotInProfile' | 'EmptyMask';

/**
 * A well-formed message the profile declines to act on. The frame decoded
 * cleanly, so its tag is trustworthy and the session answers `Rlerror` on it
 * and stays open.
 */
export class ProfileRefusal extends Error {
  readonly reason: ProfileRefusalReason;
  readonly field: string;
  /**
   * The errno an `Rlerror` would carry. `ENOTSUP`: the profile does not
   * implement the flag, as distinct from the host denying it.
   */
  readonly errno = 'ENOTSUP' as const;

  constructor(reason: ProfileRefusalReason, field: string) {
    super(`${reason} (${field})`);
    this.name = 'ProfileRefusal';
    this.reason = reason;
    this.field = field;
  }
}

export function refuse(reason: ProfileRefusalReason, field: string): never {
  throw new ProfileRefusal(reason, field);
}
