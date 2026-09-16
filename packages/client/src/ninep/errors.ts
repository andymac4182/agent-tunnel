/**
 * Codec failures. Every one of these is a framing or well-formedness failure,
 * which `docs/filesystem-api.md` answers by closing the WebSocket with 1002 —
 * never with an `Rlerror`, because the tag that would correlate the reply is
 * part of the frame that failed to decode.
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
  | 'FlagNotInProfile'
  | 'MaskNotInProfile'
  | 'EmptyMask'
  | 'CountLeavesNoRoomForFraming'
  | 'MalformedDirentBlock'
  | 'FieldTooLarge'
  | 'TagOutOfRange'
  | 'DecoderLatched';

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
