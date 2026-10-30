import { formatChallenge } from './challenge.ts';
import type {
  BearerChallenge,
  ErrorCategory,
  ErrorReason,
  ErrorResponse,
  StepUpRequirement
} from './protocol.ts';

/** Why a token failed validation, in the order of the checks (docs/architecture/sdk.md). */
export type TokenReason = Extract<
  ErrorReason,
  | 'malformed'
  | 'unsupported_critical_header'
  | 'wrong_type'
  | 'unsupported_algorithm'
  | 'unknown_key'
  | 'bad_signature'
  | 'invalid_claims'
  | 'issuer_mismatch'
  | 'wrong_audience'
  | 'expired'
  | 'not_yet_valid'
  | 'issued_in_future'
  | 'nonce_mismatch'
  | 'wrong_authorized_party'
  | 'authentication_too_old'
  | 'lifetime_too_long'
>;

/**
 * What failed, as each kind of failure describes it. `code` is a category every SDK
 * shares (`piquel_common::protocol::sdk`), except `missing_token` and
 * `invalid_request`: a resource server's request carried no bearer token, or a
 * malformed `Authorization` header, which no other SDK reports as an error.
 */
export type AuthErrorDetail =
  | {
      code: Extract<ErrorCategory, 'discovery'>;
      reason?: Extract<ErrorReason, 'issuer_mismatch' | 'invalid_document' | 'pkce_unsupported'>;
    }
  | {
      code: Extract<ErrorCategory, 'keys'>;
      reason: Extract<ErrorReason, 'invalid_document' | 'duplicate_key_id'>;
    }
  | { code: Extract<ErrorCategory, 'invalid_token'>; reason: TokenReason }
  /** `scope` is every scope the request needs, space-separated. */
  | { code: Extract<ErrorCategory, 'insufficient_scope'>; scope: string }
  | {
      code: Extract<ErrorCategory, 'insufficient_user_authentication'>;
      requirement: StepUpRequirement;
    }
  | {
      code: Extract<ErrorCategory, 'callback'>;
      reason: Extract<
        ErrorReason,
        'state_mismatch' | 'issuer_mismatch' | 'missing_issuer' | 'missing_code'
      >;
    }
  | { code: Extract<ErrorCategory, 'oauth'>; response: ErrorResponse }
  | { code: Extract<ErrorCategory, 'network'> }
  | { code: 'missing_token' }
  | { code: 'invalid_request' };

/** An error category, or a resource server's request error. */
export type AuthErrorCode = AuthErrorDetail['code'];

/**
 * Every failure this SDK reports. `code` is the category and `reason` the check that
 * failed, the same values every SDK uses, so callers narrow on `code`:
 *
 * ```ts
 * try {
 *   const token = await api.authenticate(request);
 * } catch (error) {
 *   if (error instanceof AuthError) return error.toResponse(); // status and WWW-Authenticate
 *   throw error;
 * }
 * ```
 */
export class AuthError extends Error {
  override name = 'AuthError';
  /** What kind of operation failed. */
  readonly code: AuthErrorCode;
  /** Which check failed, for categories with several. */
  readonly reason: ErrorReason | undefined;
  /** The error auth answered with, for `oauth` errors. */
  readonly response: ErrorResponse | undefined;
  readonly #detail: AuthErrorDetail;
  /** The resource's protected resource metadata URL (RFC 9728), for its challenge. */
  #resourceMetadata: string | undefined;

  /** An error for `detail`, described by `message`, caused by `options.cause`. */
  constructor(detail: AuthErrorDetail, message: string, options: { cause?: unknown } = {}) {
    super(message, options);
    this.#detail = detail;
    this.code = detail.code;
    this.reason = 'reason' in detail ? detail.reason : undefined;
    this.response = detail.code === 'oauth' ? detail.response : undefined;
  }

  /** @internal Names the resource that failed, so its challenge carries `resource_metadata`. */
  forResource(metadata: string | undefined): this {
    this.#resourceMetadata ??= metadata;
    return this;
  }

  /**
   * The `WWW-Authenticate: Bearer` challenge a resource server answers with
   * (RFC 6750 §3, RFC 9470 §3), or `undefined` when the failure is the server's own,
   * such as signing keys that cannot be fetched.
   */
  challenge(): BearerChallenge | undefined {
    const detail = this.#detail;
    const metadata: BearerChallenge = {};
    if (this.#resourceMetadata !== undefined) metadata.resource_metadata = this.#resourceMetadata;
    switch (detail.code) {
      case 'missing_token':
        return metadata;
      case 'invalid_request':
      case 'invalid_token':
        return { error: detail.code, ...metadata };
      case 'insufficient_scope':
        return { error: detail.code, scope: detail.scope, ...metadata };
      case 'insufficient_user_authentication':
        return { error: detail.code, ...detail.requirement, ...metadata };
      default:
        return undefined;
    }
  }

  /**
   * The response a resource server answers with: the challenge's status and
   * `WWW-Authenticate` header, or 503 without one when the failure is the server's.
   */
  toResponse(): Response {
    const challenge = this.challenge();
    if (challenge === undefined) return new Response(null, { status: 503 });
    const { status, header } = formatChallenge(challenge);
    return new Response(null, { status, headers: { 'www-authenticate': header } });
  }
}
