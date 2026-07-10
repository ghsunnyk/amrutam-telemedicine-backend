export type ErrorCode =
  // 400s
  | 'VALIDATION_ERROR'
  | 'INVALID_CREDENTIALS'
  | 'MFA_REQUIRED'
  | 'INVALID_MFA_CODE'
  | 'UNAUTHENTICATED'
  | 'TOKEN_EXPIRED'
  | 'TOKEN_INVALID'
  | 'FORBIDDEN'
  | 'NOT_FOUND'
  | 'CONFLICT'
  | 'SLOT_UNAVAILABLE'
  | 'IDEMPOTENCY_KEY_REUSED'
  | 'IDEMPOTENT_REQUEST_IN_PROGRESS'
  | 'ACCOUNT_LOCKED'
  | 'ACCOUNT_INACTIVE'
  | 'EMAIL_NOT_VERIFIED'
  | 'PAYLOAD_TOO_LARGE'
  | 'UNSUPPORTED_MEDIA_TYPE'
  | 'RATE_LIMITED'
  | 'PRECONDITION_FAILED'
  // 500s
  | 'INTERNAL_ERROR'
  | 'SERVICE_UNAVAILABLE'
  | 'DEPENDENCY_FAILURE'

export abstract class AppError extends Error {
  abstract readonly status: number
  abstract readonly code: ErrorCode

  readonly details?: unknown
  readonly isOperational = true
  readonly retryable: boolean

  constructor(
    message: string,
    options?: { details?: unknown; cause?: unknown; retryable?: boolean }
  ) {
    super(message, { cause: options?.cause })
    this.name = new.target.name
    this.details = options?.details
    this.retryable = options?.retryable ?? false
    Error.captureStackTrace?.(this, new.target)
  }
}

export class ValidationError extends AppError {
  readonly status = 400
  readonly code = 'VALIDATION_ERROR' as const
  constructor(message = 'Request validation failed', details?: unknown) {
    super(message, { details })
  }
}

export class UnauthenticatedError extends AppError {
  readonly status = 401
  readonly code: ErrorCode
  constructor(message = 'Authentication required', code: ErrorCode = 'UNAUTHENTICATED') {
    super(message)
    this.code = code
  }
}

export class InvalidCredentialsError extends AppError {
  readonly status = 401
  readonly code = 'INVALID_CREDENTIALS' as const
  constructor() {
    super('Invalid email or password')
  }
}

export class MfaRequiredError extends AppError {
  readonly status = 401
  readonly code = 'MFA_REQUIRED' as const
  constructor(readonly mfaToken: string) {
    super('Multi-factor authentication required', { details: { mfaRequired: true, mfaToken } })
  }
}

export class ForbiddenError extends AppError {
  readonly status = 403
  readonly code: ErrorCode
  constructor(
    message = 'You do not have permission to perform this action',
    code: ErrorCode = 'FORBIDDEN'
  ) {
    super(message)
    this.code = code
  }
}

export class NotFoundError extends AppError {
  readonly status = 404
  readonly code = 'NOT_FOUND' as const
  constructor(resource = 'Resource', id?: string) {
    super(id ? `${resource} '${id}' was not found` : `${resource} was not found`)
  }
}

export class ConflictError extends AppError {
  readonly status = 409
  readonly code: ErrorCode
  constructor(message: string, code: ErrorCode = 'CONFLICT', details?: unknown) {
    super(message, { details })
    this.code = code
  }
}

export class IdempotencyKeyReusedError extends AppError {
  readonly status = 422
  readonly code = 'IDEMPOTENCY_KEY_REUSED' as const
  constructor() {
    super('This Idempotency-Key was already used with a different request payload')
  }
}

export class IdempotentRequestInProgressError extends AppError {
  readonly status = 409
  readonly code = 'IDEMPOTENT_REQUEST_IN_PROGRESS' as const
  constructor() {
    super('A request with this Idempotency-Key is currently being processed', { retryable: true })
  }
}

export class AccountLockedError extends AppError {
  readonly status = 423
  readonly code = 'ACCOUNT_LOCKED' as const
  constructor(readonly retryAfterSeconds: number) {
    super('Account temporarily locked after too many failed sign-in attempts')
  }
}

export class RateLimitError extends AppError {
  readonly status = 429
  readonly code = 'RATE_LIMITED' as const
  constructor(readonly retryAfterSeconds: number) {
    super('Too many requests', { retryable: true })
  }
}

export class PreconditionFailedError extends AppError {
  readonly status = 412
  readonly code = 'PRECONDITION_FAILED' as const
  constructor(message = 'Resource was modified by another request') {
    super(message, { retryable: true })
  }
}

export class InternalError extends AppError {
  readonly status = 500
  readonly code = 'INTERNAL_ERROR' as const
  constructor(message = 'An unexpected error occurred', cause?: unknown) {
    super(message, { cause })
  }
}

export class ServiceUnavailableError extends AppError {
  readonly status = 503
  readonly code = 'SERVICE_UNAVAILABLE' as const
  constructor(message = 'Service temporarily unavailable', cause?: unknown) {
    super(message, { cause, retryable: true })
  }
}

export class DependencyFailureError extends AppError {
  readonly status = 502
  readonly code = 'DEPENDENCY_FAILURE' as const
  constructor(
    readonly dependency: string,
    cause?: unknown
  ) {
    super(`Upstream dependency '${dependency}' failed`, { cause, retryable: true })
  }
}

export const isAppError = (e: unknown): e is AppError => e instanceof AppError
