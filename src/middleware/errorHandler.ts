import type { NextFunction, Request, Response } from 'express'
import { ZodError } from 'zod'
import { isProduction } from '../config/env'
import {
  AccountLockedError,
  AppError,
  MfaRequiredError,
  NotFoundError,
  RateLimitError,
  ValidationError,
  isAppError,
} from '../core/errors'
import type { ErrorBody } from '../core/http'
import { logger } from '../observability/logger'
import { httpErrorsTotal } from '../observability/metrics'
import { formatZodError } from './validate'

/**
 * The single place an error becomes a response.
 *
 * The invariant: an `AppError` is a failure we chose to describe, so its message is
 * safe to return. Everything else is a bug or a dependency blowing up, and its
 * message could be a SQL string, a file path, or a connection URL with a password in
 * it — so it is logged in full and replaced with a generic 500 for the client.
 */
export function errorHandler(err: unknown, req: Request, res: Response, next: NextFunction): void {
  // Express requires the 4-arity signature; if headers are already sent, the only
  // correct move is to let Express destroy the socket.
  if (res.headersSent) return next(err)

  const normalised = normalise(err)
  const { status, code } = normalised

  httpErrorsTotal.inc({ code, status_code: String(status) })

  // 5xx is our fault: full stack, error level. 4xx is the client's: no stack, and
  // only 401/403/429 are interesting enough to warn about.
  if (status >= 500) {
    logger.error({ err, status, code, method: req.method, path: req.path }, normalised.logMessage)
  } else if (status === 401 || status === 403 || status === 429 || status === 423) {
    logger.warn({ status, code, method: req.method, path: req.path }, normalised.logMessage)
  } else {
    logger.debug({ status, code, method: req.method, path: req.path }, normalised.logMessage)
  }

  const body: ErrorBody = {
    success: false,
    error: { code, message: normalised.message },
    requestId: req.requestId,
  }

  if (normalised.details !== undefined) body.error.details = normalised.details

  // Stack traces are a development affordance and an information-disclosure bug in
  // production. Gate on NODE_ENV, never on a request header or query param.
  if (!isProduction && err instanceof Error && status >= 500) {
    ;(body.error as Record<string, unknown>).stack = err.stack
  }

  applyHeaders(res, err)
  res.status(status).json(body)
}

interface Normalised {
  status: number
  code: string
  message: string
  details?: unknown
  logMessage: string
}

function normalise(err: unknown): Normalised {
  if (isAppError(err)) {
    return {
      status: err.status,
      code: err.code,
      message: err.message,
      details: err.details,
      logMessage: err.message,
    }
  }

  // A Zod error that escaped `validate()` — e.g. thrown by a service parsing an
  // external payload. Treat it as a 400, but never echo the received value.
  if (err instanceof ZodError) {
    const e = new ValidationError()
    return { status: 400, code: e.code, message: e.message, details: formatZodError(err), logMessage: 'Validation error' }
  }

  // Body parser failures. `express.json()` raises these before any of our code runs.
  const httpErr = err as { type?: string; status?: number; statusCode?: number; expose?: boolean }
  if (httpErr?.type === 'entity.too.large') {
    return { status: 413, code: 'PAYLOAD_TOO_LARGE', message: 'Request body is too large', logMessage: 'Payload too large' }
  }
  if (httpErr?.type === 'entity.parse.failed') {
    return { status: 400, code: 'VALIDATION_ERROR', message: 'Request body is not valid JSON', logMessage: 'Malformed JSON body' }
  }
  if (httpErr?.type === 'charset.unsupported' || httpErr?.type === 'encoding.unsupported') {
    return { status: 415, code: 'UNSUPPORTED_MEDIA_TYPE', message: 'Unsupported content encoding', logMessage: 'Unsupported encoding' }
  }

  // Prisma: a unique violation that a service failed to translate is still a 409, not
  // a 500 — but we log it as a gap, because the service should have said something useful.
  const prismaCode = (err as { code?: string })?.code
  if (typeof prismaCode === 'string' && prismaCode.startsWith('P2')) {
    if (prismaCode === 'P2025') {
      const e = new NotFoundError()
      return { status: e.status, code: e.code, message: e.message, logMessage: 'Prisma P2025' }
    }
    if (prismaCode === 'P2002') {
      return { status: 409, code: 'CONFLICT', message: 'This resource already exists', logMessage: 'Untranslated Prisma P2002' }
    }
  }

  return {
    status: 500,
    code: 'INTERNAL_ERROR',
    message: 'An unexpected error occurred',
    logMessage: err instanceof Error ? err.message : 'Unknown error',
  }
}

/** Errors that carry protocol-level headers alongside their status. */
function applyHeaders(res: Response, err: unknown): void {
  if (err instanceof RateLimitError || err instanceof AccountLockedError) {
    res.setHeader('Retry-After', String(err.retryAfterSeconds))
  }
  if (err instanceof MfaRequiredError) {
    // The challenge token belongs in the body, not a header, but signal the step-up
    // in the standard place so a generic client can react.
    res.setHeader('WWW-Authenticate', 'Bearer realm="amrutam", error="mfa_required"')
  }
  if (err instanceof AppError && err.status === 401 && !(err instanceof MfaRequiredError)) {
    res.setHeader('WWW-Authenticate', 'Bearer realm="amrutam"')
  }
}

export function notFoundHandler(req: Request, res: Response): void {
  const body: ErrorBody = {
    success: false,
    error: { code: 'NOT_FOUND', message: `Cannot ${req.method} ${req.path}` },
    requestId: req.requestId,
  }
  httpErrorsTotal.inc({ code: 'NOT_FOUND', status_code: '404' })
  res.status(404).json(body)
}
