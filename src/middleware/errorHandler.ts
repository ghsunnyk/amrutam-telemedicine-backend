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

export function errorHandler(err: unknown, req: Request, res: Response, next: NextFunction): void {
  if (res.headersSent) return next(err)

  const normalised = normalise(err)
  const { status, code } = normalised

  httpErrorsTotal.inc({ code, status_code: String(status) })

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

  if (err instanceof ZodError) {
    const e = new ValidationError()
    return {
      status: 400,
      code: e.code,
      message: e.message,
      details: formatZodError(err),
      logMessage: 'Validation error',
    }
  }

  const httpErr = err as { type?: string; status?: number; statusCode?: number; expose?: boolean }
  if (httpErr?.type === 'entity.too.large') {
    return {
      status: 413,
      code: 'PAYLOAD_TOO_LARGE',
      message: 'Request body is too large',
      logMessage: 'Payload too large',
    }
  }
  if (httpErr?.type === 'entity.parse.failed') {
    return {
      status: 400,
      code: 'VALIDATION_ERROR',
      message: 'Request body is not valid JSON',
      logMessage: 'Malformed JSON body',
    }
  }
  if (httpErr?.type === 'charset.unsupported' || httpErr?.type === 'encoding.unsupported') {
    return {
      status: 415,
      code: 'UNSUPPORTED_MEDIA_TYPE',
      message: 'Unsupported content encoding',
      logMessage: 'Unsupported encoding',
    }
  }

  const prismaCode = (err as { code?: string })?.code
  if (typeof prismaCode === 'string' && prismaCode.startsWith('P2')) {
    if (prismaCode === 'P2025') {
      const e = new NotFoundError()
      return { status: e.status, code: e.code, message: e.message, logMessage: 'Prisma P2025' }
    }
    if (prismaCode === 'P2002') {
      return {
        status: 409,
        code: 'CONFLICT',
        message: 'This resource already exists',
        logMessage: 'Untranslated Prisma P2002',
      }
    }
  }

  return {
    status: 500,
    code: 'INTERNAL_ERROR',
    message: 'An unexpected error occurred',
    logMessage: err instanceof Error ? err.message : 'Unknown error',
  }
}

function applyHeaders(res: Response, err: unknown): void {
  if (err instanceof RateLimitError || err instanceof AccountLockedError) {
    res.setHeader('Retry-After', String(err.retryAfterSeconds))
  }
  if (err instanceof MfaRequiredError) {
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
