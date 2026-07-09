import pino, { type Logger, type LoggerOptions } from 'pino'
import { env, isProduction, isTest } from '../config/env'
import { getContext } from './requestContext'

/**
 * Structured JSON logs to stdout. The container runtime ships them; the app never
 * writes to a file or knows about a log backend.
 *
 * Two independent defences against leaking secrets:
 *  1. `redact` scrubs known-sensitive paths from whatever object is logged.
 *  2. `SENSITIVE_KEYS` is enforced in code review and by the `no-restricted-syntax`
 *     lint rule — never log a whole request body or a Prisma `User` row.
 */
const REDACT_PATHS = [
  'password',
  'newPassword',
  'currentPassword',
  'passwordHash',
  'token',
  'accessToken',
  'refreshToken',
  'mfaToken',
  'totpCode',
  'mfaSecret',
  'recoveryCodes',
  'authorization',
  'cookie',
  'set-cookie',
  // nested under the shapes pino-http logs
  'req.headers.authorization',
  'req.headers.cookie',
  'req.headers["x-api-key"]',
  'req.headers["idempotency-key"]',
  'res.headers["set-cookie"]',
  'body.password',
  'body.newPassword',
  'body.currentPassword',
  'body.totpCode',
  'err.config.headers.authorization',
]

const options: LoggerOptions = {
  level: isTest ? 'silent' : env.LOG_LEVEL,
  base: {
    service: env.OTEL_SERVICE_NAME,
    env: env.NODE_ENV,
    // Lets us tell which pod produced a line without a sidecar annotation.
    instance: process.env.HOSTNAME ?? undefined,
  },
  redact: { paths: REDACT_PATHS, censor: '[REDACTED]' },
  timestamp: pino.stdTimeFunctions.isoTime,
  formatters: {
    // Loki/Datadog expect `level: "info"`, not `level: 30`.
    level: (label) => ({ level: label }),
  },
  /**
   * Every line gets the ambient request/trace ids without callers passing them.
   * This is what makes "show me all logs for trace X" a one-click query.
   */
  mixin() {
    const ctx = getContext()
    if (!ctx) return {}
    return {
      requestId: ctx.requestId,
      traceId: ctx.traceId,
      spanId: ctx.spanId,
      userId: ctx.userId,
    }
  },
  serializers: {
    err: pino.stdSerializers.err,
  },
}

export const logger: Logger = pino(
  options,
  // Pretty output is a dev nicety only; in prod the transport costs a worker thread.
  isProduction || isTest
    ? pino.destination({ sync: false })
    : pino.transport({ target: 'pino-pretty', options: { colorize: true, translateTime: 'HH:MM:ss.l', ignore: 'pid,hostname,service,env' } })
)

/** Child logger tagged with a module name, e.g. `createLogger('booking')`. */
export const createLogger = (module: string): Logger => logger.child({ module })
