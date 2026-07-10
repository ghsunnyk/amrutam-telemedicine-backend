import pino, { type Logger, type LoggerOptions } from 'pino'
import { env, isProduction, isTest } from '../config/env'
import { getContext } from './requestContext'

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
    instance: process.env.HOSTNAME ?? undefined,
  },
  redact: { paths: REDACT_PATHS, censor: '[REDACTED]' },
  timestamp: pino.stdTimeFunctions.isoTime,
  formatters: {
    level: label => ({ level: label }),
  },
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
  isProduction || isTest
    ? pino.destination({ sync: false })
    : pino.transport({
        target: 'pino-pretty',
        options: {
          colorize: true,
          translateTime: 'HH:MM:ss.l',
          ignore: 'pid,hostname,service,env',
        },
      })
)

export const createLogger = (module: string): Logger => logger.child({ module })
