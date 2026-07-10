import type { NextFunction, Request, RequestHandler, Response } from 'express'
import { createHash } from 'node:crypto'
import { env } from '../config/env'
import { RateLimitError } from '../core/errors'
import type { Db } from '../db/prisma'
import { createLogger } from '../observability/logger'
import { rateLimitRejectionsTotal } from '../observability/metrics'

const log = createLogger('ratelimit')

export interface RateLimitPolicy {
  name: string
  capacity: number
  refillPerSecond: number
  cost?: number
  keyBy?: (req: Request) => string
}

interface BucketResult {
  allowed: boolean
  tokens_remaining: number
  retry_after_seconds: number
}

export function rateLimit(db: Db, policy: RateLimitPolicy): RequestHandler {
  if (!env.RATE_LIMIT_ENABLED) return (_req, _res, next) => next()

  const cost = policy.cost ?? 1
  const ttlSeconds = Math.max(60, Math.ceil((policy.capacity / policy.refillPerSecond) * 2))

  return async (req: Request, res: Response, next: NextFunction) => {
    const identity = policy.keyBy ? policy.keyBy(req) : defaultIdentity(req)
    const bucketId = `${policy.name}:${identity}`

    try {
      const [result] = await db.$queryRaw<BucketResult[]>`
        SELECT allowed, tokens_remaining, retry_after_seconds
        FROM consume_rate_limit_token(
          ${bucketId}::text,
          ${policy.capacity}::double precision,
          ${policy.refillPerSecond}::double precision,
          ${cost}::double precision,
          ${ttlSeconds}::int
        )
      `

      if (!result) throw new Error('rate limiter returned no row')

      res.setHeader(
        'RateLimit-Policy',
        `${policy.capacity};w=${Math.ceil(policy.capacity / policy.refillPerSecond)}`
      )
      res.setHeader('RateLimit-Limit', String(policy.capacity))
      res.setHeader('RateLimit-Remaining', String(Math.max(0, Math.floor(result.tokens_remaining))))

      if (!result.allowed) {
        const retryAfter = Math.max(1, Math.ceil(result.retry_after_seconds))
        rateLimitRejectionsTotal.inc({ policy: policy.name })
        res.setHeader('Retry-After', String(retryAfter))
        return next(new RateLimitError(retryAfter))
      }

      next()
    } catch (err) {
      if (err instanceof RateLimitError) return next(err)

      log.error({ err, policy: policy.name }, 'Rate limiter unavailable — failing open')
      next()
    }
  }
}

function defaultIdentity(req: Request): string {
  if (req.auth?.userId) return `user:${req.auth.userId}`
  const ip = req.ip ?? 'unknown'
  return `ip:${createHash('sha256').update(ip).digest('hex').slice(0, 24)}`
}

export const keyByBodyField =
  (field: string) =>
  (req: Request): string => {
    const value = (req.body as Record<string, unknown> | undefined)?.[field]
    const raw = typeof value === 'string' ? value.toLowerCase().slice(0, 254) : 'unknown'
    return `field:${createHash('sha256').update(raw).digest('hex').slice(0, 24)}`
  }

export const policies = {
  global: {
    name: 'global',
    capacity: env.RATE_LIMIT_GLOBAL_CAPACITY,
    refillPerSecond: env.RATE_LIMIT_GLOBAL_REFILL_PER_SEC,
  },

  login: { name: 'auth.login', capacity: 5, refillPerSecond: 1 / 30 },

  loginPerAccount: {
    name: 'auth.login.account',
    capacity: 10,
    refillPerSecond: 1 / 30,
    keyBy: keyByBodyField('email'),
  },

  register: { name: 'auth.register', capacity: 3, refillPerSecond: 1 / 300 },

  passwordReset: { name: 'auth.password_reset', capacity: 3, refillPerSecond: 1 / 300 },

  mfaChallenge: { name: 'auth.mfa', capacity: 5, refillPerSecond: 1 / 20, cost: 1 },

  refresh: { name: 'auth.refresh', capacity: 10, refillPerSecond: 1 / 60 },

  booking: { name: 'booking.write', capacity: 20, refillPerSecond: 1 },

  search: { name: 'search', capacity: 60, refillPerSecond: 5 },
} satisfies Record<string, RateLimitPolicy>
