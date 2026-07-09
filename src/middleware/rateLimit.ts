import { createHash } from 'node:crypto'
import type { NextFunction, Request, RequestHandler, Response } from 'express'
import { env } from '../config/env'
import { RateLimitError } from '../core/errors'
import type { Db } from '../db/prisma'
import { createLogger } from '../observability/logger'
import { rateLimitRejectionsTotal } from '../observability/metrics'

const log = createLogger('ratelimit')

export interface RateLimitPolicy {
  /** Stable name; becomes part of the bucket key and the metric label. */
  name: string
  /** Burst size — the most requests allowed back-to-back from a cold bucket. */
  capacity: number
  /** Sustained rate, tokens per second. */
  refillPerSecond: number
  /** Tokens a single request costs. Raise it for expensive endpoints. */
  cost?: number
  /** How the caller is identified. Defaults to user id, falling back to IP. */
  keyBy?: (req: Request) => string
}

interface BucketResult {
  allowed: boolean
  tokens_remaining: number
  retry_after_seconds: number
}

/**
 * Token bucket, evaluated by `consume_rate_limit_token()` inside Postgres.
 *
 * Why Postgres and not Redis: the limiter must be *shared* across API replicas — an
 * in-memory bucket per pod multiplies the real limit by the replica count, which is
 * exactly the bug that makes credential-stuffing defences useless in production. We
 * already run a highly-available Postgres; adding Redis would mean a second stateful
 * system to secure, patch, monitor and fail over, to hold data that fits in a table.
 * The cost is one indexed UPSERT (~0.3 ms local) per limited request.
 *
 * The token-bucket shape (rather than a fixed window) is what gives us both a burst
 * allowance and a smooth sustained rate, without the boundary-doubling problem where
 * a client fires `capacity` requests at 09:59:59.9 and `capacity` more at 10:00:00.0.
 */
export function rateLimit(db: Db, policy: RateLimitPolicy): RequestHandler {
  if (!env.RATE_LIMIT_ENABLED) return (_req, _res, next) => next()

  const cost = policy.cost ?? 1
  // Keep a bucket alive well past the time it takes to refill from empty; deleting it
  // early would hand a fresh burst allowance to a client that just exhausted one.
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

      res.setHeader('RateLimit-Policy', `${policy.capacity};w=${Math.ceil(policy.capacity / policy.refillPerSecond)}`)
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

      // Fail *open*. A database hiccup should not take authentication offline, and
      // the limiter is a mitigation, not the only control (argon2 cost and account
      // lockout still apply). This is a deliberate availability-over-security trade
      // for a non-authoritative check; it is logged loudly so it cannot hide.
      log.error({ err, policy: policy.name }, 'Rate limiter unavailable — failing open')
      next()
    }
  }
}

/**
 * Authenticated callers are limited per-account, so one user on a shared NAT cannot
 * exhaust the quota of everyone behind it. Anonymous callers fall back to IP.
 *
 * The IP is hashed, both because it lands in a table we may dump for debugging and
 * because it keeps the key length bounded regardless of IPv6 formatting.
 */
function defaultIdentity(req: Request): string {
  if (req.auth?.userId) return `user:${req.auth.userId}`
  const ip = req.ip ?? 'unknown'
  return `ip:${createHash('sha256').update(ip).digest('hex').slice(0, 24)}`
}

/** Limit by a body field (the email on a login attempt), independent of source IP. */
export const keyByBodyField =
  (field: string) =>
  (req: Request): string => {
    const value = (req.body as Record<string, unknown> | undefined)?.[field]
    const raw = typeof value === 'string' ? value.toLowerCase().slice(0, 254) : 'unknown'
    return `field:${createHash('sha256').update(raw).digest('hex').slice(0, 24)}`
  }

/**
 * Named policies. Numbers are sized against the SLO (100k consultations/day ≈ 1.2 rps
 * of bookings at mean, ~10 rps at peak) with generous headroom for retries, then
 * tightened hard on the endpoints an attacker cares about.
 */
export const policies = {
  /** Backstop for everything, per user or IP. */
  global: {
    name: 'global',
    capacity: env.RATE_LIMIT_GLOBAL_CAPACITY,
    refillPerSecond: env.RATE_LIMIT_GLOBAL_REFILL_PER_SEC,
  },

  /**
   * Credential stuffing runs at thousands of attempts per account. Five bursts then
   * one every 30s makes an online guessing attack pointless, and argon2 makes each
   * attempt cost the attacker ~50 ms of *our* CPU — which is why this is also a DoS
   * control, not only an auth control.
   */
  login: { name: 'auth.login', capacity: 5, refillPerSecond: 1 / 30 },

  /** Keyed on the email, so rotating source IPs does not reset the budget. */
  loginPerAccount: {
    name: 'auth.login.account',
    capacity: 10,
    refillPerSecond: 1 / 30,
    keyBy: keyByBodyField('email'),
  },

  register: { name: 'auth.register', capacity: 3, refillPerSecond: 1 / 300 },

  /** Password reset and email verification send mail — abuse is a spam vector. */
  passwordReset: { name: 'auth.password_reset', capacity: 3, refillPerSecond: 1 / 300 },

  /** Recovery codes are checked with argon2 against up to 10 hashes: expensive. */
  mfaChallenge: { name: 'auth.mfa', capacity: 5, refillPerSecond: 1 / 20, cost: 1 },

  /** Refresh is legitimate every 15 minutes; anything faster is a loop or a thief. */
  refresh: { name: 'auth.refresh', capacity: 10, refillPerSecond: 1 / 60 },

  /** Writes that take row locks. Bounded so one client cannot monopolise a doctor's slots. */
  booking: { name: 'booking.write', capacity: 20, refillPerSecond: 1 },

  /** Search hits trigram indexes; cheap, but not free. */
  search: { name: 'search', capacity: 60, refillPerSecond: 5 },
} satisfies Record<string, RateLimitPolicy>
