import { createHash, randomUUID } from 'node:crypto'
import type { NextFunction, Request, RequestHandler, Response } from 'express'
import { env } from '../config/env'
import {
  IdempotencyKeyReusedError,
  IdempotentRequestInProgressError,
  ValidationError,
} from '../core/errors'
import type { Db } from '../db/prisma'
import { createLogger } from '../observability/logger'
import { idempotencyHitsTotal } from '../observability/metrics'

const log = createLogger('idempotency')

/** Bound the key: it is a database column and a cache key, not free-form storage. */
const KEY_PATTERN = /^[A-Za-z0-9_-]{16,128}$/

/**
 * A response body larger than this is not replayed — we store a marker instead and
 * a retry re-executes. In practice every idempotent write here returns a small object.
 */
const MAX_STORED_BODY_BYTES = 64 * 1024

/**
 * Exactly-once semantics for unsafe HTTP methods.
 *
 * The problem: a client POSTs `/consultations`, the write commits, the response is
 * lost to a timeout, the client retries. Without this middleware the patient is
 * booked and charged twice.
 *
 * The protocol:
 *
 *   1. `INSERT … (status = IN_PROGRESS)`. The unique index on `(scope, key)` is what
 *      serialises concurrent duplicates — not a lock we take, but one Postgres takes
 *      for us. Exactly one racer inserts; the rest get a unique violation.
 *   2. Winner runs the handler. Its status + body are recorded on the row.
 *   3. Losers read the row:
 *        • COMPLETED   → replay the stored response verbatim (`Idempotency-Replayed: true`)
 *        • IN_PROGRESS → 409, retryable; the original is still running
 *      A stale IN_PROGRESS row (holder crashed) is reclaimed after `STALE_LOCK_MS`.
 *   4. A key reused with a *different* body is a 422, never a replay of the wrong
 *      response. That is the difference between an idempotency key and a cache key.
 *
 * Only 2xx responses are recorded. Replaying a 500 would make a transient failure
 * permanent for the lifetime of the key.
 */
const STALE_LOCK_MS = 60_000

export function idempotency(db: Db, options: { required?: boolean } = {}): RequestHandler {
  return async (req: Request, res: Response, next: NextFunction) => {
    const key = req.get('idempotency-key')

    if (!key) {
      if (options.required) {
        return next(
          new ValidationError('This endpoint requires an Idempotency-Key header', {
            fields: { 'idempotency-key': ['required'] },
          })
        )
      }
      return next()
    }

    if (!KEY_PATTERN.test(key)) {
      return next(
        new ValidationError('Idempotency-Key must be 16–128 characters of [A-Za-z0-9_-]', {
          fields: { 'idempotency-key': ['invalid format'] },
        })
      )
    }

    // Scope by caller. Without this, one user could guess another's key and either
    // read their response body or block their write.
    const scope = req.auth?.userId ?? `ip:${hash(req.ip ?? 'unknown')}`
    const requestHash = hashRequest(req)
    const holder = randomUUID()

    try {
      await db.idempotencyKey.create({
        data: {
          scope,
          key,
          requestHash,
          status: 'IN_PROGRESS',
          lockedBy: holder,
          expiresAt: new Date(Date.now() + env.IDEMPOTENCY_TTL_HOURS * 3600_000),
        },
      })
    } catch (err) {
      if (!isUniqueViolation(err)) return next(err)

      const outcome = await handleExistingKey(db, { scope, key, requestHash, holder })

      if (outcome.kind === 'replay') {
        idempotencyHitsTotal.inc({ outcome: 'replay' })
        res.setHeader('Idempotency-Replayed', 'true')
        res.status(outcome.status).json(outcome.body)
        return
      }
      if (outcome.kind === 'conflict') {
        idempotencyHitsTotal.inc({ outcome: 'conflict' })
        return next(new IdempotencyKeyReusedError())
      }
      if (outcome.kind === 'in_progress') {
        idempotencyHitsTotal.inc({ outcome: 'in_progress' })
        res.setHeader('Retry-After', '2')
        return next(new IdempotentRequestInProgressError())
      }
      // 'reclaimed' — the previous holder died; we now own the row and proceed.
    }

    idempotencyHitsTotal.inc({ outcome: 'miss' })
    req.idempotency = { key, scope }

    captureResponse(res, db, { scope, key, holder })
    next()
  }
}

type ExistingOutcome =
  | { kind: 'replay'; status: number; body: unknown }
  | { kind: 'conflict' }
  | { kind: 'in_progress' }
  | { kind: 'reclaimed' }

async function handleExistingKey(
  db: Db,
  params: { scope: string; key: string; requestHash: string; holder: string }
): Promise<ExistingOutcome> {
  const existing = await db.idempotencyKey.findUnique({
    where: { scope_key: { scope: params.scope, key: params.key } },
  })

  // Vanished between the failed insert and this read (TTL sweeper). Treat as a fresh
  // request rather than erroring; worst case the handler runs once more.
  if (!existing) return { kind: 'reclaimed' }

  // Same key, different request. Never replay — the stored response describes a
  // different operation, and returning it would be a silent, wrong success.
  if (existing.requestHash !== params.requestHash) return { kind: 'conflict' }

  if (existing.status === 'COMPLETED') {
    return { kind: 'replay', status: existing.responseStatus ?? 200, body: existing.responseBody }
  }

  // IN_PROGRESS. Either the original is still running, or its process died holding
  // the row. Reclaim only after the lease has clearly expired.
  const heldFor = Date.now() - existing.lockedAt.getTime()
  if (heldFor < STALE_LOCK_MS) return { kind: 'in_progress' }

  const { count } = await db.idempotencyKey.updateMany({
    // `lockedBy` in the filter makes the takeover atomic: if two requests both decide
    // the lock is stale, only the one that still sees the *old* holder wins.
    where: { id: existing.id, status: 'IN_PROGRESS', lockedBy: existing.lockedBy },
    data: { lockedBy: params.holder, lockedAt: new Date() },
  })

  if (count !== 1) return { kind: 'in_progress' }

  log.warn({ key: params.key, heldForMs: heldFor }, 'Reclaimed stale idempotency lock')
  return { kind: 'reclaimed' }
}

/**
 * Record the response once it is sent. Hooks `res.json` because that is the single
 * point every controller funnels through (see `sendSuccess`), and it gives us the
 * body *before* serialisation.
 */
function captureResponse(
  res: Response,
  db: Db,
  params: { scope: string; key: string; holder: string }
): void {
  const originalJson = res.json.bind(res)
  let captured: unknown

  res.json = (body: unknown) => {
    captured = body
    return originalJson(body)
  }

  res.on('finish', () => {
    const isSuccess = res.statusCode >= 200 && res.statusCode < 300

    if (!isSuccess) {
      // Release the key so the client can retry the same operation. A recorded 4xx/5xx
      // would pin a transient failure in place for the whole TTL.
      void db.idempotencyKey
        .deleteMany({ where: { scope: params.scope, key: params.key, lockedBy: params.holder } })
        .catch((err: unknown) => log.error({ err }, 'Failed to release idempotency key after error'))
      return
    }

    const serialised = captured === undefined ? undefined : Buffer.byteLength(JSON.stringify(captured))
    if (serialised !== undefined && serialised > MAX_STORED_BODY_BYTES) {
      log.warn({ key: params.key, bytes: serialised }, 'Response too large to store for replay')
      void db.idempotencyKey.deleteMany({
        where: { scope: params.scope, key: params.key, lockedBy: params.holder },
      })
      return
    }

    void db.idempotencyKey
      .updateMany({
        where: { scope: params.scope, key: params.key, lockedBy: params.holder },
        data: {
          status: 'COMPLETED',
          responseStatus: res.statusCode,
          responseBody: (captured ?? null) as never,
        },
      })
      .catch((err: unknown) => {
        // The write already committed. Losing the record means a retry re-executes,
        // which for a booking would double-book — so this is an alertable error.
        log.error({ err, key: params.key }, 'Failed to persist idempotent response')
      })
  })
}

/**
 * The fingerprint of "the same request". Method and path matter because one key must
 * not be reusable across endpoints. The *authenticated user* is already in the scope.
 */
function hashRequest(req: Request): string {
  return createHash('sha256')
    .update(req.method)
    .update('\x00')
    .update(req.originalUrl.split('?')[0] ?? '')
    .update('\x00')
    .update(JSON.stringify(req.body ?? null))
    .digest('hex')
}

const hash = (v: string) => createHash('sha256').update(v).digest('hex').slice(0, 24)

const isUniqueViolation = (err: unknown): boolean => (err as { code?: string })?.code === 'P2002'
