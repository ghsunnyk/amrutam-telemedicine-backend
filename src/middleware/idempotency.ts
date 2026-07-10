import type { NextFunction, Request, RequestHandler, Response } from 'express'
import { createHash, randomUUID } from 'node:crypto'
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

const KEY_PATTERN = /^[A-Za-z0-9_-]{16,128}$/

const MAX_STORED_BODY_BYTES = 64 * 1024

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

  if (!existing) return { kind: 'reclaimed' }

  if (existing.requestHash !== params.requestHash) return { kind: 'conflict' }

  if (existing.status === 'COMPLETED') {
    return { kind: 'replay', status: existing.responseStatus ?? 200, body: existing.responseBody }
  }

  const heldFor = Date.now() - existing.lockedAt.getTime()
  if (heldFor < STALE_LOCK_MS) return { kind: 'in_progress' }

  const { count } = await db.idempotencyKey.updateMany({
    where: { id: existing.id, status: 'IN_PROGRESS', lockedBy: existing.lockedBy },
    data: { lockedBy: params.holder, lockedAt: new Date() },
  })

  if (count !== 1) return { kind: 'in_progress' }

  log.warn({ key: params.key, heldForMs: heldFor }, 'Reclaimed stale idempotency lock')
  return { kind: 'reclaimed' }
}

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
      void db.idempotencyKey
        .deleteMany({ where: { scope: params.scope, key: params.key, lockedBy: params.holder } })
        .catch((err: unknown) =>
          log.error({ err }, 'Failed to release idempotency key after error')
        )
      return
    }

    const serialised =
      captured === undefined ? undefined : Buffer.byteLength(JSON.stringify(captured))
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
        log.error({ err, key: params.key }, 'Failed to persist idempotent response')
      })
  })
}

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
