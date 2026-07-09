import { PrismaPg } from '@prisma/adapter-pg'
import { Pool } from 'pg'
import { env, isTest } from '../config/env'
import { PrismaClient } from '../generated/prisma/client'
import { createLogger } from '../observability/logger'
import { dbPoolConnections, dbQueryDuration, dbTransactionRetries } from '../observability/metrics'

const log = createLogger('prisma')

/**
 * Pool sizing: a Postgres backend costs ~10 MB and the server context-switches badly
 * past roughly 2× cores. The pool is per-process, so the real ceiling is
 * `DATABASE_POOL_SIZE × replicas`, and it must stay under `max_connections` with
 * headroom for migrations and the replica's own workload. At 100k consultations/day
 * we run ~6 replicas × 20 = 120 connections against a 200-connection primary, and
 * introduce PgBouncer (transaction pooling) before growing past that.
 */
export function createPool(connectionString: string = env.DATABASE_URL): Pool {
  const pool = new Pool({
    connectionString,
    max: env.DATABASE_POOL_SIZE,
    // Fail fast rather than queue forever when the pool is saturated: a request
    // that waits 30s for a connection has already blown its SLO.
    connectionTimeoutMillis: 10_000,
    idleTimeoutMillis: 30_000,
    // A query past this is a bug or a missing index. Killing it stops one slow
    // statement from pinning a connection and cascading into pool exhaustion.
    statement_timeout: env.DATABASE_STATEMENT_TIMEOUT_MS,
    // Bound how long a write can hold row locks (booking takes FOR UPDATE).
    idle_in_transaction_session_timeout: 30_000,
    application_name: env.OTEL_SERVICE_NAME,
  })

  pool.on('error', (err) => {
    // Emitted for *idle* clients — e.g. Postgres restarted under us. Never fatal:
    // pg discards the client and the next checkout dials a fresh one.
    log.error({ err }, 'Idle database client errored')
  })

  return pool
}

export function createPrismaClient(pool: Pool): PrismaClient {
  const client = new PrismaClient({
    adapter: new PrismaPg(pool),
    log: isTest ? [] : [{ emit: 'event', level: 'warn' }, { emit: 'event', level: 'error' }],
  })

  client.$on('warn' as never, (e: { message: string }) => log.warn({ prisma: e.message }))
  client.$on('error' as never, (e: { message: string }) => log.error({ prisma: e.message }))

  /**
   * Time every query. `model` and `action` are bounded sets, so the label
   * cardinality is fine — unlike labelling by query text.
   */
  return client.$extends({
    query: {
      async $allOperations({ model, operation, args, query }) {
        const end = dbQueryDuration.startTimer({ model: model ?? 'raw', action: operation })
        try {
          return await query(args)
        } finally {
          end()
        }
      },
    },
  }) as unknown as PrismaClient
}

/** Poll pool utilisation into gauges. Returns an unsubscribe fn for graceful shutdown. */
export function observePool(pool: Pool, intervalMs = 5000): () => void {
  const timer = setInterval(() => {
    dbPoolConnections.set({ state: 'total' }, pool.totalCount)
    dbPoolConnections.set({ state: 'idle' }, pool.idleCount)
    dbPoolConnections.set({ state: 'waiting' }, pool.waitingCount)
  }, intervalMs)
  timer.unref() // never hold the event loop open
  return () => clearInterval(timer)
}

export type Db = PrismaClient

/** The transaction-scoped client Prisma hands to `$transaction(async (tx) => …)`. */
export type Tx = Omit<
  PrismaClient,
  '$connect' | '$disconnect' | '$on' | '$transaction' | '$extends'
>

// ---------------------------------------------------------------------------
// Retry on serialisation failure / deadlock
// ---------------------------------------------------------------------------

/** Postgres SQLSTATEs meaning "your transaction lost a race; run it again". */
const RETRYABLE_PG_CODES = new Set([
  '40001', // serialization_failure
  '40P01', // deadlock_detected
])

function isRetryable(err: unknown): boolean {
  if (!err || typeof err !== 'object') return false
  const e = err as { code?: string; meta?: { code?: string }; cause?: unknown }
  if (RETRYABLE_PG_CODES.has(e.code ?? '')) return true
  if (RETRYABLE_PG_CODES.has(e.meta?.code ?? '')) return true
  // Driver-adapter errors wrap the pg error.
  return e.cause ? isRetryable(e.cause) : false
}

export interface RetryOptions {
  maxAttempts?: number
  baseDelayMs?: number
  maxDelayMs?: number
}

/**
 * Exponential backoff with full jitter.
 *
 * The jitter is not decoration. Without it, N transactions that deadlocked together
 * sleep for the same interval and collide again on wake — the retry storm reproduces
 * the contention it was meant to resolve. Full jitter (`random(0, cap)`) decorrelates
 * them. See docs/architecture.md §Retry & Backoff.
 *
 * Only wrap transactions that are *safe to replay*: the whole `fn` re-runs, so it
 * must not have committed side effects outside the transaction.
 */
export async function withRetry<T>(fn: () => Promise<T>, options: RetryOptions = {}): Promise<T> {
  const { maxAttempts = 3, baseDelayMs = 25, maxDelayMs = 500 } = options

  let lastError: unknown
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      return await fn()
    } catch (err) {
      lastError = err
      if (!isRetryable(err)) throw err

      if (attempt === maxAttempts) {
        dbTransactionRetries.inc({ outcome: 'exhausted' })
        throw err
      }

      dbTransactionRetries.inc({ outcome: 'retried' })
      const cap = Math.min(maxDelayMs, baseDelayMs * 2 ** (attempt - 1))
      const delay = Math.random() * cap
      log.warn({ attempt, delayMs: Math.round(delay) }, 'Transaction conflict — retrying')
      await sleep(delay)
    }
  }
  throw lastError
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))
