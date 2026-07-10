import { PrismaPg } from '@prisma/adapter-pg'
import { Pool } from 'pg'
import { env, isTest } from '../config/env'
import { PrismaClient } from '../generated/prisma/client'
import { createLogger } from '../observability/logger'
import { dbPoolConnections, dbQueryDuration, dbTransactionRetries } from '../observability/metrics'

const log = createLogger('prisma')

export function createPool(connectionString: string = env.DATABASE_URL): Pool {
  const pool = new Pool({
    connectionString,
    max: env.DATABASE_POOL_SIZE,
    connectionTimeoutMillis: 10_000,
    idleTimeoutMillis: 30_000,
    statement_timeout: env.DATABASE_STATEMENT_TIMEOUT_MS,
    idle_in_transaction_session_timeout: 30_000,
    application_name: env.OTEL_SERVICE_NAME,
  })

  pool.on('error', err => {
    log.error({ err }, 'Idle database client errored')
  })

  return pool
}

export function createPrismaClient(pool: Pool): PrismaClient {
  const client = new PrismaClient({
    adapter: new PrismaPg(pool),
    log: isTest
      ? []
      : [
          { emit: 'event', level: 'warn' },
          { emit: 'event', level: 'error' },
        ],
  })

  client.$on('warn' as never, (e: { message: string }) => log.warn({ prisma: e.message }))
  client.$on('error' as never, (e: { message: string }) => log.error({ prisma: e.message }))

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

export type Tx = Omit<
  PrismaClient,
  '$connect' | '$disconnect' | '$on' | '$transaction' | '$extends'
>

const RETRYABLE_PG_CODES = new Set(['40001', '40P01'])

function isRetryable(err: unknown): boolean {
  if (!err || typeof err !== 'object') return false
  const e = err as { code?: string; meta?: { code?: string }; cause?: unknown }
  if (RETRYABLE_PG_CODES.has(e.code ?? '')) return true
  if (RETRYABLE_PG_CODES.has(e.meta?.code ?? '')) return true
  return e.cause ? isRetryable(e.cause) : false
}

export interface RetryOptions {
  maxAttempts?: number
  baseDelayMs?: number
  maxDelayMs?: number
}

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

const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms))
