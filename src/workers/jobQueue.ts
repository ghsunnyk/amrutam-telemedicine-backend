import type { Db } from '../db/prisma'
import { createLogger } from '../observability/logger'
import { jobDuration, jobQueueDepth, jobsProcessedTotal } from '../observability/metrics'

const log = createLogger('job-queue')

export interface JobHandler<P = unknown> {
  type: string
  handle: (payload: P, db: Db) => Promise<void>
}

export interface JobQueueOptions {
  concurrency: number
  pollIntervalMs: number
  leaseSeconds?: number
}

const BACKOFF_BASE_MS = 2_000
const BACKOFF_MAX_MS = 5 * 60_000

export function backoffMs(attempt: number): number {
  const cap = Math.min(BACKOFF_MAX_MS, BACKOFF_BASE_MS * 2 ** attempt)
  return Math.floor(Math.random() * cap)
}

export class JobQueue {
  private handlers = new Map<string, JobHandler>()
  private timer: NodeJS.Timeout | null = null
  private stopping = false
  private inFlight = 0

  constructor(
    private readonly db: Db,
    private readonly options: JobQueueOptions
  ) {}

  register(handler: JobHandler): void {
    this.handlers.set(handler.type, handler)
  }

  async enqueue(
    type: string,
    payload: unknown,
    options: { dedupeKey?: string; runAt?: Date } = {}
  ): Promise<void> {
    try {
      await this.db.job.create({
        data: {
          type,
          payload: payload as never,
          runAt: options.runAt ?? new Date(),
          dedupeKey: options.dedupeKey,
        },
      })
    } catch (err) {
      if (isUniqueViolation(err)) return // dedupeKey collision — already queued, fine
      throw err
    }
  }

  async enqueueRecurring(
    type: string,
    payload: unknown,
    dedupeKey: string,
    intervalMs: number
  ): Promise<void> {
    const existing = await this.db.job.findUnique({ where: { dedupeKey } })
    if (existing && ['PENDING', 'RUNNING'].includes(existing.status)) return
    await this.enqueue(type, payload, { dedupeKey, runAt: new Date(Date.now() + intervalMs) })
  }

  start(): void {
    this.stopping = false
    this.tick()
  }

  async stop(): Promise<void> {
    this.stopping = true
    if (this.timer) clearTimeout(this.timer)
    while (this.inFlight > 0) await sleep(50)
  }

  private tick(): void {
    if (this.stopping) return
    void this.drainOnce().finally(() => {
      this.timer = setTimeout(() => this.tick(), this.options.pollIntervalMs)
      this.timer.unref()
    })
  }

  private async drainOnce(): Promise<void> {
    const capacity = this.options.concurrency - this.inFlight
    if (capacity <= 0) return

    const leaseSeconds = this.options.leaseSeconds ?? 60
    const workerId = `${process.pid}-${Math.random().toString(36).slice(2, 8)}`

    const claimed = await this.db.$queryRaw<
      { id: string; type: string; payload: unknown; attempts: number }[]
    >`
      WITH claimable AS (
        SELECT id FROM jobs
        WHERE status = 'PENDING' AND run_at <= now()
        ORDER BY run_at
        LIMIT ${capacity}
        FOR UPDATE SKIP LOCKED
      )
      UPDATE jobs
      SET status = 'RUNNING', locked_by = ${workerId}, locked_at = now(),
          lease_until = now() + make_interval(secs => ${leaseSeconds}), attempts = attempts + 1
      WHERE id IN (SELECT id FROM claimable)
      RETURNING id, type, payload, attempts
    `

    for (const job of claimed) {
      this.inFlight++
      void this.run(job, workerId).finally(() => {
        this.inFlight--
      })
    }
  }

  private async run(
    job: { id: string; type: string; payload: unknown; attempts: number },
    _workerId: string
  ): Promise<void> {
    const handler = this.handlers.get(job.type)
    if (!handler) {
      log.error({ type: job.type }, 'No handler registered for job type — dead-lettering')
      await this.db.job.update({
        where: { id: job.id },
        data: { status: 'DEAD', lastError: 'no handler' },
      })
      jobsProcessedTotal.inc({ type: job.type, outcome: 'no_handler' })
      return
    }

    const end = jobDuration.startTimer({ type: job.type })
    try {
      await handler.handle(job.payload, this.db)
      await this.db.job.update({
        where: { id: job.id },
        data: { status: 'SUCCEEDED', completedAt: new Date(), lockedBy: null, leaseUntil: null },
      })
      jobsProcessedTotal.inc({ type: job.type, outcome: 'succeeded' })
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err)
      const current = await this.db.job.findUnique({
        where: { id: job.id },
        select: { maxAttempts: true },
      })
      const maxAttempts = current?.maxAttempts ?? 5

      if (job.attempts >= maxAttempts) {
        await this.db.job.update({
          where: { id: job.id },
          data: { status: 'DEAD', lastError: message, lockedBy: null, leaseUntil: null },
        })
        jobsProcessedTotal.inc({ type: job.type, outcome: 'dead' })
        log.error({ jobId: job.id, type: job.type, err }, 'Job exhausted retries — moved to DEAD')
      } else {
        await this.db.job.update({
          where: { id: job.id },
          data: {
            status: 'PENDING',
            lastError: message,
            lockedBy: null,
            leaseUntil: null,
            runAt: new Date(Date.now() + backoffMs(job.attempts)),
          },
        })
        jobsProcessedTotal.inc({ type: job.type, outcome: 'retried' })
        log.warn(
          { jobId: job.id, type: job.type, attempt: job.attempts, err },
          'Job failed — will retry'
        )
      }
    } finally {
      end()
    }
  }

  async reportQueueDepth(): Promise<void> {
    const rows = await this.db.job.groupBy({ by: ['queue', 'status'], _count: true })
    for (const row of rows) {
      jobQueueDepth.set({ queue: row.queue, status: row.status }, row._count)
    }
  }
}

const isUniqueViolation = (err: unknown): boolean => (err as { code?: string })?.code === 'P2002'

const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms))
