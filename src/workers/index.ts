import { env } from '../config/env'
import type { Db } from '../db/prisma'
import { createLogger } from '../observability/logger'
import { expirePendingConsultationsHandler } from './handlers/expirePendingConsultations'
import { expireSlotHoldsHandler } from './handlers/expireSlotHolds'
import { processRefundHandler } from './handlers/processRefund'
import { publishOutboxHandler } from './handlers/publishOutboxEvent'
import { JobQueue } from './jobQueue'

const log = createLogger('workers')

export function createWorker(db: Db): JobQueue {
  const queue = new JobQueue(db, {
    concurrency: env.WORKER_CONCURRENCY,
    pollIntervalMs: env.WORKER_POLL_INTERVAL_MS,
  })

  queue.register(expireSlotHoldsHandler)
  queue.register(expirePendingConsultationsHandler)
  queue.register(publishOutboxHandler)
  queue.register(processRefundHandler as any)

  return queue
}

export async function scheduleRecurringJobs(queue: JobQueue): Promise<void> {
  await queue.enqueueRecurring('expire_slot_holds', {}, 'recurring:expire_slot_holds', 15_000)
  await queue.enqueueRecurring(
    'expire_pending_consultations',
    {},
    'recurring:expire_pending_consultations',
    30_000
  )
  await queue.enqueueRecurring('publish_outbox_batch', {}, 'recurring:publish_outbox_batch', 5_000)
}

export async function reschedule(queue: JobQueue): Promise<void> {
  setInterval(() => {
    void scheduleRecurringJobs(queue).catch(err =>
      log.error({ err }, 'Failed to reschedule recurring jobs')
    )
  }, 10_000).unref()
}
