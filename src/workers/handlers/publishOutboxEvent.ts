import { createLogger } from '../../observability/logger'
import { outboxEventsTotal, outboxLagSeconds } from '../../observability/metrics'
import type { JobHandler } from '../jobQueue'

const log = createLogger('worker:outbox')

export const publishOutboxHandler: JobHandler = {
  type: 'publish_outbox_batch',
  handle: async (_payload, db) => {
    const pending = await db.outboxEvent.findMany({
      where: { status: 'PENDING', availableAt: { lte: new Date() } },
      orderBy: { createdAt: 'asc' },
      take: 100,
    })
    if (pending.length === 0) return

    const oldest = pending[0]!
    outboxLagSeconds.set((Date.now() - oldest.createdAt.getTime()) / 1000)

    for (const event of pending) {
      try {
        // Swap this for a real broker publish (SNS/Kafka/etc) — the outbox
        // pattern's job is done once this call is durable; the transport is
        // an implementation detail behind this line.
        log.info(
          { eventType: event.eventType, aggregateId: event.aggregateId },
          'Publishing outbox event'
        )

        await db.outboxEvent.update({
          where: { id: event.id },
          data: { status: 'PUBLISHED', publishedAt: new Date() },
        })
        outboxEventsTotal.inc({ event_type: event.eventType, outcome: 'published' })
      } catch (err) {
        await db.outboxEvent.update({
          where: { id: event.id },
          data: {
            attempts: { increment: 1 },
            lastError: err instanceof Error ? err.message : String(err),
          },
        })
        outboxEventsTotal.inc({ event_type: event.eventType, outcome: 'failed' })
      }
    }
  },
}
