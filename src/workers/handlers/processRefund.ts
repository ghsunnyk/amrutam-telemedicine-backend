import { AuditAction } from '../../modules/audit/audit.service'
import { createLogger } from '../../observability/logger'
import { paymentsTotal } from '../../observability/metrics'
import type { JobHandler } from '../jobQueue'

const log = createLogger('worker:refund')

interface RefundPayload {
  paymentId: string
  reason: string
}

export const processRefundHandler: JobHandler<RefundPayload> = {
  type: 'process_refund',
  handle: async (payload, db) => {
    const payment = await db.payment.findUnique({ where: { id: payload.paymentId } })
    if (!payment || payment.status !== 'REFUND_PENDING') return
    // MOCK provider refund — swap for a real gateway call.
    await db.payment.update({
      where: { id: payment.id },
      data: {
        status: 'REFUNDED',
        refundedAt: new Date(),
        refundedAmountMinor: payment.amountMinor,
      },
    })
    await db.auditLog.create({
      data: {
        action: AuditAction.PAYMENT_REFUNDED,
        resourceType: 'payment',
        resourceId: payment.id,
        metadata: { reason: payload.reason, status: 'completed' },
      },
    })
    paymentsTotal.inc({ provider: payment.provider, status: 'REFUNDED' })
    log.info({ paymentId: payment.id }, 'Refund completed')
  },
}
