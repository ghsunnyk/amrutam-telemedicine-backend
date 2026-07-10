import { AuditAction } from '../../modules/audit/audit.service'
import { createLogger } from '../../observability/logger'
import { consultationsTotal } from '../../observability/metrics'
import type { JobHandler } from '../jobQueue'

const log = createLogger('worker:expire-consultations')

export const expirePendingConsultationsHandler: JobHandler = {
  type: 'expire_pending_consultations',
  handle: async (_payload, db) => {
    const expired = await db.consultation.findMany({
      where: { status: 'PENDING_PAYMENT', expiresAt: { lt: new Date() } },
      select: { id: true, slotId: true, patientId: true },
      take: 200,
    })
    if (expired.length === 0) return

    for (const c of expired) {
      await db.$transaction(async tx => {
        const { count } = await tx.consultation.updateMany({
          where: { id: c.id, status: 'PENDING_PAYMENT' },
          data: { status: 'EXPIRED', cancelledAt: new Date(), cancelledBy: 'SYSTEM' },
        })
        if (count !== 1) return

        await tx.availabilitySlot.updateMany({
          where: { id: c.slotId, status: 'BOOKED' },
          data: { status: 'AVAILABLE', heldByUserId: null, holdExpiresAt: null, holdToken: null },
        })
        await tx.payment.updateMany({
          where: { consultationId: c.id, status: 'PENDING' },
          data: { status: 'FAILED', failureCode: 'PAYMENT_TIMEOUT' },
        })
        await tx.auditLog.create({
          data: {
            action: AuditAction.CONSULTATION_EXPIRED,
            resourceType: 'consultation',
            resourceId: c.id,
            actorId: c.patientId,
          },
        })
      })
      consultationsTotal.inc({ status: 'EXPIRED' })
    }

    log.info({ count: expired.length }, 'Expired stale pending-payment consultations')
  },
}
