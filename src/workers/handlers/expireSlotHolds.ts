import { AuditAction } from '../../modules/audit/audit.service'
import { createLogger } from '../../observability/logger'
import { getContext } from '../../observability/requestContext'
import type { JobHandler } from '../jobQueue'

const log = createLogger('worker:expire-holds')

export const expireSlotHoldsHandler: JobHandler = {
  type: 'expire_slot_holds',
  handle: async (_payload, db) => {
    const expired = await db.availabilitySlot.findMany({
      where: { status: 'HELD', holdExpiresAt: { lt: new Date() } },
      select: { id: true, heldByUserId: true },
      take: 500,
    })
    if (expired.length === 0) return

    const { count } = await db.availabilitySlot.updateMany({
      where: {
        id: { in: expired.map(s => s.id) },
        status: 'HELD',
        holdExpiresAt: { lt: new Date() },
      },
      data: { status: 'AVAILABLE', heldByUserId: null, holdExpiresAt: null, holdToken: null },
    })

    if (count > 0) {
      log.info({ count }, 'Released expired slot holds')
      for (const slot of expired) {
        await db.auditLog.create({
          data: {
            action: AuditAction.SLOT_HOLD_EXPIRED,
            resourceType: 'availability_slot',
            resourceId: slot.id,
            actorId: slot.heldByUserId,
            requestId: getContext()?.requestId ?? null,
          },
        })
      }
    }
  },
}
