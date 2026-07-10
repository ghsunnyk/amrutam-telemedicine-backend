import { randomBytes, randomUUID } from 'node:crypto'
import { fieldAad, type Keyring } from '../../core/crypto/keyring'
import { ConflictError, ForbiddenError, NotFoundError } from '../../core/errors'
import type { Db } from '../../db/prisma'
import {
  bookingAttemptsTotal,
  bookingSlotContentionTotal,
  consultationsTotal,
} from '../../observability/metrics'
import { AuditAction, type AuditService } from '../audit/audit.service'
import type { BookConsultationInput } from './consultation.schemas'

export interface BookedConsultation {
  id: string
  reference: string
  status: string
  scheduledStart: Date
  scheduledEnd: Date
  feeMinor: number
  currency: string
}

const reference = (): string => {
  const date = new Date().toISOString().slice(0, 10).replace(/-/g, '')
  return `AMR-${date}-${randomBytes(4).toString('hex').toUpperCase()}`
}

export class ConsultationService {
  constructor(
    private readonly db: Db,
    private readonly keyring: Keyring,
    private readonly audit: AuditService
  ) {}

  async book(patientId: string, input: BookConsultationInput): Promise<BookedConsultation> {
    try {
      const consultation = await this.db.$transaction(async tx => {
        const slot = await tx.availabilitySlot.findUnique({
          where: { id: input.slotId },
          include: {
            doctor: {
              select: {
                id: true,
                consultationFeeMinor: true,
                currency: true,
                isAcceptingPatients: true,
              },
            },
          },
        })

        if (!slot) throw new NotFoundError('Slot', input.slotId)
        if (
          slot.status !== 'HELD' ||
          slot.holdToken !== input.holdToken ||
          slot.heldByUserId !== patientId
        ) {
          throw new ConflictError('Your hold on this slot has expired', 'SLOT_UNAVAILABLE')
        }
        if (slot.holdExpiresAt && slot.holdExpiresAt < new Date()) {
          throw new ConflictError('Your hold on this slot has expired', 'SLOT_UNAVAILABLE')
        }

        // Same CAS pattern as holdSlot: the WHERE clause re-checks holdToken so a
        // concurrent expiry-reclaim by another request loses this race cleanly.
        const { count } = await tx.availabilitySlot.updateMany({
          where: { id: slot.id, status: 'HELD', holdToken: input.holdToken },
          data: { status: 'BOOKED' },
        })
        if (count !== 1) {
          bookingSlotContentionTotal.inc()
          throw new ConflictError('This slot was just booked by someone else', 'SLOT_UNAVAILABLE')
        }

        const consultationId = randomUUID()
        const created = await tx.consultation.create({
          data: {
            id: consultationId,
            reference: reference(),
            patientId,
            doctorId: slot.doctorId,
            slotId: slot.id,
            mode: input.mode,
            status: 'PENDING_PAYMENT',
            scheduledStart: slot.startAt,
            scheduledEnd: slot.endAt,
            feeMinor: slot.doctor.consultationFeeMinor,
            currency: slot.doctor.currency,
            chiefComplaintEnc: input.chiefComplaint
              ? this.keyring.encryptField(
                  input.chiefComplaint,
                  fieldAad('consultation', consultationId, 'chief_complaint')
                )
              : undefined,
            symptomsEnc: input.symptoms
              ? this.keyring.encryptField(
                  input.symptoms,
                  fieldAad('consultation', consultationId, 'symptoms')
                )
              : undefined,
            expiresAt: new Date(Date.now() + 15 * 60_000),
          },
        })

        await tx.payment.create({
          data: {
            consultationId: created.id,
            userId: patientId,
            provider: 'MOCK',
            status: 'PENDING',
            amountMinor: created.feeMinor,
            currency: created.currency,
          },
        })

        await tx.outboxEvent.create({
          data: {
            aggregateType: 'consultation',
            aggregateId: created.id,
            eventType: 'consultation.booked',
            payload: { consultationId: created.id, doctorId: created.doctorId, patientId },
          },
        })

        await this.audit.record(tx, {
          action: AuditAction.CONSULTATION_BOOKED,
          resourceType: 'consultation',
          resourceId: created.id,
          actorId: patientId,
        })

        return created
      })

      bookingAttemptsTotal.inc({ outcome: 'success' })
      consultationsTotal.inc({ status: 'PENDING_PAYMENT' })

      return {
        id: consultation.id,
        reference: consultation.reference,
        status: consultation.status,
        scheduledStart: consultation.scheduledStart,
        scheduledEnd: consultation.scheduledEnd,
        feeMinor: consultation.feeMinor,
        currency: consultation.currency,
      }
    } catch (err) {
      bookingAttemptsTotal.inc({ outcome: 'failure' })
      throw err
    }
  }

  async getById(userId: string, role: string, consultationId: string) {
    const consultation = await this.db.consultation.findUnique({
      where: { id: consultationId },
      include: { doctor: { select: { userId: true } } },
    })
    if (!consultation) throw new NotFoundError('Consultation', consultationId)

    const isOwner =
      consultation.patientId === userId || consultation.doctor.userId === userId || role === 'ADMIN'
    if (!isOwner) throw new ForbiddenError('You do not have access to this consultation')

    return consultation
  }
}
