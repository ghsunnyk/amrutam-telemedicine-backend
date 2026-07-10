import { randomBytes, randomUUID } from 'node:crypto'
import { fieldAad, type Keyring } from '../../core/crypto/keyring'
import { ConflictError, ForbiddenError, NotFoundError } from '../../core/errors'
import type { Db } from '../../db/prisma'
import type { Role } from '../../generated/prisma/enums'
import {
  bookingAttemptsTotal,
  bookingSlotContentionTotal,
  consultationsTotal,
} from '../../observability/metrics'
import { AuditAction, type AuditService } from '../audit/audit.service'
import type { PaymentService } from '../payments/payment.service'
import type { BookConsultationInput, CompleteConsultationInput } from './consultation.schemas'

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
    private readonly audit: AuditService,
    private readonly payments: PaymentService
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

  async start(doctorUserId: string, consultationId: string): Promise<void> {
    const consultation = await this.loadForDoctor(doctorUserId, consultationId)
    if (consultation.status !== 'SCHEDULED') {
      throw new ConflictError('Consultation must be SCHEDULED to start')
    }
    await this.db.$transaction(async tx => {
      await tx.consultation.update({
        where: { id: consultationId },
        data: { status: 'IN_PROGRESS', startedAt: new Date() },
      })
      await this.audit.record(tx, {
        action: AuditAction.CONSULTATION_STARTED,
        resourceType: 'consultation',
        resourceId: consultationId,
        actorId: doctorUserId,
        actorRole: 'DOCTOR',
      })
    })
    consultationsTotal.inc({ status: 'IN_PROGRESS' })
  }

  async complete(
    doctorUserId: string,
    consultationId: string,
    input: CompleteConsultationInput
  ): Promise<void> {
    const consultation = await this.loadForDoctor(doctorUserId, consultationId)
    if (consultation.status !== 'IN_PROGRESS') {
      throw new ConflictError('Consultation must be IN_PROGRESS to complete')
    }
    await this.db.$transaction(async tx => {
      await tx.consultation.update({
        where: { id: consultationId },
        data: {
          status: 'COMPLETED',
          endedAt: new Date(),
          diagnosisEnc: input.diagnosis
            ? this.keyring.encryptField(
                input.diagnosis,
                fieldAad('consultation', consultationId, 'diagnosis')
              )
            : undefined,
          doctorNotesEnc: input.doctorNotes
            ? this.keyring.encryptField(
                input.doctorNotes,
                fieldAad('consultation', consultationId, 'doctor_notes')
              )
            : undefined,
          followUpNotesEnc: input.followUpNotes
            ? this.keyring.encryptField(
                input.followUpNotes,
                fieldAad('consultation', consultationId, 'follow_up_notes')
              )
            : undefined,
        },
      })
      await this.audit.record(tx, {
        action: AuditAction.CONSULTATION_COMPLETED,
        resourceType: 'consultation',
        resourceId: consultationId,
        actorId: doctorUserId,
        actorRole: 'DOCTOR',
      })
    })
    consultationsTotal.inc({ status: 'COMPLETED' })
  }

  async cancel(userId: string, role: Role, consultationId: string, reason: string): Promise<void> {
    const consultation = await this.db.consultation.findUnique({
      where: { id: consultationId },
      include: { doctor: { select: { userId: true } }, payments: true },
    })
    if (!consultation) throw new NotFoundError('Consultation', consultationId)
    const isPatient = consultation.patientId === userId
    const isDoctor = consultation.doctor.userId === userId
    if (!isPatient && !isDoctor && role !== 'ADMIN') {
      throw new ForbiddenError('You do not have access to this consultation')
    }
    if (!['PENDING_PAYMENT', 'SCHEDULED'].includes(consultation.status)) {
      throw new ConflictError('Consultation can no longer be cancelled')
    }
    const cancelledBy = role === 'ADMIN' ? 'ADMIN' : isDoctor ? 'DOCTOR' : 'PATIENT'
    const capturedPayment = consultation.payments.find(p => p.status === 'CAPTURED')

    await this.db.$transaction(async tx => {
      await tx.consultation.update({
        where: { id: consultationId },
        data: {
          status: 'CANCELLED',
          cancelledAt: new Date(),
          cancelledBy,
          cancelledReason: reason,
        },
      })
      await tx.availabilitySlot.updateMany({
        where: { id: consultation.slotId, status: 'BOOKED' },
        data: { status: 'AVAILABLE', heldByUserId: null, holdExpiresAt: null, holdToken: null },
      })
      await tx.payment.updateMany({
        where: { consultationId, status: { in: ['PENDING', 'AUTHORIZED'] } },
        data: { status: 'FAILED', failureCode: 'CONSULTATION_CANCELLED' },
      })
      await this.audit.record(tx, {
        action: AuditAction.CONSULTATION_CANCELLED,
        resourceType: 'consultation',
        resourceId: consultationId,
        actorId: userId,
        actorRole: role,
        metadata: { reason, cancelledBy },
      })
    })

    if (capturedPayment) {
      await this.payments.refund(userId, consultationId, `consultation_cancelled: ${reason}`)
    }
    consultationsTotal.inc({ status: 'CANCELLED' })
  }

  async markNoShow(doctorUserId: string, consultationId: string): Promise<void> {
    const consultation = await this.loadForDoctor(doctorUserId, consultationId)
    if (consultation.status !== 'SCHEDULED') {
      throw new ConflictError('Consultation must be SCHEDULED to mark as no-show')
    }
    if (consultation.scheduledStart > new Date()) {
      throw new ConflictError('Cannot mark no-show before the scheduled start time')
    }
    await this.db.$transaction(async tx => {
      await tx.consultation.update({
        where: { id: consultationId },
        data: { status: 'NO_SHOW', cancelledAt: new Date(), cancelledBy: 'SYSTEM' },
      })
      await this.audit.record(tx, {
        action: AuditAction.CONSULTATION_CANCELLED,
        resourceType: 'consultation',
        resourceId: consultationId,
        actorId: doctorUserId,
        actorRole: 'DOCTOR',
        metadata: { reason: 'no_show' },
      })
    })
    consultationsTotal.inc({ status: 'NO_SHOW' })
  }

  private async loadForDoctor(doctorUserId: string, consultationId: string) {
    const consultation = await this.db.consultation.findUnique({
      where: { id: consultationId },
      include: { doctor: { select: { userId: true } } },
    })
    if (!consultation) throw new NotFoundError('Consultation', consultationId)
    if (consultation.doctor.userId !== doctorUserId) {
      throw new ForbiddenError('You do not have access to this consultation')
    }
    return consultation
  }
}
