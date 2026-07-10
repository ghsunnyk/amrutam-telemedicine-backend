import { env } from '../../config/env'
import { signBlob, toDbBytes } from '../../core/crypto/encryption'
import { fieldAad, type Keyring } from '../../core/crypto/keyring'
import { ConflictError, ForbiddenError, NotFoundError } from '../../core/errors'
import type { Db } from '../../db/prisma'
import { AuditAction, type AuditService } from '../audit/audit.service'
import type {
  CreatePrescriptionInput,
  MedicineItem,
  UpdatePrescriptionInput,
} from './prescription.schemas'

export interface PrescriptionView {
  id: string
  consultationId: string
  status: string
  items: MedicineItem[]
  advice: string | null
  issuedAt: Date | null
  validUntil: Date | null
  revokedAt: Date | null
  revokedReason: string | null
}

export class PrescriptionService {
  constructor(
    private readonly db: Db,
    private readonly keyring: Keyring,
    private readonly audit: AuditService
  ) {}

  async create(
    doctorUserId: string,
    consultationId: string,
    input: CreatePrescriptionInput
  ): Promise<{ id: string }> {
    const consultation = await this.loadOwnedConsultation(doctorUserId, consultationId)
    if (!['IN_PROGRESS', 'COMPLETED'].includes(consultation.status)) {
      throw new ConflictError('Prescriptions can only be created during or after a consultation')
    }
    const existing = await this.db.prescription.findUnique({ where: { consultationId } })
    if (existing) throw new ConflictError('A prescription already exists for this consultation')

    const prescription = await this.db.$transaction(async tx => {
      const created = await tx.prescription.create({
        data: {
          consultationId,
          doctorId: consultation.doctorId,
          status: 'DRAFT',
          itemsEnc: this.keyring.encryptField(
            JSON.stringify(input.items),
            fieldAad('prescription', consultationId, 'items')
          ),
          adviceEnc: input.advice
            ? this.keyring.encryptField(
                input.advice,
                fieldAad('prescription', consultationId, 'advice')
              )
            : undefined,
          validUntil: input.validForDays
            ? new Date(Date.now() + input.validForDays * 86_400_000)
            : undefined,
        },
      })
      await this.audit.record(tx, {
        action: AuditAction.PRESCRIPTION_CREATED,
        resourceType: 'prescription',
        resourceId: created.id,
        actorId: doctorUserId,
        actorRole: 'DOCTOR',
      })
      return created
    })
    return { id: prescription.id }
  }

  async update(
    doctorUserId: string,
    prescriptionId: string,
    input: UpdatePrescriptionInput
  ): Promise<void> {
    const prescription = await this.loadOwnedPrescription(doctorUserId, prescriptionId)
    if (prescription.status !== 'DRAFT')
      throw new ConflictError('Only draft prescriptions can be edited')

    await this.db.prescription.update({
      where: { id: prescriptionId },
      data: {
        itemsEnc: input.items
          ? this.keyring.encryptField(
              JSON.stringify(input.items),
              fieldAad('prescription', prescription.consultationId, 'items')
            )
          : undefined,
        adviceEnc: input.advice
          ? this.keyring.encryptField(
              input.advice,
              fieldAad('prescription', prescription.consultationId, 'advice')
            )
          : undefined,
        validUntil: input.validForDays
          ? new Date(Date.now() + input.validForDays * 86_400_000)
          : undefined,
        version: { increment: 1 },
      },
    })
  }

  async issue(doctorUserId: string, prescriptionId: string): Promise<void> {
    const prescription = await this.loadOwnedPrescription(doctorUserId, prescriptionId)
    if (prescription.status !== 'DRAFT')
      throw new ConflictError('Only draft prescriptions can be issued')

    const signaturePayload = Buffer.concat([
      Buffer.from(prescription.id, 'utf8'),
      Buffer.from(prescription.consultationId, 'utf8'),
      prescription.itemsEnc,
      prescription.adviceEnc ?? Buffer.alloc(0),
    ])
    const signature = signBlob(signaturePayload)

    await this.db.$transaction(async tx => {
      await tx.prescription.update({
        where: { id: prescriptionId },
        data: {
          status: 'ISSUED',
          issuedAt: new Date(),
          signature: toDbBytes(signature),
          signatureKeyId: env.ENCRYPTION_KEK_ID,
        },
      })
      await this.audit.record(tx, {
        action: AuditAction.PRESCRIPTION_ISSUED,
        resourceType: 'prescription',
        resourceId: prescriptionId,
        actorId: doctorUserId,
        actorRole: 'DOCTOR',
      })
    })
  }

  async revoke(doctorUserId: string, prescriptionId: string, reason: string): Promise<void> {
    const prescription = await this.loadOwnedPrescription(doctorUserId, prescriptionId)
    if (prescription.status !== 'ISSUED')
      throw new ConflictError('Only issued prescriptions can be revoked')

    await this.db.$transaction(async tx => {
      await tx.prescription.update({
        where: { id: prescriptionId },
        data: { status: 'REVOKED', revokedAt: new Date(), revokedReason: reason },
      })
      await this.audit.record(tx, {
        action: AuditAction.PRESCRIPTION_REVOKED,
        resourceType: 'prescription',
        resourceId: prescriptionId,
        actorId: doctorUserId,
        actorRole: 'DOCTOR',
        metadata: { reason },
      })
    })
  }

  async getByConsultation(
    userId: string,
    role: string,
    consultationId: string
  ): Promise<PrescriptionView> {
    const prescription = await this.db.prescription.findUnique({
      where: { consultationId },
      include: {
        consultation: { select: { patientId: true } },
        doctor: { select: { userId: true } },
      },
    })
    if (!prescription) throw new NotFoundError('Prescription for this consultation')
    const isOwner =
      prescription.consultation.patientId === userId ||
      prescription.doctor.userId === userId ||
      role === 'ADMIN'
    if (!isOwner) throw new ForbiddenError('You do not have access to this prescription')

    await this.audit.recordDetached({
      action: AuditAction.PRESCRIPTION_VIEWED,
      resourceType: 'prescription',
      resourceId: prescription.id,
      actorId: userId,
    })
    return this.toView(prescription)
  }

  private toView(prescription: {
    id: string
    consultationId: string
    status: string
    itemsEnc: Uint8Array
    adviceEnc: Uint8Array | null
    issuedAt: Date | null
    validUntil: Date | null
    revokedAt: Date | null
    revokedReason: string | null
  }): PrescriptionView {
    const items = JSON.parse(
      this.keyring.decryptField(
        prescription.itemsEnc,
        fieldAad('prescription', prescription.consultationId, 'items')
      )
    ) as MedicineItem[]
    const advice = prescription.adviceEnc
      ? this.keyring.decryptField(
          prescription.adviceEnc,
          fieldAad('prescription', prescription.consultationId, 'advice')
        )
      : null
    return {
      id: prescription.id,
      consultationId: prescription.consultationId,
      status: prescription.status,
      items,
      advice,
      issuedAt: prescription.issuedAt,
      validUntil: prescription.validUntil,
      revokedAt: prescription.revokedAt,
      revokedReason: prescription.revokedReason,
    }
  }

  private async loadOwnedConsultation(doctorUserId: string, consultationId: string) {
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

  private async loadOwnedPrescription(doctorUserId: string, prescriptionId: string) {
    const prescription = await this.db.prescription.findUnique({
      where: { id: prescriptionId },
      include: { doctor: { select: { userId: true } } },
    })
    if (!prescription) throw new NotFoundError('Prescription', prescriptionId)
    if (prescription.doctor.userId !== doctorUserId)
      throw new ForbiddenError('You do not own this prescription')
    return prescription
  }
}
