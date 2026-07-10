import { randomUUID } from 'node:crypto'
import { env } from '../../config/env'
import { ConflictError, ForbiddenError, NotFoundError } from '../../core/errors'
import { zonedDateParts, zonedWallTimeToUtc } from '../../core/timezone'
import type { Db } from '../../db/prisma'
import { AuditAction, type AuditService } from '../audit/audit.service'
import type { CreateAvailabilityRuleInput, ListSlotsQuery } from './availability.schemas'

export interface HeldSlot {
  slotId: string
  holdToken: string
  holdExpiresAt: Date
  doctorId: string
  startAt: Date
  endAt: Date
}

export class AvailabilityService {
  constructor(
    private readonly db: Db,
    private readonly audit: AuditService
  ) {}

  async createRule(
    doctorUserId: string,
    input: CreateAvailabilityRuleInput
  ): Promise<{ id: string }> {
    const doctor = await this.doctorForUser(doctorUserId)

    const rule = await this.db.availabilityRule.create({
      data: {
        doctorId: doctor.id,
        weekday: input.weekday,
        startMinute: input.startMinute,
        endMinute: input.endMinute,
        timezone: input.timezone,
        slotDurationMinutes: input.slotDurationMinutes ?? doctor.slotDurationMinutes,
        effectiveFrom: input.effectiveFrom,
        effectiveTo: input.effectiveTo,
      },
    })

    await this.audit.recordDetached({
      action: AuditAction.AVAILABILITY_RULE_CREATED,
      resourceType: 'availability_rule',
      resourceId: rule.id,
      actorId: doctorUserId,
    })

    return { id: rule.id }
  }

  async deleteRule(doctorUserId: string, ruleId: string): Promise<void> {
    const doctor = await this.doctorForUser(doctorUserId)

    const { count } = await this.db.availabilityRule.updateMany({
      where: { id: ruleId, doctorId: doctor.id },
      data: { isActive: false },
    })
    if (count !== 1) throw new NotFoundError('Availability rule', ruleId)

    await this.audit.recordDetached({
      action: AuditAction.AVAILABILITY_RULE_DELETED,
      resourceType: 'availability_rule',
      resourceId: ruleId,
      actorId: doctorUserId,
    })
  }

  async generateSlots(doctorUserId: string, horizonDays?: number): Promise<{ created: number }> {
    const doctor = await this.doctorForUser(doctorUserId)
    return this.generateSlotsForDoctor(doctor.id, horizonDays)
  }

  async generateSlotsForDoctor(
    doctorId: string,
    horizonDays?: number
  ): Promise<{ created: number }> {
    const horizon = horizonDays ?? env.SLOT_HORIZON_DAYS
    const now = new Date()

    const rules = await this.db.availabilityRule.findMany({
      where: {
        doctorId,
        isActive: true,
        effectiveFrom: { lte: new Date(now.getTime() + horizon * 86_400_000) },
        OR: [{ effectiveTo: null }, { effectiveTo: { gte: now } }],
      },
    })
    if (rules.length === 0) return { created: 0 }

    const rows: { doctorId: string; startAt: Date; endAt: Date; sourceRuleId: string }[] = []

    for (const rule of rules) {
      for (let dayOffset = 0; dayOffset <= horizon; dayOffset++) {
        const candidate = new Date(now.getTime() + dayOffset * 86_400_000)
        const parts = zonedDateParts(candidate, rule.timezone)
        if (parts.weekday !== rule.weekday) continue

        for (
          let minute = rule.startMinute;
          minute + rule.slotDurationMinutes <= rule.endMinute;
          minute += rule.slotDurationMinutes
        ) {
          const startAt = zonedWallTimeToUtc(
            parts.year,
            parts.month,
            parts.day,
            minute,
            rule.timezone
          )
          const endAt = new Date(startAt.getTime() + rule.slotDurationMinutes * 60_000)

          if (startAt <= now) continue
          if (startAt < rule.effectiveFrom) continue
          if (rule.effectiveTo && startAt > rule.effectiveTo) continue

          rows.push({ doctorId, startAt, endAt, sourceRuleId: rule.id })
        }
      }
    }

    if (rows.length === 0) return { created: 0 }

    const result = await this.db.availabilitySlot.createMany({
      data: rows.map(r => ({ ...r, status: 'AVAILABLE' as const })),
      skipDuplicates: true,
    })

    return { created: result.count }
  }

  async listAvailableSlots(doctorId: string, query: ListSlotsQuery) {
    const from = query.from ?? new Date()
    const to = query.to ?? new Date(from.getTime() + 14 * 86_400_000)

    return this.db.availabilitySlot.findMany({
      where: { doctorId, status: 'AVAILABLE', startAt: { gte: from, lte: to } },
      orderBy: { startAt: 'asc' },
      take: query.limit,
      select: { id: true, startAt: true, endAt: true },
    })
  }

  // Conditional CAS: only succeeds if the slot is free, or its previous hold has
  // expired. A race between two patients resolves to exactly one winner because
  // the WHERE clause is evaluated atomically by Postgres, not read-then-write.
  async holdSlot(patientUserId: string, slotId: string): Promise<HeldSlot> {
    const slot = await this.db.availabilitySlot.findUnique({
      where: { id: slotId },
      include: { doctor: { select: { slotHoldMinutes: true, isAcceptingPatients: true } } },
    })
    if (!slot) throw new NotFoundError('Slot', slotId)
    if (!slot.doctor.isAcceptingPatients)
      throw new ConflictError('Doctor is not accepting patients')
    if (slot.startAt <= new Date()) throw new ConflictError('Slot is in the past')

    const holdToken = randomUUID()
    const holdExpiresAt = new Date(Date.now() + slot.doctor.slotHoldMinutes * 60_000)
    const now = new Date()

    const { count } = await this.db.availabilitySlot.updateMany({
      where: {
        id: slotId,
        OR: [{ status: 'AVAILABLE' }, { status: 'HELD', holdExpiresAt: { lt: now } }],
      },
      data: { status: 'HELD', heldByUserId: patientUserId, holdExpiresAt, holdToken },
    })

    if (count !== 1) throw new ConflictError('Slot is no longer available', 'SLOT_UNAVAILABLE')

    await this.audit.recordDetached({
      action: AuditAction.SLOT_HELD,
      resourceType: 'availability_slot',
      resourceId: slotId,
      actorId: patientUserId,
    })

    return {
      slotId,
      holdToken,
      holdExpiresAt,
      doctorId: slot.doctorId,
      startAt: slot.startAt,
      endAt: slot.endAt,
    }
  }

  async releaseHold(patientUserId: string, slotId: string, holdToken: string): Promise<void> {
    const { count } = await this.db.availabilitySlot.updateMany({
      where: { id: slotId, holdToken, heldByUserId: patientUserId, status: 'HELD' },
      data: { status: 'AVAILABLE', heldByUserId: null, holdExpiresAt: null, holdToken: null },
    })
    if (count !== 1) throw new NotFoundError('Active hold', slotId)

    await this.audit.recordDetached({
      action: AuditAction.SLOT_HOLD_RELEASED,
      resourceType: 'availability_slot',
      resourceId: slotId,
      actorId: patientUserId,
    })
  }

  private async doctorForUser(userId: string) {
    const doctor = await this.db.doctor.findUnique({ where: { userId } })
    if (!doctor) throw new ForbiddenError('No doctor profile for this account')
    if (doctor.verificationStatus !== 'VERIFIED') {
      throw new ForbiddenError('Doctor profile is not yet verified')
    }
    return doctor
  }
}
