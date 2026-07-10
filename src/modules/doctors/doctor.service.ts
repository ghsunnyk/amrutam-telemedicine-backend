import { blindIndex } from '../../core/crypto/encryption'
import { fieldAad, type Keyring } from '../../core/crypto/keyring'
import { ConflictError, ForbiddenError, NotFoundError, ValidationError } from '../../core/errors'
import { decodeCursor, encodeCursor, type Paginated } from '../../core/http'
import type { Db } from '../../db/prisma'
import type { Prisma } from '../../generated/prisma/client'
import { AuditAction, type AuditService } from '../audit/audit.service'
import type {
  ApplyAsDoctorInput,
  SearchDoctorsQuery,
  UpdateDoctorProfileInput,
} from './doctor.schemas'

type DoctorWithSpecs = Prisma.DoctorGetPayload<{
  include: { specializations: { include: { specialization: true } } }
}>

export interface DoctorSummary {
  id: string
  headline: string | null
  bio: string | null
  yearsOfExperience: number
  languages: string[]
  city: string | null
  state: string | null
  country: string
  consultationFeeMinor: number
  currency: string
  ratingAvg: string
  ratingCount: number
  isAcceptingPatients: boolean
  specializations: { slug: string; name: string }[]
}

export class DoctorService {
  constructor(
    private readonly db: Db,
    private readonly keyring: Keyring,
    private readonly audit: AuditService
  ) {}

  async applyAsDoctor(userId: string, input: ApplyAsDoctorInput): Promise<{ doctorId: string }> {
    const user = await this.db.user.findUnique({ where: { id: userId } })
    if (!user || user.deletedAt) throw new NotFoundError('User', userId)
    if (user.role !== 'PATIENT') {
      throw new ConflictError('Only patient accounts can apply to become a doctor')
    }

    const existing = await this.db.doctor.findUnique({ where: { userId } })
    if (existing) throw new ConflictError('A doctor application already exists for this account')

    const specializations = await this.db.specialization.findMany({
      where: { slug: { in: input.specializationSlugs } },
    })
    if (specializations.length !== input.specializationSlugs.length) {
      throw new ValidationError('One or more specializations are unknown', {
        fields: { specializationSlugs: ['contains unknown slug(s)'] },
      })
    }

    const registrationNumberHash = blindIndex(
      input.registrationNumber,
      'doctor.registration_number'
    )

    try {
      const doctor = await this.db.$transaction(async tx => {
        const created = await tx.doctor.create({
          data: {
            userId,
            registrationNumberHash,
            registrationNumberEnc: this.keyring.encryptField(
              input.registrationNumber,
              fieldAad('doctor', userId, 'registration_number')
            ),
            registrationCouncil: input.registrationCouncil,
            headline: input.headline,
            bio: input.bio,
            yearsOfExperience: input.yearsOfExperience ?? 0,
            languages: input.languages ?? [],
            qualifications: input.qualifications ?? [],
            city: input.city,
            state: input.state,
            country: input.country ?? 'IN',
            consultationFeeMinor: input.consultationFeeMinor,
            currency: input.currency ?? 'INR',
            slotDurationMinutes: input.slotDurationMinutes ?? 30,
            slotHoldMinutes: input.slotHoldMinutes ?? 10,
            isAcceptingPatients: false,
            specializations: { create: specializations.map(s => ({ specializationId: s.id })) },
          },
        })

        await this.audit.record(tx, {
          action: AuditAction.DOCTOR_APPLICATION_SUBMITTED,
          resourceType: 'doctor',
          resourceId: created.id,
          actorId: userId,
        })

        return created
      })

      return { doctorId: doctor.id }
    } catch (err) {
      if (isUniqueViolation(err, 'registration_number_hash')) {
        throw new ConflictError('This medical registration number is already registered')
      }
      throw err
    }
  }

  async verify(doctorId: string, adminUserId: string): Promise<void> {
    const doctor = await this.db.doctor.findUnique({ where: { id: doctorId } })
    if (!doctor) throw new NotFoundError('Doctor', doctorId)
    if (doctor.verificationStatus === 'VERIFIED') {
      throw new ConflictError('Doctor is already verified')
    }

    await this.db.$transaction(async tx => {
      await tx.doctor.update({
        where: { id: doctorId },
        data: {
          verificationStatus: 'VERIFIED',
          verifiedAt: new Date(),
          verifiedByUserId: adminUserId,
          rejectionReason: null,
          isAcceptingPatients: true,
        },
      })
      await tx.user.update({ where: { id: doctor.userId }, data: { role: 'DOCTOR' } })
      await this.audit.record(tx, {
        action: AuditAction.DOCTOR_VERIFIED,
        resourceType: 'doctor',
        resourceId: doctorId,
        actorId: adminUserId,
        actorRole: 'ADMIN',
      })
    })
  }

  async reject(doctorId: string, adminUserId: string, reason: string): Promise<void> {
    const doctor = await this.db.doctor.findUnique({ where: { id: doctorId } })
    if (!doctor) throw new NotFoundError('Doctor', doctorId)
    if (doctor.verificationStatus === 'VERIFIED') {
      throw new ConflictError('Cannot reject a doctor that is already verified')
    }

    await this.db.$transaction(async tx => {
      await tx.doctor.update({
        where: { id: doctorId },
        data: {
          verificationStatus: 'REJECTED',
          rejectionReason: reason,
          isAcceptingPatients: false,
        },
      })
      await this.audit.record(tx, {
        action: AuditAction.DOCTOR_REJECTED,
        resourceType: 'doctor',
        resourceId: doctorId,
        actorId: adminUserId,
        actorRole: 'ADMIN',
        metadata: { reason },
      })
    })
  }

  async updateProfile(userId: string, input: UpdateDoctorProfileInput): Promise<void> {
    const doctor = await this.db.doctor.findUnique({ where: { userId } })
    if (!doctor) throw new NotFoundError('Doctor profile')

    let specializationUpdate: Prisma.DoctorUpdateInput = {}
    if (input.specializationSlugs) {
      const specializations = await this.db.specialization.findMany({
        where: { slug: { in: input.specializationSlugs } },
      })
      if (specializations.length !== input.specializationSlugs.length) {
        throw new ValidationError('One or more specializations are unknown', {
          fields: { specializationSlugs: ['contains unknown slug(s)'] },
        })
      }
      specializationUpdate = {
        specializations: {
          deleteMany: {},
          create: specializations.map(s => ({ specializationId: s.id })),
        },
      }
    }

    await this.db.$transaction(async tx => {
      await tx.doctor.update({
        where: { id: doctor.id },
        data: {
          headline: input.headline,
          bio: input.bio,
          yearsOfExperience: input.yearsOfExperience,
          languages: input.languages,
          qualifications: input.qualifications,
          city: input.city,
          state: input.state,
          isAcceptingPatients: input.isAcceptingPatients,
          consultationFeeMinor: input.consultationFeeMinor,
          version: { increment: 1 },
          ...specializationUpdate,
        },
      })
      await this.audit.record(tx, {
        action: AuditAction.DOCTOR_PROFILE_UPDATED,
        resourceType: 'doctor',
        resourceId: doctor.id,
        actorId: userId,
      })
    })
  }

  async search(query: SearchDoctorsQuery): Promise<Paginated<DoctorSummary>> {
    const limit = query.limit ?? 20
    const cursor = query.cursor ? decodeCursor<{ v: string; id: string }>(query.cursor) : null

    const where: Prisma.DoctorWhereInput = {
      verificationStatus: 'VERIFIED',
      isAcceptingPatients: true,
      ...(query.city ? { city: { equals: query.city, mode: 'insensitive' } } : {}),
      ...(query.minFee || query.maxFee
        ? {
            consultationFeeMinor: {
              ...(query.minFee ? { gte: query.minFee } : {}),
              ...(query.maxFee ? { lte: query.maxFee } : {}),
            },
          }
        : {}),
      ...(query.minRating ? { ratingAvg: { gte: query.minRating } } : {}),
      ...(query.specialization
        ? { specializations: { some: { specialization: { slug: query.specialization } } } }
        : {}),
      ...(cursor ? cursorFilter(query.sort, cursor) : {}),
    }

    const orderBy: Prisma.DoctorOrderByWithRelationInput[] =
      query.sort === 'fee_asc'
        ? [{ consultationFeeMinor: 'asc' }, { id: 'asc' }]
        : query.sort === 'experience'
          ? [{ yearsOfExperience: 'desc' }, { id: 'asc' }]
          : [{ ratingAvg: 'desc' }, { ratingCount: 'desc' }, { id: 'asc' }]

    const doctors = await this.db.doctor.findMany({
      where,
      orderBy,
      take: limit + 1,
      include: { specializations: { include: { specialization: true } } },
    })

    const hasMore = doctors.length > limit
    const page = hasMore ? doctors.slice(0, limit) : doctors
    const last = page[page.length - 1]

    return {
      items: page.map(toDoctorSummary),
      hasMore,
      nextCursor:
        hasMore && last ? encodeCursor({ v: sortValue(query.sort, last), id: last.id }) : null,
    }
  }

  async getById(doctorId: string): Promise<DoctorSummary> {
    const doctor = await this.db.doctor.findUnique({
      where: { id: doctorId },
      include: { specializations: { include: { specialization: true } } },
    })
    if (!doctor || doctor.verificationStatus !== 'VERIFIED') {
      throw new NotFoundError('Doctor', doctorId)
    }
    return toDoctorSummary(doctor)
  }

  async assertOwnsDoctorProfile(userId: string, doctorId: string): Promise<void> {
    const doctor = await this.db.doctor.findUnique({
      where: { id: doctorId },
      select: { userId: true },
    })
    if (!doctor) throw new NotFoundError('Doctor', doctorId)
    if (doctor.userId !== userId) throw new ForbiddenError('You do not own this doctor profile')
  }
}

function sortValue(sort: SearchDoctorsQuery['sort'], doctor: DoctorWithSpecs): string {
  if (sort === 'fee_asc') return String(doctor.consultationFeeMinor)
  if (sort === 'experience') return String(doctor.yearsOfExperience)
  return doctor.ratingAvg.toString()
}

function cursorFilter(
  sort: SearchDoctorsQuery['sort'],
  cursor: { v: string; id: string }
): Prisma.DoctorWhereInput {
  if (sort === 'fee_asc') {
    return {
      OR: [
        { consultationFeeMinor: { gt: Number(cursor.v) } },
        { consultationFeeMinor: Number(cursor.v), id: { gt: cursor.id } },
      ],
    }
  }
  if (sort === 'experience') {
    return {
      OR: [
        { yearsOfExperience: { lt: Number(cursor.v) } },
        { yearsOfExperience: Number(cursor.v), id: { gt: cursor.id } },
      ],
    }
  }
  return {
    OR: [
      { ratingAvg: { lt: Number(cursor.v) } },
      { ratingAvg: Number(cursor.v), id: { gt: cursor.id } },
    ],
  }
}

function toDoctorSummary(doctor: DoctorWithSpecs): DoctorSummary {
  return {
    id: doctor.id,
    headline: doctor.headline,
    bio: doctor.bio,
    yearsOfExperience: doctor.yearsOfExperience,
    languages: doctor.languages,
    city: doctor.city,
    state: doctor.state,
    country: doctor.country,
    consultationFeeMinor: doctor.consultationFeeMinor,
    currency: doctor.currency,
    ratingAvg: doctor.ratingAvg.toString(),
    ratingCount: doctor.ratingCount,
    isAcceptingPatients: doctor.isAcceptingPatients,
    specializations: doctor.specializations.map(ds => ({
      slug: ds.specialization.slug,
      name: ds.specialization.name,
    })),
  }
}

function isUniqueViolation(err: unknown, column: string): boolean {
  const e = err as { code?: string; meta?: { target?: string[] | string } }
  if (e?.code !== 'P2002') return false
  const target = e.meta?.target
  const columns = Array.isArray(target) ? target : [target ?? '']
  return columns.some(c => c?.includes(column))
}
