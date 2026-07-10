import { z } from 'zod'

const slug = z
  .string()
  .trim()
  .toLowerCase()
  .regex(/^[a-z0-9-]+$/)

const feeMinor = z.coerce.number().int().min(0).max(10_000_000)

export const applyAsDoctorSchema = z
  .object({
    registrationNumber: z.string().trim().min(3).max(64),
    registrationCouncil: z.string().trim().min(2).max(120),
    headline: z.string().trim().max(160).optional(),
    bio: z.string().trim().max(2000).optional(),
    yearsOfExperience: z.number().int().min(0).max(70).optional(),
    languages: z.array(z.string().trim().min(2).max(40)).max(20).optional(),
    qualifications: z.array(z.string().trim().min(2).max(120)).max(20).optional(),
    city: z.string().trim().max(80).optional(),
    state: z.string().trim().max(80).optional(),
    country: z.string().trim().length(2).toUpperCase().optional(),
    consultationFeeMinor: feeMinor,
    currency: z.string().trim().length(3).toUpperCase().optional(),
    slotDurationMinutes: z.number().int().min(10).max(180).optional(),
    slotHoldMinutes: z.number().int().min(2).max(60).optional(),
    specializationSlugs: z.array(slug).min(1).max(10),
  })
  .strict()

export type ApplyAsDoctorInput = z.infer<typeof applyAsDoctorSchema>

export const updateDoctorProfileSchema = z
  .object({
    headline: z.string().trim().max(160).optional(),
    bio: z.string().trim().max(2000).optional(),
    yearsOfExperience: z.number().int().min(0).max(70).optional(),
    languages: z.array(z.string().trim().min(2).max(40)).max(20).optional(),
    qualifications: z.array(z.string().trim().min(2).max(120)).max(20).optional(),
    city: z.string().trim().max(80).optional(),
    state: z.string().trim().max(80).optional(),
    isAcceptingPatients: z.boolean().optional(),
    consultationFeeMinor: feeMinor.optional(),
    specializationSlugs: z.array(slug).min(1).max(10).optional(),
  })
  .strict()

export type UpdateDoctorProfileInput = z.infer<typeof updateDoctorProfileSchema>

export const rejectDoctorSchema = z.object({ reason: z.string().trim().min(5).max(500) }).strict()

export type RejectDoctorInput = z.infer<typeof rejectDoctorSchema>

export const searchDoctorsQuerySchema = z
  .object({
    specialization: slug.optional(),
    city: z.string().trim().max(80).optional(),
    minFee: z.coerce.number().int().min(0).optional(),
    maxFee: z.coerce.number().int().min(0).optional(),
    minRating: z.coerce.number().min(0).max(5).optional(),
    sort: z.enum(['rating', 'fee_asc', 'experience']).default('rating'),
    cursor: z.string().max(512).optional(),
    limit: z.coerce.number().int().min(1).max(50).default(20),
  })
  .strict()

export type SearchDoctorsQuery = z.infer<typeof searchDoctorsQuerySchema>

export const doctorIdParamSchema = z.object({ doctorId: z.string().uuid() }).strict()
