import { z } from 'zod'

export const createAvailabilityRuleSchema = z
  .object({
    weekday: z.number().int().min(0).max(6),
    startMinute: z.number().int().min(0).max(1439),
    endMinute: z.number().int().min(1).max(1440),
    timezone: z.string().trim().min(1).max(64).default('Asia/Kolkata'),
    slotDurationMinutes: z.number().int().min(10).max(180).optional(),
    effectiveFrom: z.coerce.date(),
    effectiveTo: z.coerce.date().optional(),
  })
  .strict()
  .refine(v => v.endMinute > v.startMinute, {
    message: 'endMinute must be after startMinute',
    path: ['endMinute'],
  })
  .refine(v => !v.effectiveTo || v.effectiveTo > v.effectiveFrom, {
    message: 'effectiveTo must be after effectiveFrom',
    path: ['effectiveTo'],
  })

export type CreateAvailabilityRuleInput = z.infer<typeof createAvailabilityRuleSchema>

export const ruleIdParamSchema = z.object({ ruleId: z.string().uuid() }).strict()

export const generateSlotsSchema = z
  .object({ horizonDays: z.number().int().min(1).max(365).optional() })
  .strict()

export type GenerateSlotsInput = z.infer<typeof generateSlotsSchema>

export const listSlotsQuerySchema = z
  .object({
    from: z.coerce.date().optional(),
    to: z.coerce.date().optional(),
    limit: z.coerce.number().int().min(1).max(200).default(50),
  })
  .strict()
  .refine(v => !v.from || !v.to || v.to > v.from, {
    message: 'to must be after from',
    path: ['to'],
  })

export type ListSlotsQuery = z.infer<typeof listSlotsQuerySchema>

export const doctorIdParamSchema = z.object({ doctorId: z.string().uuid() }).strict()
export const slotIdParamSchema = z.object({ slotId: z.string().uuid() }).strict()

export const releaseHoldSchema = z.object({ holdToken: z.string().uuid() }).strict()
export type ReleaseHoldInput = z.infer<typeof releaseHoldSchema>
