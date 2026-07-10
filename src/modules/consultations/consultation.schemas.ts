import { z } from 'zod'

export const bookConsultationSchema = z
  .object({
    slotId: z.string().uuid(),
    holdToken: z.string().uuid(),
    mode: z.enum(['VIDEO', 'AUDIO', 'CHAT', 'IN_PERSON']).default('VIDEO'),
    chiefComplaint: z.string().trim().min(1).max(2000).optional(),
    symptoms: z.string().trim().min(1).max(2000).optional(),
  })
  .strict()

export type BookConsultationInput = z.infer<typeof bookConsultationSchema>

export const consultationIdParamSchema = z.object({ consultationId: z.string().uuid() }).strict()

export const cancelConsultationSchema = z
  .object({ reason: z.string().trim().min(3).max(500) })
  .strict()

export type CancelConsultationInput = z.infer<typeof cancelConsultationSchema>

export const completeConsultationSchema = z
  .object({
    diagnosis: z.string().trim().min(1).max(4000).optional(),
    doctorNotes: z.string().trim().min(1).max(4000).optional(),
    followUpNotes: z.string().trim().min(1).max(2000).optional(),
  })
  .strict()

export type CompleteConsultationInput = z.infer<typeof completeConsultationSchema>
