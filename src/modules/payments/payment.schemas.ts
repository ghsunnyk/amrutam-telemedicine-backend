import { z } from 'zod'

export const consultationIdParamSchema = z.object({ consultationId: z.string().uuid() }).strict()

export const refundPaymentSchema = z.object({ reason: z.string().trim().min(3).max(500) }).strict()
export type RefundPaymentInput = z.infer<typeof refundPaymentSchema>
