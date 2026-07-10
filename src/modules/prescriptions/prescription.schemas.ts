import { z } from 'zod'

const medicineItem = z
  .object({
    name: z.string().trim().min(1).max(160),
    dosage: z.string().trim().min(1).max(80),
    frequency: z.string().trim().min(1).max(80),
    durationDays: z.number().int().min(1).max(365),
    instructions: z.string().trim().max(300).optional(),
  })
  .strict()

export const createPrescriptionSchema = z
  .object({
    items: z.array(medicineItem).min(1).max(30),
    advice: z.string().trim().max(2000).optional(),
    validForDays: z.number().int().min(1).max(180).optional(),
  })
  .strict()
export type CreatePrescriptionInput = z.infer<typeof createPrescriptionSchema>
export type MedicineItem = z.infer<typeof medicineItem>

export const updatePrescriptionSchema = createPrescriptionSchema.partial().strict()
export type UpdatePrescriptionInput = z.infer<typeof updatePrescriptionSchema>

export const revokePrescriptionSchema = z
  .object({ reason: z.string().trim().min(3).max(500) })
  .strict()
export type RevokePrescriptionInput = z.infer<typeof revokePrescriptionSchema>

export const consultationIdParamSchema = z.object({ consultationId: z.string().uuid() }).strict()
export const prescriptionIdParamSchema = z.object({ prescriptionId: z.string().uuid() }).strict()
