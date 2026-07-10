import { z } from 'zod'

export const timeseriesQuerySchema = z
  .object({ days: z.coerce.number().int().min(1).max(180).default(30) })
  .strict()
export type TimeseriesQuery = z.infer<typeof timeseriesQuerySchema>

export const topDoctorsQuerySchema = z
  .object({ limit: z.coerce.number().int().min(1).max(50).default(10) })
  .strict()
export type TopDoctorsQuery = z.infer<typeof topDoctorsQuerySchema>
