import { Router } from 'express'
import type { Container } from '../../container'
import { asyncHandler } from '../../core/http'
import { authenticate } from '../../middleware/authenticate'
import { requireRole } from '../../middleware/authorize'
import { validate } from '../../middleware/validate'
import { timeseriesQuerySchema, topDoctorsQuerySchema } from './analytics.schemas'

export function createAnalyticsRouter(c: Container): Router {
  const router = Router()
  const { analyticsController: ctrl, tokens, db } = c
  const requireAuth = authenticate(tokens, db)

  router.use(requireAuth, requireRole('ADMIN'))
  router.get('/overview', asyncHandler(ctrl.overview))
  router.get(
    '/consultations/timeseries',
    validate(timeseriesQuerySchema, 'query'),
    asyncHandler(ctrl.timeseries)
  )
  router.get(
    '/doctors/top',
    validate(topDoctorsQuerySchema, 'query'),
    asyncHandler(ctrl.topDoctors)
  )

  return router
}
