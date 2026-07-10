import { Router } from 'express'
import type { Container } from '../../container'
import { asyncHandler } from '../../core/http'
import { authenticate } from '../../middleware/authenticate'
import { requireRole } from '../../middleware/authorize'
import { idempotency } from '../../middleware/idempotency'
import { policies, rateLimit } from '../../middleware/rateLimit'
import { validate } from '../../middleware/validate'
import {
  bookConsultationSchema,
  cancelConsultationSchema,
  completeConsultationSchema,
  consultationIdParamSchema,
} from './consultation.schemas'

export function createConsultationRouter(c: Container): Router {
  const router = Router()
  const { consultationController: ctrl, tokens, db } = c
  const requireAuth = authenticate(tokens, db)

  router.post(
    '/',
    requireAuth,
    requireRole('PATIENT'),
    rateLimit(db, policies.booking),
    idempotency(db, { required: true }),
    validate(bookConsultationSchema),
    asyncHandler(ctrl.book)
  )

  router.get(
    '/:consultationId',
    requireAuth,
    validate(consultationIdParamSchema, 'params'),
    asyncHandler(ctrl.getById)
  )

  router.post(
    '/:consultationId/start',
    requireAuth,
    requireRole('DOCTOR'),
    validate(consultationIdParamSchema, 'params'),
    asyncHandler(ctrl.start)
  )
  router.post(
    '/:consultationId/complete',
    requireAuth,
    requireRole('DOCTOR'),
    validate(consultationIdParamSchema, 'params'),
    validate(completeConsultationSchema),
    asyncHandler(ctrl.complete)
  )
  router.post(
    '/:consultationId/cancel',
    requireAuth,
    validate(consultationIdParamSchema, 'params'),
    validate(cancelConsultationSchema),
    asyncHandler(ctrl.cancel)
  )
  router.post(
    '/:consultationId/no-show',
    requireAuth,
    requireRole('DOCTOR'),
    validate(consultationIdParamSchema, 'params'),
    asyncHandler(ctrl.markNoShow)
  )

  return router
}
