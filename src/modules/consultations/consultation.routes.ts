import { Router } from 'express'
import type { Container } from '../../container'
import { asyncHandler } from '../../core/http'
import { authenticate } from '../../middleware/authenticate'
import { requireRole } from '../../middleware/authorize'
import { idempotency } from '../../middleware/idempotency'
import { policies, rateLimit } from '../../middleware/rateLimit'
import { validate } from '../../middleware/validate'
import { bookConsultationSchema, consultationIdParamSchema } from './consultation.schemas'

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

  return router
}
