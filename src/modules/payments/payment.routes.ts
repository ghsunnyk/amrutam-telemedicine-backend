import { Router } from 'express'
import type { Container } from '../../container'
import { asyncHandler } from '../../core/http'
import { authenticate } from '../../middleware/authenticate'
import { requireRole } from '../../middleware/authorize'
import { idempotency } from '../../middleware/idempotency'
import { policies, rateLimit } from '../../middleware/rateLimit'
import { validate } from '../../middleware/validate'
import { consultationIdParamSchema, refundPaymentSchema } from './payment.schemas'

export function createPaymentRouter(c: Container): Router {
  const router = Router()
  const { paymentController: ctrl, tokens, db } = c
  const requireAuth = authenticate(tokens, db)

  router.post(
    '/:consultationId/pay',
    requireAuth,
    requireRole('PATIENT'),
    rateLimit(db, policies.booking),
    idempotency(db, { required: true }),
    validate(consultationIdParamSchema, 'params'),
    asyncHandler(ctrl.pay)
  )

  router.post(
    '/:consultationId/refund',
    requireAuth,
    requireRole('ADMIN', 'PATIENT'),
    validate(consultationIdParamSchema, 'params'),
    validate(refundPaymentSchema),
    asyncHandler(ctrl.refund)
  )

  return router
}
