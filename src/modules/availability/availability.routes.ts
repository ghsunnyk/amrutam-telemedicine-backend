import { Router } from 'express'
import type { Container } from '../../container'
import { asyncHandler } from '../../core/http'
import { authenticate } from '../../middleware/authenticate'
import { requireRole } from '../../middleware/authorize'
import { policies, rateLimit } from '../../middleware/rateLimit'
import { validate } from '../../middleware/validate'
import {
  createAvailabilityRuleSchema,
  doctorIdParamSchema,
  generateSlotsSchema,
  listSlotsQuerySchema,
  releaseHoldSchema,
  ruleIdParamSchema,
  slotIdParamSchema,
} from './availability.schemas'

export function createAvailabilityRouter(c: Container): Router {
  const router = Router()
  const { availabilityController: ctrl, tokens, db } = c
  const requireAuth = authenticate(tokens, db)

  router.post(
    '/rules',
    requireAuth,
    requireRole('DOCTOR'),
    validate(createAvailabilityRuleSchema),
    asyncHandler(ctrl.createRule)
  )

  router.delete(
    '/rules/:ruleId',
    requireAuth,
    requireRole('DOCTOR'),
    validate(ruleIdParamSchema, 'params'),
    asyncHandler(ctrl.deleteRule)
  )

  router.post(
    '/slots/generate',
    requireAuth,
    requireRole('DOCTOR'),
    validate(generateSlotsSchema),
    asyncHandler(ctrl.generateSlots)
  )

  router.get(
    '/:doctorId/slots',
    validate(doctorIdParamSchema, 'params'),
    validate(listSlotsQuerySchema, 'query'),
    asyncHandler(ctrl.listSlots)
  )

  router.post(
    '/slots/:slotId/hold',
    requireAuth,
    requireRole('PATIENT'),
    rateLimit(db, policies.booking),
    validate(slotIdParamSchema, 'params'),
    asyncHandler(ctrl.holdSlot)
  )

  router.delete(
    '/slots/:slotId/hold',
    requireAuth,
    requireRole('PATIENT'),
    validate(slotIdParamSchema, 'params'),
    validate(releaseHoldSchema),
    asyncHandler(ctrl.releaseHold)
  )

  return router
}
