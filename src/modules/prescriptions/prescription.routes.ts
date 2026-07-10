import { Router } from 'express'
import type { Container } from '../../container'
import { asyncHandler } from '../../core/http'
import { authenticate } from '../../middleware/authenticate'
import { requireRole } from '../../middleware/authorize'
import { validate } from '../../middleware/validate'
import {
  consultationIdParamSchema,
  createPrescriptionSchema,
  prescriptionIdParamSchema,
  revokePrescriptionSchema,
  updatePrescriptionSchema,
} from './prescription.schemas'

export function createPrescriptionRouter(c: Container): Router {
  const router = Router()
  const { prescriptionController: ctrl, tokens, db } = c
  const requireAuth = authenticate(tokens, db)

  router.post(
    '/consultations/:consultationId/prescriptions',
    requireAuth,
    requireRole('DOCTOR'),
    validate(consultationIdParamSchema, 'params'),
    validate(createPrescriptionSchema),
    asyncHandler(ctrl.create)
  )
  router.get(
    '/consultations/:consultationId/prescriptions',
    requireAuth,
    validate(consultationIdParamSchema, 'params'),
    asyncHandler(ctrl.getByConsultation)
  )
  router.patch(
    '/prescriptions/:prescriptionId',
    requireAuth,
    requireRole('DOCTOR'),
    validate(prescriptionIdParamSchema, 'params'),
    validate(updatePrescriptionSchema),
    asyncHandler(ctrl.update)
  )
  router.post(
    '/prescriptions/:prescriptionId/issue',
    requireAuth,
    requireRole('DOCTOR'),
    validate(prescriptionIdParamSchema, 'params'),
    asyncHandler(ctrl.issue)
  )
  router.post(
    '/prescriptions/:prescriptionId/revoke',
    requireAuth,
    requireRole('DOCTOR'),
    validate(prescriptionIdParamSchema, 'params'),
    validate(revokePrescriptionSchema),
    asyncHandler(ctrl.revoke)
  )

  return router
}
