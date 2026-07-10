import { Router } from 'express'
import type { Container } from '../../container'
import { asyncHandler } from '../../core/http'
import { authenticate } from '../../middleware/authenticate'
import { requireRole } from '../../middleware/authorize'
import { policies, rateLimit } from '../../middleware/rateLimit'
import { validate } from '../../middleware/validate'
import {
  applyAsDoctorSchema,
  doctorIdParamSchema,
  rejectDoctorSchema,
  searchDoctorsQuerySchema,
  updateDoctorProfileSchema,
} from './doctor.schemas'

export function createDoctorRouter(c: Container): Router {
  const router = Router()
  const { doctorController: ctrl, tokens, db } = c
  const requireAuth = authenticate(tokens, db)

  router.get(
    '/',
    rateLimit(db, policies.search),
    validate(searchDoctorsQuerySchema, 'query'),
    asyncHandler(ctrl.search)
  )

  router.get('/:doctorId', validate(doctorIdParamSchema, 'params'), asyncHandler(ctrl.getById))

  router.post(
    '/apply',
    requireAuth,
    requireRole('PATIENT'),
    validate(applyAsDoctorSchema),
    asyncHandler(ctrl.apply)
  )

  router.patch(
    '/me',
    requireAuth,
    requireRole('DOCTOR'),
    validate(updateDoctorProfileSchema),
    asyncHandler(ctrl.updateProfile)
  )

  router.post(
    '/:doctorId/verify',
    requireAuth,
    requireRole('ADMIN'),
    validate(doctorIdParamSchema, 'params'),
    asyncHandler(ctrl.verify)
  )

  router.post(
    '/:doctorId/reject',
    requireAuth,
    requireRole('ADMIN'),
    validate(doctorIdParamSchema, 'params'),
    validate(rejectDoctorSchema),
    asyncHandler(ctrl.reject)
  )

  return router
}
