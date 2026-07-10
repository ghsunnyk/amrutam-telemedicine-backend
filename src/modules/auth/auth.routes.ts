import { Router } from 'express'
import type { Container } from '../../container'
import { asyncHandler } from '../../core/http'
import { authenticate } from '../../middleware/authenticate'
import { policies, rateLimit } from '../../middleware/rateLimit'
import { validate } from '../../middleware/validate'
import {
  changePasswordSchema,
  disableMfaSchema,
  enrolMfaSchema,
  loginSchema,
  logoutSchema,
  mfaChallengeSchema,
  refreshSchema,
  registerSchema,
  requestPasswordResetSchema,
  resetPasswordSchema,
  verifyEmailSchema,
} from './auth.schemas'

export function createAuthRouter(c: Container): Router {
  const router = Router()
  const { authController: ctrl, tokens, db } = c
  const requireAuth = authenticate(tokens, db)

  router.post(
    '/register',
    rateLimit(db, policies.register),
    validate(registerSchema),
    asyncHandler(ctrl.register)
  )

  router.post(
    '/login',
    rateLimit(db, policies.login),
    validate(loginSchema),
    rateLimit(db, policies.loginPerAccount), // after validate: needs a parsed email
    asyncHandler(ctrl.login)
  )

  router.post(
    '/mfa/challenge',
    rateLimit(db, policies.mfaChallenge),
    validate(mfaChallengeSchema),
    asyncHandler(ctrl.mfaChallenge)
  )

  router.post(
    '/refresh',
    rateLimit(db, policies.refresh),
    validate(refreshSchema),
    asyncHandler(ctrl.refresh)
  )

  router.post('/logout', validate(logoutSchema), asyncHandler(ctrl.logout))

  router.post(
    '/password/reset-request',
    rateLimit(db, policies.passwordReset),
    validate(requestPasswordResetSchema),
    asyncHandler(ctrl.requestPasswordReset)
  )

  router.post(
    '/password/reset',
    rateLimit(db, policies.passwordReset),
    validate(resetPasswordSchema),
    asyncHandler(ctrl.resetPassword)
  )

  router.post(
    '/email/verify',
    rateLimit(db, policies.passwordReset),
    validate(verifyEmailSchema),
    asyncHandler(ctrl.verifyEmail)
  )

  router.get('/me', requireAuth, asyncHandler(ctrl.me))

  router.post('/logout-all', requireAuth, asyncHandler(ctrl.logoutAll))

  router.post(
    '/password/change',
    requireAuth,
    rateLimit(db, policies.passwordReset),
    validate(changePasswordSchema),
    asyncHandler(ctrl.changePassword)
  )

  router.get('/mfa', requireAuth, asyncHandler(ctrl.mfaStatus))

  router.post(
    '/mfa/enrol',
    requireAuth,
    rateLimit(db, policies.mfaChallenge),
    asyncHandler(ctrl.beginMfaEnrolment)
  )

  router.post(
    '/mfa/enrol/confirm',
    requireAuth,
    rateLimit(db, policies.mfaChallenge),
    validate(enrolMfaSchema),
    asyncHandler(ctrl.enrolMfa)
  )

  router.post(
    '/mfa/disable',
    requireAuth,
    rateLimit(db, policies.mfaChallenge),
    validate(disableMfaSchema),
    asyncHandler(ctrl.disableMfa)
  )

  return router
}
