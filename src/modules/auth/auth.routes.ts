import { Router } from 'express'
import { asyncHandler } from '../../core/http'
import { authenticate } from '../../middleware/authenticate'
import { policies, rateLimit } from '../../middleware/rateLimit'
import { validate } from '../../middleware/validate'
import type { Container } from '../../container'
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

/**
 * Middleware order is a security property, not a style choice:
 *
 *   rateLimit → validate → authenticate → handler
 *
 * Rate limiting comes first so an attacker cannot make us do argon2 work (or even
 * schema parsing) before we decide to reject them. Validation comes before
 * authentication on unauthenticated routes so a malformed body is a cheap 400.
 *
 * On login there are *two* limiters: one per source IP and one per target email. The
 * first stops a single host hammering many accounts; the second stops a botnet
 * hammering one account from many hosts. Neither alone covers credential stuffing.
 */
export function createAuthRouter(c: Container): Router {
  const router = Router()
  const { authController: ctrl, tokens, db } = c
  const requireAuth = authenticate(tokens, db)

  // --- Public ---------------------------------------------------------------

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

  // Unauthenticated: a client whose access token already expired must still be able
  // to invalidate its refresh token.
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

  // --- Authenticated --------------------------------------------------------

  router.get('/me', requireAuth, asyncHandler(ctrl.me))

  router.post('/logout-all', requireAuth, asyncHandler(ctrl.logoutAll))

  router.post(
    '/password/change',
    requireAuth,
    rateLimit(db, policies.passwordReset),
    validate(changePasswordSchema),
    asyncHandler(ctrl.changePassword)
  )

  // --- MFA management -------------------------------------------------------

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
