import type { Role } from '../generated/prisma/enums'

/**
 * `req.auth` is populated *only* by the `authenticate` middleware, after the JWT
 * signature, expiry, issuer, audience and `tokens_valid_from` have all been checked.
 * Nothing else may write it. Authorisation decisions read from here and nowhere else.
 */
export interface AuthContext {
  userId: string
  role: Role
  sessionId: string
  /** True once the session has cleared MFA (or the user has no MFA enrolled). */
  mfaSatisfied: boolean
  issuedAt: number
}

declare global {
  namespace Express {
    interface Request {
      auth?: AuthContext
      requestId: string
      /** Set by the idempotency middleware so the controller can record its response. */
      idempotency?: { key: string; scope: string }
    }
  }
}

export {}
