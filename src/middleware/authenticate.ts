import type { NextFunction, Request, RequestHandler, Response } from 'express'
import { ForbiddenError, UnauthenticatedError } from '../core/errors'
import type { Db } from '../db/prisma'
import type { TokenService } from '../modules/auth/token.service'
import { setContext } from '../observability/requestContext'

/**
 * Verifies the bearer token and populates `req.auth`.
 *
 * Beyond the signature check there is one database read per request, and it is not
 * optional: a stateless JWT cannot know that the user was suspended, had their role
 * changed, or hit "sign out everywhere" ten seconds ago. Checking `tokensValidFrom`
 * and `status` against the live row bounds that staleness to zero, at the cost of an
 * indexed primary-key lookup (sub-millisecond, and the row is almost always in
 * shared_buffers).
 *
 * The alternative — a denylist of revoked jti values — trades this read for a write
 * on every logout plus its own storage. For a healthcare system where an
 * access-control mistake is a reportable breach, the read is the right side of the trade.
 */
export function authenticate(tokens: TokenService, db: Db): RequestHandler {
  return async (req: Request, _res: Response, next: NextFunction) => {
    try {
      const token = extractBearerToken(req)
      if (!token) throw new UnauthenticatedError('Missing bearer token')

      const claims = tokens.verifyAccessToken(token)

      const user = await db.user.findUnique({
        where: { id: claims.sub },
        select: { id: true, role: true, status: true, tokensValidFrom: true, deletedAt: true, mfaEnabled: true },
      })

      if (!user || user.deletedAt) throw new UnauthenticatedError('Account no longer exists', 'TOKEN_INVALID')

      if (user.status === 'SUSPENDED' || user.status === 'DEACTIVATED') {
        throw new ForbiddenError('This account is not active', 'ACCOUNT_INACTIVE')
      }

      // `iat` is whole seconds; `tokensValidFrom` has millisecond precision. Compare
      // in seconds (rounding the cutoff up) or a token minted in the same second as a
      // "logout everywhere" would survive it.
      const validFromSeconds = Math.ceil(user.tokensValidFrom.getTime() / 1000)
      if (!claims.iat || claims.iat < validFromSeconds) {
        throw new UnauthenticatedError('Session has been revoked', 'TOKEN_INVALID')
      }

      // The role in the token can be stale (an admin demoted the user mid-session).
      // The database row is authoritative.
      if (user.role !== claims.role) {
        throw new UnauthenticatedError('Session is no longer valid for this account', 'TOKEN_INVALID')
      }

      req.auth = {
        userId: user.id,
        role: user.role,
        sessionId: claims.sid,
        mfaSatisfied: claims.mfa === true,
        issuedAt: claims.iat,
      }

      setContext({ userId: user.id, userRole: user.role })
      next()
    } catch (err) {
      next(err)
    }
  }
}

/**
 * Populates `req.auth` when a valid token is present, and does nothing when it is
 * absent. For endpoints that are public but richer when authenticated (doctor search
 * showing "you have an upcoming consultation with this doctor").
 *
 * A *malformed* token still fails: silently ignoring it would mask client bugs and
 * let an expired session look like an anonymous one.
 */
export function optionalAuthenticate(tokens: TokenService, db: Db): RequestHandler {
  const required = authenticate(tokens, db)
  return (req, res, next) => {
    if (!extractBearerToken(req)) return next()
    return required(req, res, next)
  }
}

function extractBearerToken(req: Request): string | null {
  const header = req.get('authorization')
  if (!header) return null

  // Exactly "Bearer <token>". Case-insensitive scheme per RFC 7235.
  const match = /^Bearer\s+(\S+)$/i.exec(header.trim())
  return match?.[1] ?? null
}
