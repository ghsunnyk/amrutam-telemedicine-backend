import type { NextFunction, Request, RequestHandler, Response } from 'express'
import { ForbiddenError, UnauthenticatedError } from '../core/errors'
import type { Db } from '../db/prisma'
import type { TokenService } from '../modules/auth/token.service'
import { setContext } from '../observability/requestContext'

export function authenticate(tokens: TokenService, db: Db): RequestHandler {
  return async (req: Request, _res: Response, next: NextFunction) => {
    try {
      const token = extractBearerToken(req)
      if (!token) throw new UnauthenticatedError('Missing bearer token')

      const claims = tokens.verifyAccessToken(token)

      const user = await db.user.findUnique({
        where: { id: claims.sub },
        select: {
          id: true,
          role: true,
          status: true,
          tokensValidFrom: true,
          deletedAt: true,
          mfaEnabled: true,
        },
      })

      if (!user || user.deletedAt)
        throw new UnauthenticatedError('Account no longer exists', 'TOKEN_INVALID')

      if (user.status === 'SUSPENDED' || user.status === 'DEACTIVATED') {
        throw new ForbiddenError('This account is not active', 'ACCOUNT_INACTIVE')
      }

      const validFromSeconds = Math.ceil(user.tokensValidFrom.getTime() / 1000)
      if (!claims.iat || claims.iat < validFromSeconds) {
        throw new UnauthenticatedError('Session has been revoked', 'TOKEN_INVALID')
      }

      if (user.role !== claims.role) {
        throw new UnauthenticatedError(
          'Session is no longer valid for this account',
          'TOKEN_INVALID'
        )
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

  const match = /^Bearer\s+(\S+)$/i.exec(header.trim())
  return match?.[1] ?? null
}
