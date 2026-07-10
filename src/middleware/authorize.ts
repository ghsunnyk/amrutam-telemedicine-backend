import type { NextFunction, Request, RequestHandler, Response } from 'express'
import { ForbiddenError, NotFoundError, UnauthenticatedError } from '../core/errors'
import type { Db } from '../db/prisma'
import type { Role } from '../generated/prisma/enums'
import type { AuditService } from '../modules/audit/audit.service'
import { AuditAction } from '../modules/audit/audit.service'

export function requireRole(...allowed: Role[]): RequestHandler {
  return (req: Request, _res: Response, next: NextFunction) => {
    if (!req.auth) return next(new UnauthenticatedError())

    if (!allowed.includes(req.auth.role)) {
      return next(new ForbiddenError(`This action requires one of: ${allowed.join(', ')}`))
    }

    next()
  }
}

export function requireMfa(): RequestHandler {
  return (req: Request, _res: Response, next: NextFunction) => {
    if (!req.auth) return next(new UnauthenticatedError())

    if (!req.auth.mfaSatisfied) {
      return next(
        new ForbiddenError('This action requires multi-factor authentication', 'MFA_REQUIRED')
      )
    }

    next()
  }
}

export function requireVerifiedEmail(db: Db): RequestHandler {
  return async (req: Request, _res: Response, next: NextFunction) => {
    if (!req.auth) return next(new UnauthenticatedError())

    try {
      const user = await db.user.findUnique({
        where: { id: req.auth.userId },
        select: { emailVerifiedAt: true },
      })

      if (!user?.emailVerifiedAt) {
        return next(
          new ForbiddenError('Verify your email address to continue', 'EMAIL_NOT_VERIFIED')
        )
      }
      next()
    } catch (err) {
      next(err)
    }
  }
}

export function auditAccessDenied(audit: AuditService, req: Request, reason: string): void {
  void audit.recordDetached({
    action: AuditAction.ACCESS_DENIED,
    resourceType: 'endpoint',
    resourceId: `${req.method} ${req.route?.path ?? req.path}`,
    outcome: 'DENIED',
    metadata: { reason },
  })
}

export function assertOwnership(
  auth: { userId: string; role: Role },
  ownerId: string,
  resource = 'resource'
): void {
  if (auth.role === 'ADMIN') return
  if (auth.userId !== ownerId) {
    throw new NotFoundError(resourceLabel(resource))
  }
}

const resourceLabel = (resource: string): string =>
  resource.charAt(0).toUpperCase() + resource.slice(1)
