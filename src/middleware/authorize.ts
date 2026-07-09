import type { NextFunction, Request, RequestHandler, Response } from 'express'
import { ForbiddenError, NotFoundError, UnauthenticatedError } from '../core/errors'
import type { Db } from '../db/prisma'
import type { Role } from '../generated/prisma/enums'
import type { AuditService } from '../modules/audit/audit.service'
import { AuditAction } from '../modules/audit/audit.service'

/**
 * Role-based access control.
 *
 * Two layers, and both are needed:
 *
 *  1. `requireRole` — coarse, declarative, at the route. "Only doctors may write a
 *     prescription." Cheap, and visible when reading the router.
 *
 *  2. Ownership checks in the service — fine-grained, per-row. "Only the doctor who
 *     ran *this* consultation may write *its* prescription." No middleware can do
 *     this without loading the row, so it belongs where the row is loaded.
 *
 * Skipping (2) because (1) passed is the IDOR bug that turns up in every
 * healthcare pentest report. See `docs/security.md` §Broken Object Level Authorisation.
 */
export function requireRole(...allowed: Role[]): RequestHandler {
  return (req: Request, _res: Response, next: NextFunction) => {
    if (!req.auth) return next(new UnauthenticatedError())

    if (!allowed.includes(req.auth.role)) {
      return next(new ForbiddenError(`This action requires one of: ${allowed.join(', ')}`))
    }

    next()
  }
}

/**
 * Demand that the current session actually completed an MFA challenge.
 *
 * Gate the operations where a stolen access token does the most damage: issuing
 * prescriptions, admin actions, changing payout details. A user with MFA enrolled
 * always satisfies this; a user without it never will, which is why MFA is mandatory
 * for DOCTOR and ADMIN at registration.
 */
export function requireMfa(): RequestHandler {
  return (req: Request, _res: Response, next: NextFunction) => {
    if (!req.auth) return next(new UnauthenticatedError())

    if (!req.auth.mfaSatisfied) {
      return next(new ForbiddenError('This action requires multi-factor authentication', 'MFA_REQUIRED'))
    }

    next()
  }
}

/** Some routes must be unavailable until the user proves control of their mailbox. */
export function requireVerifiedEmail(db: Db): RequestHandler {
  return async (req: Request, _res: Response, next: NextFunction) => {
    if (!req.auth) return next(new UnauthenticatedError())

    try {
      const user = await db.user.findUnique({
        where: { id: req.auth.userId },
        select: { emailVerifiedAt: true },
      })

      if (!user?.emailVerifiedAt) {
        return next(new ForbiddenError('Verify your email address to continue', 'EMAIL_NOT_VERIFIED'))
      }
      next()
    } catch (err) {
      next(err)
    }
  }
}

/**
 * Records every 403 to the audit trail. Mounted once in the error handler rather than
 * per-route, so a denial can never be missed by forgetting to wire it up.
 *
 * Denials are the highest-signal security event we collect: a legitimate client
 * essentially never triggers one, so a burst is either a broken deploy or an attacker
 * probing object ids.
 */
export function auditAccessDenied(audit: AuditService, req: Request, reason: string): void {
  void audit.recordDetached({
    action: AuditAction.ACCESS_DENIED,
    resourceType: 'endpoint',
    resourceId: `${req.method} ${req.route?.path ?? req.path}`,
    outcome: 'DENIED',
    metadata: { reason },
  })
}

/**
 * Ownership assertion for service layers.
 *
 * `ADMIN` bypasses, which is a deliberate and *audited* superpower — every admin read
 * of a patient record lands in `audit_logs` via the calling service.
 *
 * Raises 404 rather than 403 on purpose. A 403 confirms "this consultation exists,
 * it just isn't yours", which is enough to enumerate the id space and learn who
 * consulted whom. Callers that are already scoped by an owning id (e.g. "list *my*
 * consultations") don't need this — their query has no rows to leak.
 */
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

const resourceLabel = (resource: string): string => resource.charAt(0).toUpperCase() + resource.slice(1)
