import type { Db, Tx } from '../../db/prisma'
import type { Role } from '../../generated/prisma/enums'
import { createLogger } from '../../observability/logger'
import { auditLogWritesTotal } from '../../observability/metrics'
import { getContext } from '../../observability/requestContext'

const log = createLogger('audit')

export type AuditOutcome = 'SUCCESS' | 'FAILURE' | 'DENIED'

export interface AuditEntry {
  action: string
  resourceType: string
  resourceId?: string | null
  actorId?: string | null
  actorRole?: Role | null
  outcome?: AuditOutcome
  metadata?: Record<string, unknown>
}

const FORBIDDEN_KEYS = new Set([
  'password',
  'passwordhash',
  'newpassword',
  'currentpassword',
  'token',
  'accesstoken',
  'refreshtoken',
  'mfatoken',
  'totpcode',
  'mfasecret',
  'secret',
  'recoverycodes',
  'authorization',
  'cookie',
  // PHI — the audit trail records *that* a diagnosis was written, never its content.
  'diagnosis',
  'symptoms',
  'chiefcomplaint',
  'doctornotes',
  'notes',
  'items',
  'advice',
  'phone',
  'dateofbirth',
  'address',
])

const MAX_STRING_LENGTH = 512
const MAX_DEPTH = 4

export class AuditService {
  constructor(private readonly db: Db) {}

  async record(tx: Tx, entry: AuditEntry): Promise<void> {
    await tx.auditLog.create({ data: this.buildRow(entry) })
    auditLogWritesTotal.inc({ outcome: 'written' })
  }

  async recordDetached(entry: AuditEntry): Promise<void> {
    try {
      await this.db.auditLog.create({ data: this.buildRow(entry) })
      auditLogWritesTotal.inc({ outcome: 'written' })
    } catch (err) {
      auditLogWritesTotal.inc({ outcome: 'failed' })
      // Log at error: a silent audit gap is a compliance incident.
      log.error({ err, action: entry.action }, 'Failed to write audit log entry')
    }
  }

  private buildRow(entry: AuditEntry) {
    const ctx = getContext()

    return {
      action: entry.action,
      resourceType: entry.resourceType,
      resourceId: entry.resourceId ?? null,
      // Fall back to the ambient authenticated user so callers rarely pass it.
      actorId: entry.actorId !== undefined ? entry.actorId : (ctx?.userId ?? null),
      actorRole: entry.actorRole ?? (ctx?.userRole as Role | undefined) ?? null,
      outcome: entry.outcome ?? 'SUCCESS',
      metadata: entry.metadata ? (redact(entry.metadata) as object) : undefined,
      ipHash: ctx?.ip ?? null,
      userAgent: ctx?.userAgent?.slice(0, MAX_STRING_LENGTH) ?? null,
      requestId: ctx?.requestId ?? null,
      traceId: ctx?.traceId ?? null,
    }
  }
}

export function redact(value: unknown, depth = 0): unknown {
  if (depth > MAX_DEPTH) return '[TRUNCATED_DEPTH]'

  if (value === null || value === undefined) return value

  if (typeof value === 'string') {
    return value.length > MAX_STRING_LENGTH
      ? `${value.slice(0, MAX_STRING_LENGTH)}…[TRUNCATED]`
      : value
  }

  if (typeof value === 'number' || typeof value === 'boolean') return value
  if (value instanceof Date) return value.toISOString()
  if (Buffer.isBuffer(value)) return '[BINARY]'

  if (Array.isArray(value)) {
    const capped = value.slice(0, 50).map(v => redact(v, depth + 1))
    return value.length > 50 ? [...capped, `…${value.length - 50} more`] : capped
  }

  if (typeof value === 'object') {
    const out: Record<string, unknown> = {}
    for (const [key, val] of Object.entries(value)) {
      if (FORBIDDEN_KEYS.has(key.toLowerCase())) {
        out[key] = '[REDACTED]'
        continue
      }
      out[key] = redact(val, depth + 1)
    }
    return out
  }

  if (typeof value === 'bigint') return value.toString()
  return `[${typeof value}]`
}

export const AuditAction = {
  // auth
  REGISTER: 'auth.register',
  LOGIN_SUCCESS: 'auth.login.success',
  LOGIN_FAILED: 'auth.login.failed',
  LOGIN_LOCKED: 'auth.login.locked',
  LOGOUT: 'auth.logout',
  LOGOUT_ALL: 'auth.logout_all',
  TOKEN_REFRESHED: 'auth.token.refreshed',
  TOKEN_REUSE_DETECTED: 'auth.token.reuse_detected',
  PASSWORD_CHANGED: 'auth.password.changed',
  PASSWORD_RESET_REQUESTED: 'auth.password.reset_requested',
  PASSWORD_RESET_COMPLETED: 'auth.password.reset_completed',
  EMAIL_VERIFIED: 'auth.email.verified',
  MFA_ENROLL_STARTED: 'auth.mfa.enroll_started',
  MFA_ENABLED: 'auth.mfa.enabled',
  MFA_DISABLED: 'auth.mfa.disabled',
  MFA_CHALLENGE_FAILED: 'auth.mfa.challenge_failed',
  MFA_RECOVERY_CODE_USED: 'auth.mfa.recovery_code_used',

  // authorisation
  ACCESS_DENIED: 'authz.access_denied',

  // doctors
  DOCTOR_PROFILE_UPDATED: 'doctor.profile.updated',
  DOCTOR_VERIFIED: 'doctor.verified',
  DOCTOR_REJECTED: 'doctor.rejected',
  AVAILABILITY_RULE_CREATED: 'doctor.availability.rule_created',
  AVAILABILITY_RULE_DELETED: 'doctor.availability.rule_deleted',

  // booking
  SLOT_HELD: 'booking.slot.held',
  SLOT_HOLD_RELEASED: 'booking.slot.hold_released',
  SLOT_HOLD_EXPIRED: 'booking.slot.hold_expired',
  CONSULTATION_BOOKED: 'consultation.booked',
  CONSULTATION_CONFIRMED: 'consultation.confirmed',
  CONSULTATION_STARTED: 'consultation.started',
  CONSULTATION_COMPLETED: 'consultation.completed',
  CONSULTATION_CANCELLED: 'consultation.cancelled',
  CONSULTATION_RESCHEDULED: 'consultation.rescheduled',
  CONSULTATION_EXPIRED: 'consultation.expired',

  // clinical — the *fact* of access is auditable; the content never is
  CONSULTATION_NOTES_VIEWED: 'consultation.notes.viewed',
  PRESCRIPTION_CREATED: 'prescription.created',
  PRESCRIPTION_ISSUED: 'prescription.issued',
  PRESCRIPTION_VIEWED: 'prescription.viewed',
  PRESCRIPTION_REVOKED: 'prescription.revoked',

  // payments
  PAYMENT_INITIATED: 'payment.initiated',
  PAYMENT_CAPTURED: 'payment.captured',
  PAYMENT_FAILED: 'payment.failed',
  PAYMENT_REFUNDED: 'payment.refunded',

  // platform
  ENCRYPTION_KEY_ROTATED: 'platform.encryption_key.rotated',
  RATE_LIMIT_EXCEEDED: 'platform.rate_limit.exceeded',
} as const

export type AuditActionName = (typeof AuditAction)[keyof typeof AuditAction]
