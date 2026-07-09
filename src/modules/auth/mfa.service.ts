import { env } from '../../config/env'
import { type Keyring, fieldAad } from '../../core/crypto/keyring'
import { hashPassword, verifyPassword } from '../../core/crypto/password'
import { buildOtpAuthUrl, generateRecoveryCodes, generateSecret, verifyToken } from '../../core/crypto/totp'
import { ConflictError, ForbiddenError, NotFoundError, UnauthenticatedError } from '../../core/errors'
import type { Db } from '../../db/prisma'
import { createLogger } from '../../observability/logger'
import { AuditAction, type AuditService } from '../audit/audit.service'

const log = createLogger('mfa')

export interface EnrolmentChallenge {
  secret: string
  otpauthUrl: string
}

export interface EnrolmentResult {
  recoveryCodes: string[]
}

/**
 * TOTP-based MFA.
 *
 * Enrolment is two-phase on purpose. `beginEnrolment` stores an encrypted secret but
 * leaves `mfaEnabled = false`; only `completeEnrolment`, which requires a code the
 * user's authenticator actually produced, flips the flag. Without that proof step a
 * user can lock themselves out by scanning a QR that never made it into their app.
 */
export class MfaService {
  constructor(
    private readonly db: Db,
    private readonly keyring: Keyring,
    private readonly audit: AuditService
  ) {}

  async beginEnrolment(userId: string): Promise<EnrolmentChallenge> {
    const user = await this.db.user.findUnique({
      where: { id: userId },
      select: { id: true, email: true, mfaEnabled: true },
    })
    if (!user) throw new NotFoundError('User', userId)
    if (user.mfaEnabled) throw new ConflictError('Multi-factor authentication is already enabled')

    const secret = generateSecret()

    // Overwrites any previous unfinished enrolment — restarting is always allowed.
    await this.db.user.update({
      where: { id: userId },
      data: {
        mfaSecretEnc: this.keyring.encryptField(secret, fieldAad('user', userId, 'mfa_secret')),
        mfaEnabled: false,
        mfaLastUsedStep: null,
      },
    })

    await this.audit.recordDetached({
      action: AuditAction.MFA_ENROLL_STARTED,
      resourceType: 'user',
      resourceId: userId,
    })

    return {
      secret,
      otpauthUrl: buildOtpAuthUrl({ secret, account: user.email, issuer: env.MFA_ISSUER }),
    }
  }

  /**
   * Prove possession of the secret, then enable MFA and hand back recovery codes.
   * The codes are returned exactly once; we store only their argon2 hashes.
   */
  async completeEnrolment(userId: string, totpCode: string): Promise<EnrolmentResult> {
    const user = await this.db.user.findUnique({
      where: { id: userId },
      select: { id: true, mfaEnabled: true, mfaSecretEnc: true },
    })
    if (!user) throw new NotFoundError('User', userId)
    if (user.mfaEnabled) throw new ConflictError('Multi-factor authentication is already enabled')
    if (!user.mfaSecretEnc) throw new ConflictError('Start MFA enrolment before confirming it')

    const secret = this.keyring.decryptField(user.mfaSecretEnc, fieldAad('user', userId, 'mfa_secret'))
    const result = verifyToken(totpCode, secret, { window: env.MFA_WINDOW })

    if (!result.valid) {
      await this.audit.recordDetached({
        action: AuditAction.MFA_CHALLENGE_FAILED,
        resourceType: 'user',
        resourceId: userId,
        outcome: 'FAILURE',
        metadata: { phase: 'enrolment' },
      })
      throw new UnauthenticatedError('Invalid authenticator code', 'INVALID_MFA_CODE')
    }

    const codes = generateRecoveryCodes()
    const codeHashes = await Promise.all(codes.map((c) => hashPassword(c)))

    await this.db.$transaction(async (tx) => {
      await tx.user.update({
        where: { id: userId },
        data: { mfaEnabled: true, mfaEnrolledAt: new Date(), mfaLastUsedStep: BigInt(result.step!) },
      })
      // Replacing codes wholesale keeps "regenerate codes" and "enrol" on one path.
      await tx.mfaRecoveryCode.deleteMany({ where: { userId } })
      await tx.mfaRecoveryCode.createMany({
        data: codeHashes.map((codeHash) => ({ userId, codeHash })),
      })
      await this.audit.record(tx, {
        action: AuditAction.MFA_ENABLED,
        resourceType: 'user',
        resourceId: userId,
      })
    })

    return { recoveryCodes: codes }
  }

  /**
   * Verify a TOTP code during login.
   *
   * `mfaLastUsedStep` is advanced on every success, and `verifyToken` refuses any
   * step at or below it. Without that, a code shoulder-surfed (or captured by a
   * phishing proxy) stays usable for the remainder of its 30-second window plus the
   * clock-skew tolerance on either side.
   */
  async verifyChallenge(userId: string, code: string): Promise<boolean> {
    const user = await this.db.user.findUnique({
      where: { id: userId },
      select: { id: true, mfaEnabled: true, mfaSecretEnc: true, mfaLastUsedStep: true },
    })
    if (!user?.mfaEnabled || !user.mfaSecretEnc) {
      throw new ConflictError('Multi-factor authentication is not enabled for this account')
    }

    const secret = this.keyring.decryptField(user.mfaSecretEnc, fieldAad('user', userId, 'mfa_secret'))
    const result = verifyToken(code, secret, {
      window: env.MFA_WINDOW,
      lastUsedStep: user.mfaLastUsedStep === null ? null : Number(user.mfaLastUsedStep),
    })

    if (!result.valid) return false

    // Guarded write: if a concurrent login already advanced the step past ours, that
    // request consumed this code and we must reject rather than accept the replay.
    const { count } = await this.db.user.updateMany({
      where: {
        id: userId,
        OR: [{ mfaLastUsedStep: null }, { mfaLastUsedStep: { lt: BigInt(result.step!) } }],
      },
      data: { mfaLastUsedStep: BigInt(result.step!) },
    })

    if (count !== 1) {
      log.warn({ userId, step: result.step }, 'TOTP code replayed concurrently — rejecting')
      return false
    }

    return true
  }

  /**
   * Redeem a single-use recovery code.
   *
   * The codes are argon2 hashes, so we cannot look one up by value — we must verify
   * against each unused hash in turn. With ten codes that is bounded and fine; it is
   * also why recovery-code endpoints sit behind a strict rate limit.
   */
  async verifyRecoveryCode(userId: string, code: string): Promise<boolean> {
    const normalised = code.trim().toUpperCase()

    const candidates = await this.db.mfaRecoveryCode.findMany({
      where: { userId, usedAt: null },
      select: { id: true, codeHash: true },
    })

    for (const candidate of candidates) {
      if (!(await verifyPassword(normalised, candidate.codeHash))) continue

      // `usedAt: null` in the filter makes redemption single-use under concurrency.
      const { count } = await this.db.mfaRecoveryCode.updateMany({
        where: { id: candidate.id, usedAt: null },
        data: { usedAt: new Date() },
      })
      if (count !== 1) return false

      await this.audit.recordDetached({
        action: AuditAction.MFA_RECOVERY_CODE_USED,
        resourceType: 'user',
        resourceId: userId,
        metadata: { remaining: candidates.length - 1 },
      })
      return true
    }

    return false
  }

  /**
   * Disabling MFA is a privilege escalation in reverse: it lowers the account's
   * security. Re-authenticating with the password proves the session belongs to the
   * human, not to someone who walked up to an unlocked laptop.
   */
  async disable(userId: string, currentPassword: string): Promise<void> {
    const user = await this.db.user.findUnique({
      where: { id: userId },
      select: { id: true, passwordHash: true, mfaEnabled: true },
    })
    if (!user) throw new NotFoundError('User', userId)
    if (!user.mfaEnabled) throw new ConflictError('Multi-factor authentication is not enabled')
    if (!user.passwordHash || !(await verifyPassword(currentPassword, user.passwordHash))) {
      throw new ForbiddenError('Current password is incorrect')
    }

    await this.db.$transaction(async (tx) => {
      await tx.user.update({
        where: { id: userId },
        data: { mfaEnabled: false, mfaSecretEnc: null, mfaEnrolledAt: null, mfaLastUsedStep: null },
      })
      await tx.mfaRecoveryCode.deleteMany({ where: { userId } })
      await this.audit.record(tx, {
        action: AuditAction.MFA_DISABLED,
        resourceType: 'user',
        resourceId: userId,
      })
    })
  }

  async countUnusedRecoveryCodes(userId: string): Promise<number> {
    return this.db.mfaRecoveryCode.count({ where: { userId, usedAt: null } })
  }
}
