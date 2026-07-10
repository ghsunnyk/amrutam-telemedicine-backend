import { env } from '../../config/env'
import { type Keyring, fieldAad } from '../../core/crypto/keyring'
import { hashPassword, verifyPassword } from '../../core/crypto/password'
import {
  buildOtpAuthUrl,
  generateRecoveryCodes,
  generateSecret,
  verifyToken,
} from '../../core/crypto/totp'
import {
  ConflictError,
  ForbiddenError,
  NotFoundError,
  UnauthenticatedError,
} from '../../core/errors'
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

  async completeEnrolment(userId: string, totpCode: string): Promise<EnrolmentResult> {
    const user = await this.db.user.findUnique({
      where: { id: userId },
      select: { id: true, mfaEnabled: true, mfaSecretEnc: true },
    })
    if (!user) throw new NotFoundError('User', userId)
    if (user.mfaEnabled) throw new ConflictError('Multi-factor authentication is already enabled')
    if (!user.mfaSecretEnc) throw new ConflictError('Start MFA enrolment before confirming it')

    const secret = this.keyring.decryptField(
      user.mfaSecretEnc,
      fieldAad('user', userId, 'mfa_secret')
    )
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
    const codeHashes = await Promise.all(codes.map(c => hashPassword(c)))

    await this.db.$transaction(async tx => {
      await tx.user.update({
        where: { id: userId },
        data: {
          mfaEnabled: true,
          mfaEnrolledAt: new Date(),
          mfaLastUsedStep: BigInt(result.step!),
        },
      })
      await tx.mfaRecoveryCode.deleteMany({ where: { userId } })
      await tx.mfaRecoveryCode.createMany({
        data: codeHashes.map(codeHash => ({ userId, codeHash })),
      })
      await this.audit.record(tx, {
        action: AuditAction.MFA_ENABLED,
        resourceType: 'user',
        resourceId: userId,
      })
    })

    return { recoveryCodes: codes }
  }

  async verifyChallenge(userId: string, code: string): Promise<boolean> {
    const user = await this.db.user.findUnique({
      where: { id: userId },
      select: { id: true, mfaEnabled: true, mfaSecretEnc: true, mfaLastUsedStep: true },
    })
    if (!user?.mfaEnabled || !user.mfaSecretEnc) {
      throw new ConflictError('Multi-factor authentication is not enabled for this account')
    }

    const secret = this.keyring.decryptField(
      user.mfaSecretEnc,
      fieldAad('user', userId, 'mfa_secret')
    )
    const result = verifyToken(code, secret, {
      window: env.MFA_WINDOW,
      lastUsedStep: user.mfaLastUsedStep === null ? null : Number(user.mfaLastUsedStep),
    })

    if (!result.valid) return false

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

  async verifyRecoveryCode(userId: string, code: string): Promise<boolean> {
    const normalised = code.trim().toUpperCase()

    const candidates = await this.db.mfaRecoveryCode.findMany({
      where: { userId, usedAt: null },
      select: { id: true, codeHash: true },
    })

    for (const candidate of candidates) {
      if (!(await verifyPassword(normalised, candidate.codeHash))) continue

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

    await this.db.$transaction(async tx => {
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
