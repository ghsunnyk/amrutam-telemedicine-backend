import { createHash, randomBytes } from 'node:crypto'
import { env } from '../../config/env'
import { blindIndex } from '../../core/crypto/encryption'
import { type Keyring, fieldAad } from '../../core/crypto/keyring'
import { fakeVerify, hashPassword, needsRehash, verifyPassword } from '../../core/crypto/password'
import {
  AccountLockedError,
  ConflictError,
  ForbiddenError,
  InvalidCredentialsError,
  MfaRequiredError,
  UnauthenticatedError,
} from '../../core/errors'
import type { Db } from '../../db/prisma'
import type { Role, User } from '../../generated/prisma/client'
import { createLogger } from '../../observability/logger'
import { authAttemptsTotal } from '../../observability/metrics'
import { AuditAction, type AuditService } from '../audit/audit.service'
import type { MfaService } from './mfa.service'
import type {
  ChangePasswordInput,
  LoginInput,
  MfaChallengeInput,
  RegisterInput,
} from './auth.schemas'
import { type TokenService, type TokenPair } from './token.service'

const log = createLogger('auth')

export interface RequestMeta {
  ip?: string
  userAgent?: string
}

export interface AuthenticatedUser {
  id: string
  email: string
  role: Role
  mfaEnabled: boolean
  emailVerified: boolean
}

export interface LoginResult {
  tokens: TokenPair
  user: AuthenticatedUser
}

const VERIFICATION_TOKEN_TTL_MS = 24 * 60 * 60 * 1000
const PASSWORD_RESET_TTL_MS = 30 * 60 * 1000

/** Verification/reset tokens are high-entropy randoms, so SHA-256 suffices. */
const hashOpaqueToken = (token: string) => createHash('sha256').update(token).digest('hex')

export class AuthService {
  constructor(
    private readonly db: Db,
    private readonly tokens: TokenService,
    private readonly mfa: MfaService,
    private readonly keyring: Keyring,
    private readonly audit: AuditService
  ) {}

  // -------------------------------------------------------------------------
  // Registration
  // -------------------------------------------------------------------------

  /**
   * Always creates a PATIENT. Role is never taken from the request body — see
   * `registerSchema`, which is `.strict()` and has no `role` field.
   *
   * Returns the verification token so the caller can enqueue an email. It is never
   * put in the HTTP response outside development.
   */
  async register(input: RegisterInput): Promise<{ user: AuthenticatedUser; verificationToken: string }> {
    const passwordHash = await hashPassword(input.password)
    const rawToken = randomBytes(32).toString('base64url')

    try {
      const user = await this.db.$transaction(async (tx) => {
        const created = await tx.user.create({
          data: {
            email: input.email,
            passwordHash,
            role: 'PATIENT',
            status: 'PENDING_VERIFICATION',
          },
        })

        await tx.profile.create({
          data: {
            userId: created.id,
            firstName: input.firstName,
            lastName: input.lastName,
            timezone: input.timezone ?? 'Asia/Kolkata',
            ...(input.phone
              ? {
                  phoneHash: blindIndex(input.phone, 'profile.phone'),
                  phoneEnc: this.keyring.encryptField(
                    input.phone,
                    fieldAad('profile', created.id, 'phone')
                  ),
                }
              : {}),
          },
        })

        await tx.verificationToken.create({
          data: {
            userId: created.id,
            purpose: 'EMAIL_VERIFY',
            tokenHash: hashOpaqueToken(rawToken),
            expiresAt: new Date(Date.now() + VERIFICATION_TOKEN_TTL_MS),
          },
        })

        await this.audit.record(tx, {
          action: AuditAction.REGISTER,
          resourceType: 'user',
          resourceId: created.id,
          actorId: created.id,
          actorRole: 'PATIENT',
        })

        return created
      })

      authAttemptsTotal.inc({ event: 'register', outcome: 'success' })
      return { user: toAuthenticatedUser(user), verificationToken: rawToken }
    } catch (err) {
      if (isUniqueViolation(err, 'email')) {
        authAttemptsTotal.inc({ event: 'register', outcome: 'duplicate' })
        // Account enumeration: an attacker learns this email is registered. The
        // alternative — pretending to succeed and emailing "you already have an
        // account" — is what a bank does. For a clinic, the usability cost of a
        // silent no-op outweighs the (already public) fact of registration, so we
        // are explicit, and we rate-limit registration hard instead.
        throw new ConflictError('An account with this email already exists')
      }
      if (isUniqueViolation(err, 'phone_hash')) {
        throw new ConflictError('An account with this phone number already exists')
      }
      throw err
    }
  }

  // -------------------------------------------------------------------------
  // Login
  // -------------------------------------------------------------------------

  /**
   * Password login.
   *
   * Failure modes are deliberately indistinguishable to the caller: unknown email,
   * wrong password and no-password-set all raise the same `InvalidCredentialsError`
   * after the same argon2 cost (see `fakeVerify`). Only a *locked* account reveals
   * more, because the user needs to know to wait.
   */
  async login(input: LoginInput, meta: RequestMeta): Promise<LoginResult | { mfaRequired: true; mfaToken: string }> {
    const user = await this.db.user.findFirst({
      where: { email: input.email, deletedAt: null },
    })

    if (!user || !user.passwordHash) {
      await fakeVerify(input.password) // equalise timing
      await this.recordFailedLogin(input.email, null)
      throw new InvalidCredentialsError()
    }

    if (user.lockedUntil && user.lockedUntil > new Date()) {
      const retryAfter = Math.ceil((user.lockedUntil.getTime() - Date.now()) / 1000)
      await this.audit.recordDetached({
        action: AuditAction.LOGIN_LOCKED,
        resourceType: 'user',
        resourceId: user.id,
        actorId: user.id,
        outcome: 'DENIED',
      })
      throw new AccountLockedError(retryAfter)
    }

    if (!(await verifyPassword(input.password, user.passwordHash))) {
      await this.registerFailedAttempt(user)
      await this.recordFailedLogin(input.email, user.id)
      throw new InvalidCredentialsError()
    }

    this.assertUsableAccount(user)

    // Correct password → the counter resets even if MFA later fails. MFA failures are
    // counted separately; conflating them lets an attacker who knows the password
    // lock out the victim by spamming bad TOTP codes.
    await this.clearFailedAttempts(user)

    // Transparent hash upgrade when the cost parameters have been raised.
    if (needsRehash(user.passwordHash)) {
      const upgraded = await hashPassword(input.password)
      await this.db.user.update({ where: { id: user.id }, data: { passwordHash: upgraded } })
      log.info({ userId: user.id }, 'Password hash upgraded to current argon2 parameters')
    }

    if (user.mfaEnabled) {
      authAttemptsTotal.inc({ event: 'login', outcome: 'mfa_required' })
      throw new MfaRequiredError(this.tokens.signMfaChallengeToken(user.id))
    }

    const tokens = await this.issueSession(user, meta)
    authAttemptsTotal.inc({ event: 'login', outcome: 'success' })

    await this.audit.recordDetached({
      action: AuditAction.LOGIN_SUCCESS,
      resourceType: 'user',
      resourceId: user.id,
      actorId: user.id,
      actorRole: user.role,
      metadata: { mfa: false },
    })

    return { tokens, user: toAuthenticatedUser(user) }
  }

  /** Second leg of login: exchange the MFA challenge token + a code for a session. */
  async completeMfaChallenge(input: MfaChallengeInput, meta: RequestMeta): Promise<LoginResult> {
    const claims = this.tokens.verifyMfaChallengeToken(input.mfaToken)

    const user = await this.db.user.findFirst({ where: { id: claims.sub, deletedAt: null } })
    if (!user) throw new UnauthenticatedError('Invalid MFA challenge', 'TOKEN_INVALID')

    if (user.lockedUntil && user.lockedUntil > new Date()) {
      throw new AccountLockedError(Math.ceil((user.lockedUntil.getTime() - Date.now()) / 1000))
    }
    this.assertUsableAccount(user)

    const usedRecoveryCode = Boolean(input.recoveryCode)
    const ok = usedRecoveryCode
      ? await this.mfa.verifyRecoveryCode(user.id, input.recoveryCode!)
      : await this.mfa.verifyChallenge(user.id, input.totpCode!)

    if (!ok) {
      // MFA failures feed the same lockout counter as password failures. Someone
      // holding a valid password and guessing 6-digit codes has 10^6 tries; five
      // attempts and a 15-minute lock makes that a 3-year exercise.
      await this.registerFailedAttempt(user)
      authAttemptsTotal.inc({ event: 'mfa', outcome: 'failure' })
      await this.audit.recordDetached({
        action: AuditAction.MFA_CHALLENGE_FAILED,
        resourceType: 'user',
        resourceId: user.id,
        actorId: user.id,
        outcome: 'FAILURE',
        metadata: { method: usedRecoveryCode ? 'recovery_code' : 'totp' },
      })
      throw new UnauthenticatedError('Invalid authenticator code', 'INVALID_MFA_CODE')
    }

    await this.clearFailedAttempts(user)

    const tokens = await this.issueSession(user, meta, { mfaSatisfied: true })
    authAttemptsTotal.inc({ event: 'mfa', outcome: 'success' })

    await this.audit.recordDetached({
      action: AuditAction.LOGIN_SUCCESS,
      resourceType: 'user',
      resourceId: user.id,
      actorId: user.id,
      actorRole: user.role,
      metadata: { mfa: true, method: usedRecoveryCode ? 'recovery_code' : 'totp' },
    })

    return { tokens, user: toAuthenticatedUser(user) }
  }

  // -------------------------------------------------------------------------
  // Session lifecycle
  // -------------------------------------------------------------------------

  async refresh(presentedToken: string, meta: RequestMeta): Promise<TokenPair> {
    const { userId, familyId, newRefreshToken } = await this.tokens.rotateRefreshToken(presentedToken, meta)

    const user = await this.db.user.findFirst({ where: { id: userId, deletedAt: null } })
    if (!user) throw new UnauthenticatedError('Account no longer exists', 'TOKEN_INVALID')
    this.assertUsableAccount(user)

    authAttemptsTotal.inc({ event: 'refresh', outcome: 'success' })

    return {
      accessToken: this.tokens.signAccessToken({
        userId: user.id,
        role: user.role,
        sessionId: familyId,
        // The session already cleared MFA when it was created; rotation inherits it.
        mfaSatisfied: user.mfaEnabled,
      }),
      refreshToken: newRefreshToken,
      expiresIn: env.JWT_ACCESS_TTL,
      tokenType: 'Bearer',
    }
  }

  async logout(refreshToken: string, userId?: string): Promise<void> {
    await this.tokens.revokeToken(refreshToken, 'LOGOUT')
    if (userId) {
      await this.audit.recordDetached({ action: AuditAction.LOGOUT, resourceType: 'user', resourceId: userId })
    }
  }

  async logoutAll(userId: string): Promise<void> {
    await this.tokens.revokeAllForUser(userId, 'LOGOUT_ALL')
    await this.audit.recordDetached({ action: AuditAction.LOGOUT_ALL, resourceType: 'user', resourceId: userId })
  }

  // -------------------------------------------------------------------------
  // Password management
  // -------------------------------------------------------------------------

  /** Changing a password kills every other session. That is the point of changing it. */
  async changePassword(userId: string, input: ChangePasswordInput): Promise<void> {
    const user = await this.db.user.findUnique({ where: { id: userId } })
    if (!user?.passwordHash) throw new ForbiddenError('Password change is unavailable for this account')

    if (!(await verifyPassword(input.currentPassword, user.passwordHash))) {
      throw new ForbiddenError('Current password is incorrect')
    }

    const passwordHash = await hashPassword(input.newPassword)

    await this.db.$transaction(async (tx) => {
      await tx.user.update({
        where: { id: userId },
        data: { passwordHash, tokensValidFrom: new Date() },
      })
      await tx.refreshToken.updateMany({
        where: { userId, revokedAt: null },
        data: { revokedAt: new Date(), revokedReason: 'PASSWORD_CHANGED' },
      })
      await this.audit.record(tx, {
        action: AuditAction.PASSWORD_CHANGED,
        resourceType: 'user',
        resourceId: userId,
      })
    })
  }

  /**
   * Returns the reset token, or null when the email is unknown.
   *
   * The *controller* answers 202 either way. Leaking "no such account" here would
   * turn password reset into a free account-enumeration endpoint, which is the most
   * commonly missed instance of the problem.
   */
  async requestPasswordReset(email: string): Promise<string | null> {
    const user = await this.db.user.findFirst({ where: { email, deletedAt: null }, select: { id: true } })
    if (!user) return null

    const rawToken = randomBytes(32).toString('base64url')

    await this.db.$transaction(async (tx) => {
      // Only the newest reset link should work.
      await tx.verificationToken.updateMany({
        where: { userId: user.id, purpose: 'PASSWORD_RESET', consumedAt: null },
        data: { consumedAt: new Date() },
      })
      await tx.verificationToken.create({
        data: {
          userId: user.id,
          purpose: 'PASSWORD_RESET',
          tokenHash: hashOpaqueToken(rawToken),
          expiresAt: new Date(Date.now() + PASSWORD_RESET_TTL_MS),
        },
      })
      await this.audit.record(tx, {
        action: AuditAction.PASSWORD_RESET_REQUESTED,
        resourceType: 'user',
        resourceId: user.id,
        actorId: user.id,
      })
    })

    return rawToken
  }

  async resetPassword(token: string, newPassword: string): Promise<void> {
    const tokenHash = hashOpaqueToken(token)
    const passwordHash = await hashPassword(newPassword)

    await this.db.$transaction(async (tx) => {
      const record = await tx.verificationToken.findUnique({ where: { tokenHash } })

      if (!record || record.purpose !== 'PASSWORD_RESET' || record.consumedAt || record.expiresAt <= new Date()) {
        throw new UnauthenticatedError('Password reset link is invalid or has expired', 'TOKEN_INVALID')
      }

      // Single-use under concurrency.
      const { count } = await tx.verificationToken.updateMany({
        where: { id: record.id, consumedAt: null },
        data: { consumedAt: new Date() },
      })
      if (count !== 1) throw new UnauthenticatedError('Password reset link has already been used', 'TOKEN_INVALID')

      await tx.user.update({
        where: { id: record.userId },
        data: {
          passwordHash,
          tokensValidFrom: new Date(),
          // Whoever locked the account out is no longer relevant; the owner proved
          // control of the mailbox.
          failedLoginCount: 0,
          lockedUntil: null,
        },
      })
      await tx.refreshToken.updateMany({
        where: { userId: record.userId, revokedAt: null },
        data: { revokedAt: new Date(), revokedReason: 'PASSWORD_RESET' },
      })
      await this.audit.record(tx, {
        action: AuditAction.PASSWORD_RESET_COMPLETED,
        resourceType: 'user',
        resourceId: record.userId,
        actorId: record.userId,
      })
    })
  }

  // -------------------------------------------------------------------------
  // Email verification
  // -------------------------------------------------------------------------

  async verifyEmail(token: string): Promise<void> {
    const tokenHash = hashOpaqueToken(token)

    await this.db.$transaction(async (tx) => {
      const record = await tx.verificationToken.findUnique({ where: { tokenHash } })
      if (!record || record.purpose !== 'EMAIL_VERIFY' || record.consumedAt || record.expiresAt <= new Date()) {
        throw new UnauthenticatedError('Verification link is invalid or has expired', 'TOKEN_INVALID')
      }

      const { count } = await tx.verificationToken.updateMany({
        where: { id: record.id, consumedAt: null },
        data: { consumedAt: new Date() },
      })
      if (count !== 1) throw new UnauthenticatedError('Verification link has already been used', 'TOKEN_INVALID')

      await tx.user.update({
        where: { id: record.userId },
        data: {
          emailVerifiedAt: new Date(),
          // Don't resurrect a suspended account by verifying an old email link.
          status: 'ACTIVE',
        },
      })
      await this.audit.record(tx, {
        action: AuditAction.EMAIL_VERIFIED,
        resourceType: 'user',
        resourceId: record.userId,
        actorId: record.userId,
      })
    })
  }

  // -------------------------------------------------------------------------
  // Internals
  // -------------------------------------------------------------------------

  private async issueSession(
    user: User,
    meta: RequestMeta,
    options: { mfaSatisfied?: boolean } = {}
  ): Promise<TokenPair> {
    const { token, familyId } = await this.db.$transaction((tx) =>
      this.tokens.issueRefreshToken(tx, { userId: user.id, userAgent: meta.userAgent, ip: meta.ip })
    )

    return {
      accessToken: this.tokens.signAccessToken({
        userId: user.id,
        role: user.role,
        sessionId: familyId,
        mfaSatisfied: options.mfaSatisfied ?? !user.mfaEnabled,
      }),
      refreshToken: token,
      expiresIn: env.JWT_ACCESS_TTL,
      tokenType: 'Bearer',
    }
  }

  private assertUsableAccount(user: Pick<User, 'status'>): void {
    if (user.status === 'SUSPENDED') throw new ForbiddenError('This account has been suspended', 'ACCOUNT_INACTIVE')
    if (user.status === 'DEACTIVATED') throw new ForbiddenError('This account has been deactivated', 'ACCOUNT_INACTIVE')
    // PENDING_VERIFICATION users may sign in; route guards restrict what they can do.
    // Blocking login here would make "resend verification email" impossible.
  }

  /**
   * Increment the failure counter and lock the account once it crosses the threshold.
   *
   * The increment is done by the database (`{ increment: 1 }`) and we branch on the
   * *returned* value, not on the count we read before verifying the password.
   * Branching on the stale read lets two parallel guesses both observe `count = 4`,
   * neither reach the threshold, and the lock never engage.
   */
  private async registerFailedAttempt(user: Pick<User, 'id'>): Promise<void> {
    const { failedLoginCount } = await this.db.user.update({
      where: { id: user.id },
      data: { failedLoginCount: { increment: 1 } },
      select: { failedLoginCount: true },
    })

    if (failedLoginCount < env.MAX_FAILED_LOGINS) return

    // Threshold crossed. Reset the counter as we lock, so the next window starts
    // clean rather than locking again on the first attempt after expiry.
    await this.db.user.update({
      where: { id: user.id },
      data: {
        lockedUntil: new Date(Date.now() + env.ACCOUNT_LOCK_MINUTES * 60_000),
        failedLoginCount: 0,
      },
    })
    log.warn({ userId: user.id }, 'Account locked after repeated failed authentication')
  }

  private async clearFailedAttempts(user: Pick<User, 'id' | 'failedLoginCount' | 'lockedUntil'>): Promise<void> {
    // Skip the write on the common path: a clean account authenticating successfully.
    if (user.failedLoginCount === 0 && user.lockedUntil === null) return

    await this.db.user.update({
      where: { id: user.id },
      data: { failedLoginCount: 0, lockedUntil: null },
    })
  }

  private async recordFailedLogin(email: string, userId: string | null): Promise<void> {
    authAttemptsTotal.inc({ event: 'login', outcome: 'failure' })
    await this.audit.recordDetached({
      action: AuditAction.LOGIN_FAILED,
      resourceType: 'user',
      resourceId: userId,
      actorId: userId,
      outcome: 'FAILURE',
      // The email is the only way to investigate credential stuffing. It is already
      // in the request; recording it does not increase exposure.
      metadata: { email },
    })
  }
}

const toAuthenticatedUser = (user: User): AuthenticatedUser => ({
  id: user.id,
  email: user.email,
  role: user.role,
  mfaEnabled: user.mfaEnabled,
  emailVerified: user.emailVerifiedAt !== null,
})

/** Prisma P2002 — unique constraint. `meta.target` names the column(s). */
function isUniqueViolation(err: unknown, column: string): boolean {
  const e = err as { code?: string; meta?: { target?: string[] | string } }
  if (e?.code !== 'P2002') return false
  const target = e.meta?.target
  const columns = Array.isArray(target) ? target : [target ?? '']
  return columns.some((c) => c?.includes(column))
}
