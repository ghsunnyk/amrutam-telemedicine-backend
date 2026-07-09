import { createHash, randomBytes, randomUUID } from 'node:crypto'
import jwt, { type JwtPayload, type SignOptions } from 'jsonwebtoken'
import { env } from '../../config/env'
import { hashIp } from '../../core/crypto/encryption'
import { UnauthenticatedError } from '../../core/errors'
import type { Db, Tx } from '../../db/prisma'
import type { Role } from '../../generated/prisma/enums'
import { createLogger } from '../../observability/logger'
import { authTokenRefreshReuseTotal } from '../../observability/metrics'

const log = createLogger('token')

export interface AccessTokenClaims extends JwtPayload {
  sub: string
  role: Role
  sid: string // session (refresh-token family) id
  mfa: boolean // has this session satisfied MFA?
  typ: 'access'
}

/** Short-lived, signed, and *only* used to complete an MFA challenge. */
export interface MfaChallengeClaims extends JwtPayload {
  sub: string
  typ: 'mfa_challenge'
}

export interface TokenPair {
  accessToken: string
  refreshToken: string
  expiresIn: number
  tokenType: 'Bearer'
}

/** SHA-256, not argon2. Refresh tokens are 256 bits of CSPRNG output, so there is
 *  nothing to brute-force; we only need a one-way function that is cheap enough to
 *  run on every refresh. Argon2 here would add 50ms to the hot path for no benefit. */
const hashToken = (token: string): string => createHash('sha256').update(token).digest('hex')

export class TokenService {
  constructor(private readonly db: Db) {}

  // --- Access tokens --------------------------------------------------------

  signAccessToken(params: { userId: string; role: Role; sessionId: string; mfaSatisfied: boolean }): string {
    const options: SignOptions = {
      expiresIn: env.JWT_ACCESS_TTL,
      issuer: env.JWT_ISSUER,
      audience: env.JWT_AUDIENCE,
      algorithm: 'HS256',
      jwtid: randomUUID(),
    }
    const claims: Omit<AccessTokenClaims, 'iat' | 'exp'> = {
      sub: params.userId,
      role: params.role,
      sid: params.sessionId,
      mfa: params.mfaSatisfied,
      typ: 'access',
    }
    return jwt.sign(claims, env.JWT_ACCESS_SECRET, options)
  }

  /**
   * Verify signature, expiry, issuer and audience.
   *
   * `algorithms` is pinned explicitly. Omitting it is the classic JWT vulnerability:
   * the library would honour the `alg` header, and an attacker sets `alg: none` or
   * downgrades an RS256 deployment to HS256 signed with the public key.
   */
  verifyAccessToken(token: string): AccessTokenClaims {
    try {
      const claims = jwt.verify(token, env.JWT_ACCESS_SECRET, {
        algorithms: ['HS256'],
        issuer: env.JWT_ISSUER,
        audience: env.JWT_AUDIENCE,
      }) as AccessTokenClaims

      // A refresh or MFA token presented as an access token must not be accepted.
      if (claims.typ !== 'access') throw new UnauthenticatedError('Wrong token type', 'TOKEN_INVALID')

      return claims
    } catch (err) {
      if (err instanceof UnauthenticatedError) throw err
      if (err instanceof jwt.TokenExpiredError) {
        throw new UnauthenticatedError('Access token expired', 'TOKEN_EXPIRED')
      }
      throw new UnauthenticatedError('Invalid access token', 'TOKEN_INVALID')
    }
  }

  // --- MFA challenge tokens -------------------------------------------------

  /** Issued after a correct password but before a correct TOTP code. 5-minute life. */
  signMfaChallengeToken(userId: string): string {
    return jwt.sign({ sub: userId, typ: 'mfa_challenge' }, env.JWT_ACCESS_SECRET, {
      expiresIn: 300,
      issuer: env.JWT_ISSUER,
      audience: env.JWT_AUDIENCE,
      algorithm: 'HS256',
      jwtid: randomUUID(),
    })
  }

  verifyMfaChallengeToken(token: string): MfaChallengeClaims {
    try {
      const claims = jwt.verify(token, env.JWT_ACCESS_SECRET, {
        algorithms: ['HS256'],
        issuer: env.JWT_ISSUER,
        audience: env.JWT_AUDIENCE,
      }) as MfaChallengeClaims

      if (claims.typ !== 'mfa_challenge') {
        throw new UnauthenticatedError('Wrong token type', 'TOKEN_INVALID')
      }
      return claims
    } catch (err) {
      if (err instanceof UnauthenticatedError) throw err
      throw new UnauthenticatedError('Invalid or expired MFA challenge', 'TOKEN_INVALID')
    }
  }

  // --- Refresh tokens -------------------------------------------------------

  /**
   * Mint a refresh token. `familyId` identifies the login session; every rotation
   * within that session reuses it, which is what lets us revoke the whole chain when
   * a stolen token surfaces.
   */
  async issueRefreshToken(
    tx: Tx,
    params: { userId: string; familyId?: string; userAgent?: string; ip?: string }
  ): Promise<{ token: string; familyId: string }> {
    const token = randomBytes(32).toString('base64url') // 256 bits
    const familyId = params.familyId ?? randomUUID()

    await tx.refreshToken.create({
      data: {
        userId: params.userId,
        familyId,
        tokenHash: hashToken(token),
        expiresAt: new Date(Date.now() + env.JWT_REFRESH_TTL * 1000),
        userAgent: params.userAgent?.slice(0, 512),
        ipHash: params.ip ? hashIp(params.ip) : undefined,
      },
    })

    return { token, familyId }
  }

  /**
   * Exchange a refresh token for a new pair, atomically.
   *
   * Reuse detection (RFC 6819 §5.2.2.3 / OAuth BCP): a refresh token is single-use.
   * If one arrives that has already been rotated, either the client raced itself or
   * an attacker is replaying a stolen token — and we cannot tell which. The safe
   * response is to assume theft and revoke the entire family, forcing a fresh login
   * on the real user and locking the attacker out of a chain they may have advanced.
   *
   * The whole exchange runs in one transaction, and the `rotatedAt IS NULL` guard is
   * enforced by an `updateMany` whose count we check — so two concurrent refreshes
   * with the same token cannot both succeed.
   */
  async rotateRefreshToken(
    presentedToken: string,
    context: { userAgent?: string; ip?: string }
  ): Promise<{ userId: string; familyId: string; newRefreshToken: string }> {
    const tokenHash = hashToken(presentedToken)

    return this.db.$transaction(async (tx) => {
      const existing = await tx.refreshToken.findUnique({
        where: { tokenHash },
        select: {
          id: true,
          userId: true,
          familyId: true,
          expiresAt: true,
          revokedAt: true,
          rotatedAt: true,
        },
      })

      if (!existing) throw new UnauthenticatedError('Invalid refresh token', 'TOKEN_INVALID')

      if (existing.rotatedAt || existing.revokedAt) {
        await this.revokeFamily(tx, existing.familyId, 'REUSE_DETECTED')
        authTokenRefreshReuseTotal.inc()
        log.error(
          { userId: existing.userId, familyId: existing.familyId },
          'Refresh token reuse detected — revoking token family'
        )
        throw new UnauthenticatedError('Refresh token has already been used', 'TOKEN_INVALID')
      }

      if (existing.expiresAt <= new Date()) {
        throw new UnauthenticatedError('Refresh token expired', 'TOKEN_EXPIRED')
      }

      // Guarded update: whoever flips `rotatedAt` from NULL first wins the race.
      const { count } = await tx.refreshToken.updateMany({
        where: { id: existing.id, rotatedAt: null, revokedAt: null },
        data: { rotatedAt: new Date() },
      })
      if (count !== 1) {
        throw new UnauthenticatedError('Refresh token has already been used', 'TOKEN_INVALID')
      }

      const { token } = await this.issueRefreshToken(tx, {
        userId: existing.userId,
        familyId: existing.familyId,
        userAgent: context.userAgent,
        ip: context.ip,
      })

      return { userId: existing.userId, familyId: existing.familyId, newRefreshToken: token }
    })
  }

  /** Revoke one token (normal logout). */
  async revokeToken(token: string, reason = 'LOGOUT'): Promise<void> {
    await this.db.refreshToken.updateMany({
      where: { tokenHash: hashToken(token), revokedAt: null },
      data: { revokedAt: new Date(), revokedReason: reason },
    })
  }

  /** Revoke every live token in a session chain. */
  async revokeFamily(tx: Tx, familyId: string, reason: string): Promise<void> {
    await tx.refreshToken.updateMany({
      where: { familyId, revokedAt: null },
      data: { revokedAt: new Date(), revokedReason: reason },
    })
  }

  /**
   * Sign out everywhere. Revoking refresh tokens is not enough on its own — already
   * issued access tokens stay valid until they expire. Bumping `tokensValidFrom`
   * makes `authenticate` reject any access token whose `iat` predates it, which
   * closes that window at the cost of one indexed read per request.
   */
  async revokeAllForUser(userId: string, reason: string): Promise<void> {
    await this.db.$transaction(async (tx) => {
      await tx.refreshToken.updateMany({
        where: { userId, revokedAt: null },
        data: { revokedAt: new Date(), revokedReason: reason },
      })
      await tx.user.update({
        where: { id: userId },
        data: { tokensValidFrom: new Date() },
      })
    })
  }

  /** Housekeeping: expired and long-revoked rows serve no forensic purpose. */
  async pruneExpired(olderThan: Date = new Date()): Promise<number> {
    const { count } = await this.db.refreshToken.deleteMany({
      where: { expiresAt: { lt: olderThan } },
    })
    return count
  }
}
