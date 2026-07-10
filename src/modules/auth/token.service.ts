import jwt, { type JwtPayload, type SignOptions } from 'jsonwebtoken'
import { createHash, randomBytes, randomUUID } from 'node:crypto'
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

const hashToken = (token: string): string => createHash('sha256').update(token).digest('hex')

export class TokenService {
  constructor(private readonly db: Db) {}

  signAccessToken(params: {
    userId: string
    role: Role
    sessionId: string
    mfaSatisfied: boolean
  }): string {
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

  verifyAccessToken(token: string): AccessTokenClaims {
    try {
      const claims = jwt.verify(token, env.JWT_ACCESS_SECRET, {
        algorithms: ['HS256'],
        issuer: env.JWT_ISSUER,
        audience: env.JWT_AUDIENCE,
      }) as AccessTokenClaims

      if (claims.typ !== 'access')
        throw new UnauthenticatedError('Wrong token type', 'TOKEN_INVALID')

      return claims
    } catch (err) {
      if (err instanceof UnauthenticatedError) throw err
      if (err instanceof jwt.TokenExpiredError) {
        throw new UnauthenticatedError('Access token expired', 'TOKEN_EXPIRED')
      }
      throw new UnauthenticatedError('Invalid access token', 'TOKEN_INVALID')
    }
  }

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

  async rotateRefreshToken(
    presentedToken: string,
    context: { userAgent?: string; ip?: string }
  ): Promise<{ userId: string; familyId: string; newRefreshToken: string }> {
    const tokenHash = hashToken(presentedToken)

    return this.db.$transaction(async tx => {
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

  async revokeToken(token: string, reason = 'LOGOUT'): Promise<void> {
    await this.db.refreshToken.updateMany({
      where: { tokenHash: hashToken(token), revokedAt: null },
      data: { revokedAt: new Date(), revokedReason: reason },
    })
  }

  async revokeFamily(tx: Tx, familyId: string, reason: string): Promise<void> {
    await tx.refreshToken.updateMany({
      where: { familyId, revokedAt: null },
      data: { revokedAt: new Date(), revokedReason: reason },
    })
  }

  async revokeAllForUser(userId: string, reason: string): Promise<void> {
    await this.db.$transaction(async tx => {
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

  async pruneExpired(olderThan: Date = new Date()): Promise<number> {
    const { count } = await this.db.refreshToken.deleteMany({
      where: { expiresAt: { lt: olderThan } },
    })
    return count
  }
}
