import type { Request, Response } from 'express'
import { isProduction } from '../../config/env'
import { UnauthenticatedError } from '../../core/errors'
import { sendSuccess } from '../../core/http'
import type {
  ChangePasswordInput,
  DisableMfaInput,
  EnrolMfaInput,
  LoginInput,
  LogoutInput,
  MfaChallengeInput,
  RefreshInput,
  RegisterInput,
  RequestPasswordResetInput,
  ResetPasswordInput,
  VerifyEmailInput,
} from './auth.schemas'
import type { AuthService, RequestMeta } from './auth.service'
import type { MfaService } from './mfa.service'

export class AuthController {
  constructor(
    private readonly auth: AuthService,
    private readonly mfa: MfaService
  ) {}

  register = async (req: Request, res: Response): Promise<void> => {
    const input = req.body as RegisterInput
    const { user, verificationToken } = await this.auth.register(input)

    sendSuccess(res, { user, ...(isProduction ? {} : { verificationToken }) }, { status: 201 })
  }

  login = async (req: Request, res: Response): Promise<void> => {
    const result = await this.auth.login(req.body as LoginInput, requestMeta(req))
    sendSuccess(res, result)
  }

  mfaChallenge = async (req: Request, res: Response): Promise<void> => {
    const result = await this.auth.completeMfaChallenge(
      req.body as MfaChallengeInput,
      requestMeta(req)
    )
    sendSuccess(res, result)
  }

  refresh = async (req: Request, res: Response): Promise<void> => {
    const { refreshToken } = req.body as RefreshInput
    const tokens = await this.auth.refresh(refreshToken, requestMeta(req))
    sendSuccess(res, tokens)
  }

  logout = async (req: Request, res: Response): Promise<void> => {
    const { refreshToken } = req.body as LogoutInput
    await this.auth.logout(refreshToken, req.auth?.userId)
    res.status(204).end()
  }

  logoutAll = async (req: Request, res: Response): Promise<void> => {
    await this.auth.logoutAll(requireAuth(req).userId)
    res.status(204).end()
  }

  me = async (req: Request, res: Response): Promise<void> => {
    const auth = requireAuth(req)
    sendSuccess(res, {
      userId: auth.userId,
      role: auth.role,
      mfaSatisfied: auth.mfaSatisfied,
      sessionId: auth.sessionId,
    })
  }

  changePassword = async (req: Request, res: Response): Promise<void> => {
    await this.auth.changePassword(requireAuth(req).userId, req.body as ChangePasswordInput)
    res.status(204).end()
  }

  requestPasswordReset = async (req: Request, res: Response): Promise<void> => {
    const { email } = req.body as RequestPasswordResetInput
    const token = await this.auth.requestPasswordReset(email)

    sendSuccess(
      res,
      {
        message: 'If an account exists for this address, a reset link has been sent.',
        ...(isProduction || !token ? {} : { resetToken: token }),
      },
      { status: 202 }
    )
  }

  resetPassword = async (req: Request, res: Response): Promise<void> => {
    const { token, newPassword } = req.body as ResetPasswordInput
    await this.auth.resetPassword(token, newPassword)
    res.status(204).end()
  }

  verifyEmail = async (req: Request, res: Response): Promise<void> => {
    const { token } = req.body as VerifyEmailInput
    await this.auth.verifyEmail(token)
    res.status(204).end()
  }

  beginMfaEnrolment = async (req: Request, res: Response): Promise<void> => {
    const challenge = await this.mfa.beginEnrolment(requireAuth(req).userId)
    sendSuccess(res, challenge)
  }

  enrolMfa = async (req: Request, res: Response): Promise<void> => {
    const { totpCode } = req.body as EnrolMfaInput
    const { recoveryCodes } = await this.mfa.completeEnrolment(requireAuth(req).userId, totpCode)

    sendSuccess(res, {
      recoveryCodes,
      message: 'Store these codes somewhere safe. They will not be shown again.',
    })
  }

  disableMfa = async (req: Request, res: Response): Promise<void> => {
    const { currentPassword } = req.body as DisableMfaInput
    await this.mfa.disable(requireAuth(req).userId, currentPassword)
    res.status(204).end()
  }

  mfaStatus = async (req: Request, res: Response): Promise<void> => {
    const auth = requireAuth(req)
    sendSuccess(res, {
      enabled: auth.mfaSatisfied,
      unusedRecoveryCodes: await this.mfa.countUnusedRecoveryCodes(auth.userId),
    })
  }
}

const requestMeta = (req: Request): RequestMeta => ({
  ip: req.ip,
  userAgent: req.get('user-agent'),
})

function requireAuth(req: Request): NonNullable<Request['auth']> {
  if (!req.auth) throw new UnauthenticatedError()
  return req.auth
}
