import type { Request, Response } from 'express'
import { isProduction } from '../../config/env'
import { UnauthenticatedError } from '../../core/errors'
import { sendSuccess } from '../../core/http'
import type { AuthService, RequestMeta } from './auth.service'
import type { MfaService } from './mfa.service'
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

/**
 * Controllers do three things and nothing else: pull already-validated input off the
 * request, call a service, shape the response. No business rules, no database access,
 * no error handling — errors propagate to `errorHandler`, which is the only place
 * that decides what a client is allowed to see.
 */
export class AuthController {
  constructor(
    private readonly auth: AuthService,
    private readonly mfa: MfaService
  ) {}

  register = async (req: Request, res: Response): Promise<void> => {
    const input = req.body as RegisterInput
    const { user, verificationToken } = await this.auth.register(input)

    // TODO(phase-2): enqueue `email.verification` on the outbox instead.
    // Returning the token outside production is what makes the flow testable without
    // a mail server; leaking it in production would let anyone verify anyone's email.
    sendSuccess(
      res,
      { user, ...(isProduction ? {} : { verificationToken }) },
      { status: 201 }
    )
  }

  /**
   * Two possible successes: a session, or an MFA challenge. The challenge path throws
   * `MfaRequiredError` from the service, so it surfaces as a 401 carrying `mfaToken`
   * in `error.details` — a client that ignores the body still fails closed.
   */
  login = async (req: Request, res: Response): Promise<void> => {
    const result = await this.auth.login(req.body as LoginInput, requestMeta(req))
    sendSuccess(res, result)
  }

  mfaChallenge = async (req: Request, res: Response): Promise<void> => {
    const result = await this.auth.completeMfaChallenge(req.body as MfaChallengeInput, requestMeta(req))
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

  // --- Password -------------------------------------------------------------

  changePassword = async (req: Request, res: Response): Promise<void> => {
    await this.auth.changePassword(requireAuth(req).userId, req.body as ChangePasswordInput)
    // 204 with no body: every other session is now dead, including any the client
    // might have been holding. It must re-authenticate.
    res.status(204).end()
  }

  /**
   * Always 202, whether or not the email exists.
   *
   * This endpoint is the most commonly overlooked account-enumeration oracle: a 404
   * for unknown addresses lets anyone test whether a person is a patient here, which
   * for a healthcare provider is itself sensitive information.
   */
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

  // --- MFA ------------------------------------------------------------------

  /**
   * Returns the shared secret and an `otpauth://` URI. The secret is shown exactly
   * once; `mfaEnabled` stays false until `enrolMfa` proves the authenticator works.
   */
  beginMfaEnrolment = async (req: Request, res: Response): Promise<void> => {
    const challenge = await this.mfa.beginEnrolment(requireAuth(req).userId)
    sendSuccess(res, challenge)
  }

  enrolMfa = async (req: Request, res: Response): Promise<void> => {
    const { totpCode } = req.body as EnrolMfaInput
    const { recoveryCodes } = await this.mfa.completeEnrolment(requireAuth(req).userId, totpCode)

    // The only time these are ever readable. We store argon2 hashes.
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

/**
 * Narrows `req.auth` from optional to defined. The `authenticate` middleware
 * guarantees it, but the type system does not know that — and an unguarded `!` is how
 * a route that forgot the middleware becomes an authorisation bypass instead of a crash.
 */
function requireAuth(req: Request): NonNullable<Request['auth']> {
  if (!req.auth) throw new UnauthenticatedError()
  return req.auth
}
