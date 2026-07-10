import { z } from 'zod'

const email = z
  .string()
  .trim()
  .toLowerCase()
  .min(3)
  .max(254) // RFC 5321
  .email('must be a valid email address')

const password = z
  .string()
  .min(12, 'must be at least 12 characters')
  .max(128, 'must be at most 128 characters')
  .refine(v => !/^(.)\1+$/.test(v), 'must not be a single repeated character')
  .refine(v => v.trim().length === v.length, 'must not start or end with whitespace')

const totpCode = z
  .string()
  .trim()
  .regex(/^\d{6}$/, 'must be a 6-digit code')

const recoveryCode = z
  .string()
  .trim()
  .toUpperCase()
  .regex(/^[0-9A-F]{5}-[0-9A-F]{5}$/, 'must be a valid recovery code')

const refreshToken = z.string().min(32).max(256)

const name = z
  .string()
  .trim()
  .min(1)
  .max(80)
  .regex(/^[\p{L}\p{M}][\p{L}\p{M}\s'.-]*$/u, 'contains invalid characters')

const phone = z
  .string()
  .trim()
  .regex(/^\+[1-9]\d{7,14}$/, 'must be in E.164 format, e.g. +919876543210')

export const registerSchema = z
  .object({
    email,
    password,
    firstName: name,
    lastName: name,
    phone: phone.optional(),
    timezone: z.string().max(64).optional(),
  })
  .strict()

export type RegisterInput = z.infer<typeof registerSchema>

export const loginSchema = z
  .object({
    email,
    password: z.string().min(1).max(128), // don't apply policy to *existing* passwords
  })
  .strict()

export type LoginInput = z.infer<typeof loginSchema>

export const mfaChallengeSchema = z
  .object({
    mfaToken: z.string().min(1),
    totpCode: totpCode.optional(),
    recoveryCode: recoveryCode.optional(),
  })
  .strict()
  .refine(
    v => Boolean(v.totpCode) !== Boolean(v.recoveryCode),
    'provide exactly one of totpCode or recoveryCode'
  )

export type MfaChallengeInput = z.infer<typeof mfaChallengeSchema>

export const refreshSchema = z.object({ refreshToken }).strict()
export type RefreshInput = z.infer<typeof refreshSchema>

export const logoutSchema = z.object({ refreshToken }).strict()
export type LogoutInput = z.infer<typeof logoutSchema>

export const changePasswordSchema = z
  .object({
    currentPassword: z.string().min(1).max(128),
    newPassword: password,
  })
  .strict()
  .refine(v => v.currentPassword !== v.newPassword, {
    message: 'new password must differ from the current one',
    path: ['newPassword'],
  })

export type ChangePasswordInput = z.infer<typeof changePasswordSchema>

export const requestPasswordResetSchema = z.object({ email }).strict()
export type RequestPasswordResetInput = z.infer<typeof requestPasswordResetSchema>

export const resetPasswordSchema = z
  .object({
    token: z.string().min(32).max(256),
    newPassword: password,
  })
  .strict()

export type ResetPasswordInput = z.infer<typeof resetPasswordSchema>

export const verifyEmailSchema = z.object({ token: z.string().min(32).max(256) }).strict()
export type VerifyEmailInput = z.infer<typeof verifyEmailSchema>

export const enrolMfaSchema = z.object({ totpCode }).strict()
export type EnrolMfaInput = z.infer<typeof enrolMfaSchema>

export const disableMfaSchema = z.object({ currentPassword: z.string().min(1).max(128) }).strict()
export type DisableMfaInput = z.infer<typeof disableMfaSchema>
