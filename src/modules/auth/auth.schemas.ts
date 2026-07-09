import { z } from 'zod'

/**
 * Request validation lives here, not in controllers. Every schema is `.strict()` so
 * an unexpected property is a 400 rather than something silently ignored — that is
 * what stops mass-assignment (`{"email":"…","role":"ADMIN"}` on registration).
 */

const email = z
  .string()
  .trim()
  .toLowerCase()
  .min(3)
  .max(254) // RFC 5321
  .email('must be a valid email address')

/**
 * NIST SP 800-63B: length is what matters, composition rules are not.
 * We enforce a floor of 12, a ceiling of 128 (argon2 cost is linear in input, and
 * an unbounded password is a cheap DoS), and reject the obvious garbage.
 */
const password = z
  .string()
  .min(12, 'must be at least 12 characters')
  .max(128, 'must be at most 128 characters')
  .refine((v) => !/^(.)\1+$/.test(v), 'must not be a single repeated character')
  .refine((v) => v.trim().length === v.length, 'must not start or end with whitespace')

const totpCode = z
  .string()
  .trim()
  .regex(/^\d{6}$/, 'must be a 6-digit code')

const recoveryCode = z
  .string()
  .trim()
  .toUpperCase()
  .regex(/^[0-9A-F]{5}-[0-9A-F]{5}$/, 'must be a valid recovery code')

/** Opaque 256-bit token, base64url. Bounded so we never hash an unbounded string. */
const refreshToken = z.string().min(32).max(256)

const name = z
  .string()
  .trim()
  .min(1)
  .max(80)
  // Letters (any script), marks, spaces, hyphen, apostrophe, period.
  .regex(/^[\p{L}\p{M}][\p{L}\p{M}\s'.-]*$/u, 'contains invalid characters')

/** E.164. Stored encrypted with an HMAC blind index for lookup. */
const phone = z
  .string()
  .trim()
  .regex(/^\+[1-9]\d{7,14}$/, 'must be in E.164 format, e.g. +919876543210')

// --- Registration -----------------------------------------------------------

export const registerSchema = z
  .object({
    email,
    password,
    firstName: name,
    lastName: name,
    phone: phone.optional(),
    // `role` is deliberately absent. A caller cannot choose their own role; patient
    // is implicit, and doctor accounts are created through an admin-reviewed flow.
    timezone: z.string().max(64).optional(),
  })
  .strict()

export type RegisterInput = z.infer<typeof registerSchema>

// --- Login ------------------------------------------------------------------

export const loginSchema = z
  .object({
    email,
    password: z.string().min(1).max(128), // don't apply policy to *existing* passwords
  })
  .strict()

export type LoginInput = z.infer<typeof loginSchema>

/** Second leg of login when MFA is enrolled. Exactly one of the two codes. */
export const mfaChallengeSchema = z
  .object({
    mfaToken: z.string().min(1),
    totpCode: totpCode.optional(),
    recoveryCode: recoveryCode.optional(),
  })
  .strict()
  .refine(
    (v) => Boolean(v.totpCode) !== Boolean(v.recoveryCode),
    'provide exactly one of totpCode or recoveryCode'
  )

export type MfaChallengeInput = z.infer<typeof mfaChallengeSchema>

// --- Session ----------------------------------------------------------------

export const refreshSchema = z.object({ refreshToken }).strict()
export type RefreshInput = z.infer<typeof refreshSchema>

export const logoutSchema = z.object({ refreshToken }).strict()
export type LogoutInput = z.infer<typeof logoutSchema>

// --- Password ---------------------------------------------------------------

export const changePasswordSchema = z
  .object({
    currentPassword: z.string().min(1).max(128),
    newPassword: password,
  })
  .strict()
  .refine((v) => v.currentPassword !== v.newPassword, {
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

// --- Email verification -----------------------------------------------------

export const verifyEmailSchema = z.object({ token: z.string().min(32).max(256) }).strict()
export type VerifyEmailInput = z.infer<typeof verifyEmailSchema>

// --- MFA management ---------------------------------------------------------

export const enrolMfaSchema = z.object({ totpCode }).strict()
export type EnrolMfaInput = z.infer<typeof enrolMfaSchema>

export const disableMfaSchema = z.object({ currentPassword: z.string().min(1).max(128) }).strict()
export type DisableMfaInput = z.infer<typeof disableMfaSchema>
