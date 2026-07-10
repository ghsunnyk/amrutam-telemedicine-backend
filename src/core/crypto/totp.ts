import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto'

const DIGITS = 6
const STEP_SECONDS = 30
const SECRET_BYTES = 20

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

export const generateSecret = (): string => base32Encode(randomBytes(SECRET_BYTES))

export const currentStep = (atMs: number = Date.now()): number =>
  Math.floor(atMs / 1000 / STEP_SECONDS)

export function generateToken(secret: string, step: number = currentStep()): string {
  const key = base32Decode(secret)

  const counter = Buffer.alloc(8)
  counter.writeBigUInt64BE(BigInt(step))

  const digest = createHmac('sha1', key).update(counter).digest()

  const offset = digest[digest.length - 1]! & 0x0f
  const binary =
    ((digest[offset]! & 0x7f) << 24) |
    ((digest[offset + 1]! & 0xff) << 16) |
    ((digest[offset + 2]! & 0xff) << 8) |
    (digest[offset + 3]! & 0xff)

  return (binary % 10 ** DIGITS).toString().padStart(DIGITS, '0')
}

export interface VerifyResult {
  valid: boolean
  step?: number
}

export function verifyToken(
  token: string,
  secret: string,
  options: { window?: number; atMs?: number; lastUsedStep?: number | null } = {}
): VerifyResult {
  const { window = 1, atMs = Date.now(), lastUsedStep = null } = options

  if (!/^\d{6}$/.test(token)) return { valid: false }

  const now = currentStep(atMs)

  for (let offset = -window; offset <= window; offset++) {
    const step = now + offset
    if (lastUsedStep !== null && step <= lastUsedStep) continue // replay

    if (constantTimeEqual(token, generateToken(secret, step))) {
      return { valid: true, step }
    }
  }

  return { valid: false }
}

export function buildOtpAuthUrl(params: {
  secret: string
  account: string
  issuer: string
}): string {
  const label = `${encodeURIComponent(params.issuer)}:${encodeURIComponent(params.account)}`
  const query = new URLSearchParams({
    secret: params.secret,
    issuer: params.issuer,
    algorithm: 'SHA1',
    digits: String(DIGITS),
    period: String(STEP_SECONDS),
  })
  return `otpauth://totp/${label}?${query.toString()}`
}

export function generateRecoveryCodes(count = 10): string[] {
  return Array.from({ length: count }, () => {
    const raw = randomBytes(5).toString('hex').toUpperCase() // 10 hex chars, 40 bits
    return `${raw.slice(0, 5)}-${raw.slice(5)}`
  })
}

function constantTimeEqual(a: string, b: string): boolean {
  const bufA = Buffer.from(a, 'utf8')
  const bufB = Buffer.from(b, 'utf8')
  if (bufA.length !== bufB.length) return false
  return timingSafeEqual(bufA, bufB)
}

function base32Encode(buffer: Buffer): string {
  let bits = 0
  let value = 0
  let output = ''

  for (const byte of buffer) {
    value = (value << 8) | byte
    bits += 8
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31]
      bits -= 5
    }
  }
  if (bits > 0) output += BASE32_ALPHABET[(value << (5 - bits)) & 31]

  return output
}

function base32Decode(input: string): Buffer {
  const clean = input.toUpperCase().replace(/=+$/, '').replace(/\s/g, '')

  let bits = 0
  let value = 0
  const output: number[] = []

  for (const char of clean) {
    const idx = BASE32_ALPHABET.indexOf(char)
    if (idx === -1) throw new Error('Invalid base32 character in TOTP secret')

    value = (value << 5) | idx
    bits += 5
    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 0xff)
      bits -= 8
    }
  }

  return Buffer.from(output)
}
