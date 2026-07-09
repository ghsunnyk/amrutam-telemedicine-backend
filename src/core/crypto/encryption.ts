import {
  createCipheriv,
  createDecipheriv,
  createHmac,
  randomBytes,
  timingSafeEqual,
} from 'node:crypto'
import { env } from '../../config/env'
import { InternalError } from '../errors'

/**
 * Envelope encryption for column-level PHI/PII.
 *
 *   KEK (env / KMS)  ──wraps──▶  DEK v1, v2, … (encryption_keys table)  ──encrypts──▶  columns
 *
 * Why two levels: rotating the KEK only rewraps a handful of rows in
 * `encryption_keys`; rotating a DEK is a background re-encryption of the columns
 * that reference it. Neither ever requires downtime, and a leaked DEK is
 * blast-radius-limited to the rows encrypted under that version.
 *
 * Ciphertext layout (all big-endian, concatenated):
 *
 *   ┌────────┬──────────┬──────────┬─────────┬────────────┐
 *   │ magic  │ keyVer   │ iv       │ authTag │ ciphertext │
 *   │ 2 B    │ 4 B      │ 12 B     │ 16 B    │ n B        │
 *   └────────┴──────────┴──────────┴─────────┴────────────┘
 *
 * `keyVer` is stored *inside* the blob so a row is self-describing: we can decrypt
 * without a separate column telling us which DEK to use, which in turn makes
 * re-encryption restartable.
 */

/**
 * Prisma types a `Bytes` column as `Uint8Array<ArrayBuffer>`, which a Node `Buffer`
 * (`Uint8Array<ArrayBufferLike>`) is not assignable to — a Buffer may be backed by a
 * SharedArrayBuffer. Conversion happens once, at the database boundary in `Keyring`.
 */
export type DbBytes = Uint8Array<ArrayBuffer>

/** Copies into a plain ArrayBuffer. Also detaches from Node's pooled 8 KiB slab, so a
 *  long-lived ciphertext cannot pin the whole slab in memory. */
export const toDbBytes = (buf: Buffer): DbBytes => Uint8Array.from(buf)

export const fromDbBytes = (bytes: Uint8Array): Buffer =>
  Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength)

const MAGIC = Buffer.from([0xa3, 0x01]) // 'Amrutam envelope v1'
const MAGIC_LEN = 2
const KEY_VER_LEN = 4
const IV_LEN = 12 // GCM standard; 96-bit IVs are the only size with a security proof
const TAG_LEN = 16
const HEADER_LEN = MAGIC_LEN + KEY_VER_LEN + IV_LEN + TAG_LEN

const ALGORITHM = 'aes-256-gcm'

export interface DataKey {
  version: number
  key: Buffer // raw 32 bytes, only ever in memory
}

/** Wrap/unwrap a DEK under the KEK. Same AEAD construction, no key version needed. */
export function wrapDataKey(dek: Buffer, kek: Buffer = env.ENCRYPTION_KEK): Buffer {
  const iv = randomBytes(IV_LEN)
  const cipher = createCipheriv(ALGORITHM, kek, iv)
  const ciphertext = Buffer.concat([cipher.update(dek), cipher.final()])
  return Buffer.concat([iv, cipher.getAuthTag(), ciphertext])
}

export function unwrapDataKey(wrapped: Buffer, kek: Buffer = env.ENCRYPTION_KEK): Buffer {
  if (wrapped.length < IV_LEN + TAG_LEN) throw new InternalError('Malformed wrapped data key')
  const iv = wrapped.subarray(0, IV_LEN)
  const tag = wrapped.subarray(IV_LEN, IV_LEN + TAG_LEN)
  const ciphertext = wrapped.subarray(IV_LEN + TAG_LEN)
  const decipher = createDecipheriv(ALGORITHM, kek, iv)
  decipher.setAuthTag(tag)
  return Buffer.concat([decipher.update(ciphertext), decipher.final()])
}

export const generateDataKey = (): Buffer => randomBytes(32)

/**
 * @param aad Additional authenticated data — bind the ciphertext to its context
 *   (e.g. `consultation:<id>:diagnosis`). A blob lifted from one row cannot then
 *   be pasted into another: decryption fails the auth-tag check.
 */
export function encrypt(plaintext: string | Buffer, dek: DataKey, aad?: string): Buffer {
  const iv = randomBytes(IV_LEN)
  const cipher = createCipheriv(ALGORITHM, dek.key, iv)
  if (aad) cipher.setAAD(Buffer.from(aad, 'utf8'))

  const input = typeof plaintext === 'string' ? Buffer.from(plaintext, 'utf8') : plaintext
  const ciphertext = Buffer.concat([cipher.update(input), cipher.final()])

  const keyVer = Buffer.alloc(KEY_VER_LEN)
  keyVer.writeUInt32BE(dek.version)

  return Buffer.concat([MAGIC, keyVer, iv, cipher.getAuthTag(), ciphertext])
}

/** Reads the key version out of a blob without decrypting — used by the rotation job. */
export function readKeyVersion(blob: Buffer): number {
  assertEnvelope(blob)
  return blob.readUInt32BE(MAGIC_LEN)
}

export function decrypt(blob: Buffer, dek: DataKey, aad?: string): Buffer {
  assertEnvelope(blob)

  const version = blob.readUInt32BE(MAGIC_LEN)
  if (version !== dek.version) {
    throw new InternalError(`Ciphertext requires key version ${version}, got ${dek.version}`)
  }

  const iv = blob.subarray(MAGIC_LEN + KEY_VER_LEN, MAGIC_LEN + KEY_VER_LEN + IV_LEN)
  const tag = blob.subarray(MAGIC_LEN + KEY_VER_LEN + IV_LEN, HEADER_LEN)
  const ciphertext = blob.subarray(HEADER_LEN)

  const decipher = createDecipheriv(ALGORITHM, dek.key, iv)
  decipher.setAuthTag(tag)
  if (aad) decipher.setAAD(Buffer.from(aad, 'utf8'))

  try {
    return Buffer.concat([decipher.update(ciphertext), decipher.final()])
  } catch {
    // Wrong key, wrong AAD, or tampered ciphertext — all indistinguishable, by design.
    throw new InternalError('Decryption failed: ciphertext failed authentication')
  }
}

export const decryptToString = (blob: Buffer, dek: DataKey, aad?: string): string =>
  decrypt(blob, dek, aad).toString('utf8')

function assertEnvelope(blob: Buffer): void {
  if (blob.length < HEADER_LEN || !blob.subarray(0, MAGIC_LEN).equals(MAGIC)) {
    throw new InternalError('Malformed ciphertext envelope')
  }
}

/**
 * Blind index: deterministic HMAC that lets us do equality lookups
 * (`WHERE phone_hash = $1`) on a column whose plaintext we never store.
 *
 * It is deterministic, so it leaks equality — two users with the same phone share a
 * hash. That is exactly the property we need for a uniqueness constraint, and it is
 * why blind indexes are only used on identifiers, never on low-entropy attributes
 * like gender or diagnosis where a frequency analysis would be trivial.
 *
 * The pepper lives in env, not the database, so a dump of Postgres alone does not
 * let an attacker brute-force the (small) phone-number space.
 */
export function blindIndex(value: string, domain: string): string {
  return createHmac('sha256', env.BLIND_INDEX_PEPPER)
    .update(domain)
    .update('\x00') // domain separation: hmac("ab","c") !== hmac("a","bc")
    .update(normalise(value))
    .digest('hex')
}

/** Non-reversible, salted IP hash for audit logs — correlation without storing PII. */
export function hashIp(ip: string): string {
  return createHmac('sha256', env.IP_HASH_SALT).update(ip).digest('hex').slice(0, 32)
}

/** Constant-time compare for hex/base64 digests of equal expected length. */
export function safeEqual(a: string, b: string): boolean {
  const bufA = Buffer.from(a)
  const bufB = Buffer.from(b)
  if (bufA.length !== bufB.length) return false
  return timingSafeEqual(bufA, bufB)
}

const normalise = (v: string): string => v.trim().toLowerCase().normalize('NFKC')
