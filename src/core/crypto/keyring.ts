import type { PrismaClient } from '../../generated/prisma/client'
import { createLogger } from '../../observability/logger'
import { InternalError } from '../errors'
import {
  type DataKey,
  type DbBytes,
  decrypt,
  decryptToString,
  encrypt,
  fromDbBytes,
  generateDataKey,
  readKeyVersion,
  toDbBytes,
  unwrapDataKey,
  wrapDataKey,
} from './encryption'
import { env } from '../../config/env'

const log = createLogger('keyring')

/**
 * Holds the unwrapped DEKs in memory and hands them to callers that need to
 * encrypt or decrypt a column.
 *
 * Design notes:
 *  - Unwrapped keys are cached for the process lifetime. Re-reading + unwrapping on
 *    every field access would put a KMS call on the hot path of every consultation read.
 *  - Only one key is ACTIVE at a time; it is the one new writes use. RETIRED and
 *    COMPROMISED keys stay loaded so old rows still decrypt while the re-encryption
 *    job works through them.
 *  - `rotate()` is safe to call concurrently: the unique constraint on `version`
 *    means exactly one caller wins and the loser simply reloads.
 */
export class Keyring {
  private keys = new Map<number, DataKey>()
  private activeVersion: number | null = null
  private loaded = false

  constructor(private readonly prisma: PrismaClient) {}

  /** Called once at boot. Bootstraps the very first DEK on an empty database. */
  async load(): Promise<void> {
    const rows = await this.prisma.encryptionKey.findMany({ orderBy: { version: 'asc' } })

    if (rows.length === 0) {
      log.warn('No encryption keys found — bootstrapping the first data key')
      await this.createKey(1)
      return this.load()
    }

    this.keys.clear()
    for (const row of rows) {
      try {
        this.keys.set(row.version, {
          version: row.version,
          key: unwrapDataKey(fromDbBytes(row.wrappedDek)),
        })
      } catch (cause) {
        // Almost always "the KEK in env is not the KEK that wrapped this row".
        throw new InternalError(
          `Cannot unwrap data key v${row.version} — is ENCRYPTION_KEK correct for kek_id '${row.kekId}'?`,
          cause
        )
      }
    }

    const active = rows.filter((r) => r.status === 'ACTIVE')
    if (active.length === 0) throw new InternalError('No ACTIVE encryption key; refusing to start')
    if (active.length > 1) {
      throw new InternalError(
        `${active.length} ACTIVE encryption keys; exactly one must be active. Fix encryption_keys before starting.`
      )
    }

    this.activeVersion = active[0]!.version
    this.loaded = true
    log.info({ versions: rows.map((r) => r.version), active: this.activeVersion }, 'Keyring loaded')
  }

  /** The key new ciphertext is written under. */
  private active(): DataKey {
    if (!this.loaded || this.activeVersion === null) throw new InternalError('Keyring not loaded')
    const key = this.keys.get(this.activeVersion)
    if (!key) throw new InternalError(`Active key v${this.activeVersion} missing from keyring`)
    return key
  }

  private forVersion(version: number): DataKey {
    const key = this.keys.get(version)
    if (!key) {
      throw new InternalError(`Ciphertext references unknown key version ${version}; cannot decrypt`)
    }
    return key
  }

  /** Encrypt under the active key. `aad` binds the blob to its row + column. */
  encryptField(plaintext: string, aad?: string): DbBytes {
    return toDbBytes(encrypt(plaintext, this.active(), aad))
  }

  /** Decrypt, selecting the key version recorded inside the blob itself. */
  decryptField(blob: Uint8Array, aad?: string): string {
    const buf = fromDbBytes(blob)
    return decryptToString(buf, this.forVersion(readKeyVersion(buf)), aad)
  }

  decryptFieldRaw(blob: Uint8Array, aad?: string): Buffer {
    const buf = fromDbBytes(blob)
    return decrypt(buf, this.forVersion(readKeyVersion(buf)), aad)
  }

  /** Optional-field convenience — most encrypted columns are nullable. */
  encryptOptional(plaintext: string | null | undefined, aad?: string): DbBytes | null {
    return plaintext == null || plaintext === '' ? null : this.encryptField(plaintext, aad)
  }

  decryptOptional(blob: Uint8Array | null | undefined, aad?: string): string | null {
    return blob == null ? null : this.decryptField(blob, aad)
  }

  /** True when a blob is not encrypted under the active key — the rotation job's filter. */
  needsReencryption(blob: Uint8Array): boolean {
    return readKeyVersion(fromDbBytes(blob)) !== this.activeVersion
  }

  /**
   * Mint a new DEK, mark it ACTIVE, retire the previous one. Old rows keep
   * decrypting under the retired key until `jobs/reencrypt` has walked them.
   */
  async rotate(): Promise<number> {
    const current = await this.prisma.encryptionKey.findFirst({
      where: { status: 'ACTIVE' },
      orderBy: { version: 'desc' },
    })
    const nextVersion = (current?.version ?? 0) + 1

    await this.prisma.$transaction(async (tx) => {
      if (current) {
        await tx.encryptionKey.update({
          where: { id: current.id },
          data: { status: 'RETIRED', retiredAt: new Date() },
        })
      }
      await tx.encryptionKey.create({
        data: {
          version: nextVersion,
          wrappedDek: toDbBytes(wrapDataKey(generateDataKey())),
          kekId: env.ENCRYPTION_KEK_ID,
          status: 'ACTIVE',
        },
      })
    })

    await this.load()
    log.warn({ version: nextVersion }, 'Data encryption key rotated')
    return nextVersion
  }

  private async createKey(version: number): Promise<void> {
    await this.prisma.encryptionKey.create({
      data: {
        version,
        wrappedDek: toDbBytes(wrapDataKey(generateDataKey())),
        kekId: env.ENCRYPTION_KEK_ID,
        status: 'ACTIVE',
      },
    })
  }
}

/** Canonical AAD for a column, so a ciphertext cannot be moved between rows. */
export const fieldAad = (model: string, id: string, column: string): string =>
  `${model}:${id}:${column}`
