import type { Pool } from 'pg'
import { Keyring } from './core/crypto/keyring'
import { initPasswordHasher } from './core/crypto/password'
import { createPool, createPrismaClient, observePool, type Db } from './db/prisma'
import { AuditService } from './modules/audit/audit.service'
import { AuthController } from './modules/auth/auth.controller'
import { AuthService } from './modules/auth/auth.service'
import { MfaService } from './modules/auth/mfa.service'
import { TokenService } from './modules/auth/token.service'
import { createLogger } from './observability/logger'

const log = createLogger('container')

/**
 * Dependency injection by explicit composition.
 *
 * No decorators, no reflect-metadata, no string tokens. Services take their
 * collaborators as constructor arguments and this function is the single place they
 * are wired together — so the dependency graph is a function you can read, the
 * compiler checks it, and a test can substitute any node by passing a different
 * object. A framework container buys nothing here except a runtime failure mode.
 */
export interface Container {
  pool: Pool
  db: Db
  keyring: Keyring
  audit: AuditService
  tokens: TokenService
  mfa: MfaService
  auth: AuthService
  authController: AuthController
  shutdown: () => Promise<void>
}

export interface ContainerOptions {
  /** Override the connection string — integration tests point at a scratch database. */
  databaseUrl?: string
}

export async function createContainer(options: ContainerOptions = {}): Promise<Container> {
  const pool = createPool(options.databaseUrl)
  const db = createPrismaClient(pool)

  const stopPoolObserver = observePool(pool)

  // Order matters: the keyring reads (and on an empty database, bootstraps) the DEK
  // before any service can encrypt a field. Failing here is fatal and should be —
  // starting with a broken keyring means writing rows nobody can ever decrypt.
  const keyring = new Keyring(db)
  await keyring.load()

  // Warms the dummy hash used to equalise login timing for unknown accounts.
  await initPasswordHasher()

  const audit = new AuditService(db)
  const tokens = new TokenService(db)
  const mfa = new MfaService(db, keyring, audit)
  const auth = new AuthService(db, tokens, mfa, keyring, audit)

  const authController = new AuthController(auth, mfa)

  const shutdown = async (): Promise<void> => {
    stopPoolObserver()
    await db.$disconnect()
    await pool.end()
    log.info('Database connections closed')
  }

  return { pool, db, keyring, audit, tokens, mfa, auth, authController, shutdown }
}
