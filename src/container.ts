import type { Pool } from 'pg'
import { Keyring } from './core/crypto/keyring'
import { initPasswordHasher } from './core/crypto/password'
import { createPool, createPrismaClient, observePool, type Db } from './db/prisma'
import { AuditService } from './modules/audit/audit.service'
import { AuthController } from './modules/auth/auth.controller'
import { AuthService } from './modules/auth/auth.service'
import { MfaService } from './modules/auth/mfa.service'
import { TokenService } from './modules/auth/token.service'
import { DoctorController } from './modules/doctors/doctor.controller'
import { DoctorService } from './modules/doctors/doctor.service'
import { createLogger } from './observability/logger'

const log = createLogger('container')

export interface Container {
  pool: Pool
  db: Db
  keyring: Keyring
  audit: AuditService
  tokens: TokenService
  mfa: MfaService
  auth: AuthService
  authController: AuthController
  doctorController: DoctorController
  shutdown: () => Promise<void>
}

export interface ContainerOptions {
  databaseUrl?: string
}

export async function createContainer(options: ContainerOptions = {}): Promise<Container> {
  const pool = createPool(options.databaseUrl)
  const db = createPrismaClient(pool)

  const stopPoolObserver = observePool(pool)

  const keyring = new Keyring(db)
  await keyring.load()

  await initPasswordHasher()

  const audit = new AuditService(db)
  const tokens = new TokenService(db)
  const mfa = new MfaService(db, keyring, audit)
  const auth = new AuthService(db, tokens, mfa, keyring, audit)
  const doctors = new DoctorService(db, keyring, audit)

  const authController = new AuthController(auth, mfa)
  const doctorController = new DoctorController(doctors)

  const shutdown = async (): Promise<void> => {
    stopPoolObserver()
    await db.$disconnect()
    await pool.end()
    log.info('Database connections closed')
  }

  return { pool, db, keyring, audit, tokens, mfa, auth, authController, doctorController, shutdown }
}
