import type { Pool } from 'pg'
import { env } from './config/env'
import { Keyring } from './core/crypto/keyring'
import { initPasswordHasher } from './core/crypto/password'
import { createPool, createPrismaClient, observePool, type Db } from './db/prisma'
import { AuditService } from './modules/audit/audit.service'
import { AuthController } from './modules/auth/auth.controller'
import { AuthService } from './modules/auth/auth.service'
import { MfaService } from './modules/auth/mfa.service'
import { TokenService } from './modules/auth/token.service'
import { AvailabilityController } from './modules/availability/availability.controller'
import { AvailabilityService } from './modules/availability/availability.service'
import { ConsultationController } from './modules/consultations/consultation.controller'
import { ConsultationService } from './modules/consultations/consultation.service'
import { DoctorController } from './modules/doctors/doctor.controller'
import { DoctorService } from './modules/doctors/doctor.service'
import { PaymentController } from './modules/payments/payment.controller'
import { PaymentService } from './modules/payments/payment.service'
import { createLogger } from './observability/logger'
import { createWorker, reschedule, scheduleRecurringJobs } from './workers'
import type { JobQueue } from './workers/jobQueue'

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
  doctors: DoctorService
  doctorController: DoctorController
  availability: AvailabilityService
  availabilityController: AvailabilityController
  payments: PaymentService
  paymentController: PaymentController
  consultations: ConsultationService
  consultationController: ConsultationController
  worker: JobQueue | null
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
  const authController = new AuthController(auth, mfa)

  const doctors = new DoctorService(db, keyring, audit)
  const doctorController = new DoctorController(doctors)

  const availability = new AvailabilityService(db, audit)
  const availabilityController = new AvailabilityController(availability)

  const worker = env.WORKER_ENABLED ? createWorker(db) : null

  const payments = new PaymentService(db, audit, worker)
  const paymentController = new PaymentController(payments)

  const consultations = new ConsultationService(db, keyring, audit, payments)
  const consultationController = new ConsultationController(consultations)

  if (worker) {
    worker.start()
    await scheduleRecurringJobs(worker)
    await reschedule(worker)
  }

  const shutdown = async (): Promise<void> => {
    if (worker) await worker.stop()
    stopPoolObserver()
    await db.$disconnect()
    await pool.end()
    log.info('Database connections closed')
  }

  return {
    pool,
    db,
    keyring,
    audit,
    tokens,
    mfa,
    auth,
    authController,
    doctors,
    doctorController,
    availability,
    availabilityController,
    payments,
    paymentController,
    consultations,
    consultationController,
    worker,
    shutdown,
  }
}
