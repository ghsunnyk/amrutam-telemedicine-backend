import compression from 'compression'
import cors from 'cors'
import express, { type Express } from 'express'
import helmet from 'helmet'
import { env, isProduction } from './config/env'
import type { Container } from './container'
import { errorHandler, notFoundHandler } from './middleware/errorHandler'
import { httpObservability, metricsHandler } from './middleware/httpObservability'
import { policies, rateLimit } from './middleware/rateLimit'
import { requestContext } from './middleware/requestContext'
import { createAuthRouter } from './modules/auth/auth.routes'
import { createAvailabilityRouter } from './modules/availability/availability.routes'
import { createConsultationRouter } from './modules/consultations/consultation.routes'
import { createDoctorRouter } from './modules/doctors/doctor.route'
import { createPaymentRouter } from './modules/payments/payment.routes'

import { createHealthRouter } from './routes/health'

export function createApp(container: Container): Express {
  const app = express()

  app.set('trust proxy', env.TRUST_PROXY_HOPS)

  app.disable('x-powered-by')
  app.set('query parser', 'simple')
  app.set('etag', false)

  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: { 'default-src': ["'none'"], 'frame-ancestors': ["'none'"] },
      },
      hsts: isProduction ? { maxAge: 63_072_000, includeSubDomains: true, preload: true } : false,
      referrerPolicy: { policy: 'no-referrer' },
      crossOriginResourcePolicy: { policy: 'same-site' },
    })
  )

  app.use(requestContext)
  app.use(httpObservability())

  app.use(
    cors({
      origin(origin, callback) {
        if (!origin) return callback(null, false)
        callback(null, env.CORS_ORIGINS.includes(origin))
      },
      credentials: true,
      methods: ['GET', 'POST', 'PATCH', 'PUT', 'DELETE'],
      allowedHeaders: [
        'Content-Type',
        'Authorization',
        'Idempotency-Key',
        'X-Request-Id',
        'traceparent',
      ],
      exposedHeaders: [
        'X-Request-Id',
        'RateLimit-Limit',
        'RateLimit-Remaining',
        'Retry-After',
        'Idempotency-Replayed',
      ],
      maxAge: 600,
    })
  )

  app.use(express.json({ limit: env.BODY_LIMIT, strict: true }))
  app.use(express.urlencoded({ extended: false, limit: env.BODY_LIMIT }))
  app.use(compression())

  app.use('/health', createHealthRouter(container))
  app.get('/metrics', metricsHandler())

  app.use(rateLimit(container.db, policies.global))

  app.use('/api/v1/auth', createAuthRouter(container))
  app.use('/api/v1/doctors', createDoctorRouter(container))
  app.use('/api/v1/availability', createAvailabilityRouter(container))
  app.use('/api/v1/consultations', createConsultationRouter(container))
  app.use('/api/v1/consultations', createConsultationRouter(container))
  app.use('/api/v1/consultations', createPaymentRouter(container))

  app.get('/api/v1', (_req, res) => {
    res.json({ success: true, data: { name: 'Amrutam Telemedicine API', version: 'v1' } })
  })

  app.use(notFoundHandler)
  app.use(errorHandler)

  return app
}
