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
import { createHealthRouter } from './routes/health'

/**
 * The middleware stack, in the order it runs. Each layer assumes the ones above it
 * have run, so the order is part of the contract:
 *
 *   1. trust proxy       — makes `req.ip` mean something
 *   2. helmet            — response headers, applied even to error responses
 *   3. requestContext    — correlation ids, before anything that logs
 *   4. httpObservability — starts the latency timer before any work happens
 *   5. cors              — reject cross-origin before parsing a body
 *   6. body parsers      — bounded; an unbounded parser is a memory DoS
 *   7. global rateLimit  — after we know the caller, before we do real work
 *   8. routes
 *   9. notFound → errorHandler
 */
export function createApp(container: Container): Express {
  const app = express()

  // Exactly the number of proxies we run. `trust proxy: true` would let any client
  // set X-Forwarded-For and impersonate an arbitrary IP, defeating IP rate limiting
  // and poisoning the audit log.
  app.set('trust proxy', env.TRUST_PROXY_HOPS)

  // Advertising the framework is free reconnaissance.
  app.disable('x-powered-by')
  // Reject the `?a[b]=c` object syntax we never use, and its prototype-pollution surface.
  app.set('query parser', 'simple')
  app.set('etag', false)

  app.use(
    helmet({
      // This is a JSON API: nothing it returns should ever be rendered as a document.
      contentSecurityPolicy: {
        directives: { 'default-src': ["'none'"], 'frame-ancestors': ["'none'"] },
      },
      // Two years, preloadable. A TLS downgrade against a health API is not acceptable.
      hsts: isProduction ? { maxAge: 63_072_000, includeSubDomains: true, preload: true } : false,
      referrerPolicy: { policy: 'no-referrer' },
      crossOriginResourcePolicy: { policy: 'same-site' },
    })
  )

  app.use(requestContext)
  app.use(httpObservability())

  app.use(
    cors({
      // A function, not an array. `origin: [...]` looks equivalent but reflects the
      // request's Origin on match, and we want an explicit allow/deny we can reason about.
      origin(origin, callback) {
        if (!origin) return callback(null, false) // same-origin or server-to-server
        callback(null, env.CORS_ORIGINS.includes(origin))
      },
      credentials: true,
      methods: ['GET', 'POST', 'PATCH', 'PUT', 'DELETE'],
      allowedHeaders: ['Content-Type', 'Authorization', 'Idempotency-Key', 'X-Request-Id', 'traceparent'],
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

  // `limit` is the single most effective anti-DoS knob in an Express app. 100kb is far
  // more than any request here needs — a prescription with 50 line items is ~8kb.
  app.use(express.json({ limit: env.BODY_LIMIT, strict: true }))
  app.use(express.urlencoded({ extended: false, limit: env.BODY_LIMIT }))
  app.use(compression())

  // Health and metrics must answer when the database is down and when the caller has
  // exhausted their quota, so they are mounted above the global limiter.
  app.use('/health', createHealthRouter(container))
  app.get('/metrics', metricsHandler())

  app.use(rateLimit(container.db, policies.global))

  app.use('/api/v1/auth', createAuthRouter(container))

  app.get('/api/v1', (_req, res) => {
    res.json({ success: true, data: { name: 'Amrutam Telemedicine API', version: 'v1' } })
  })

  app.use(notFoundHandler)
  app.use(errorHandler)

  return app
}
