import type { NextFunction, Request, RequestHandler, Response } from 'express'
import { timingSafeEqual } from 'node:crypto'
import { env } from '../config/env'
import { logger } from '../observability/logger'
import { httpRequestDuration, httpRequestsInFlight, httpRequestsTotal, registry } from '../observability/metrics'
import { getContext } from '../observability/requestContext'

/** Never log or count these — they are health probes and would drown the signal. */
const QUIET_PATHS = new Set(['/health', '/health/live', '/health/ready', '/metrics'])

/**
 * Resolve the *route pattern*, not the concrete path.
 *
 * `req.route.path` is only populated after routing, which is why this reads it at
 * response time. Falling back to `req.path` for unmatched requests would let an
 * attacker mint unbounded time series by hitting `/does-not-exist-<random>`, so
 * unmatched requests are bucketed under a single label.
 */
function routeLabel(req: Request): string {
  const route = (req as Request & { route?: { path?: string } }).route?.path
  if (!route) return req.route ? req.path : '__unmatched__'

  // `req.baseUrl` carries the mount prefix (`/api/v1/auth`), `route` the leaf (`/login`).
  return `${req.baseUrl}${route}`.replace(/\/$/, '') || '/'
}

/**
 * One access-log line and one metric observation per request, emitted on `finish`.
 *
 * `finish` fires when the response is handed to the kernel. `close` fires if the
 * client hung up first — we count those too, because a client that gives up at 30s is
 * exactly the request we most want in the latency histogram, and dropping it makes
 * p95 look healthy while users see timeouts.
 */
export function httpObservability(): RequestHandler {
  return (req: Request, res: Response, next: NextFunction) => {
    if (QUIET_PATHS.has(req.path)) return next()

    const start = process.hrtime.bigint()
    httpRequestsInFlight.inc({ method: req.method })

    let settled = false
    const record = (aborted: boolean) => {
      if (settled) return
      settled = true

      const durationSeconds = Number(process.hrtime.bigint() - start) / 1e9
      const labels = {
        method: req.method,
        route: routeLabel(req),
        // A client-aborted request never got a status; 499 is nginx's convention.
        status_code: String(aborted ? 499 : res.statusCode),
      }

      httpRequestsInFlight.dec({ method: req.method })
      httpRequestDuration.observe(labels, durationSeconds)
      httpRequestsTotal.inc(labels)

      const ctx = getContext()
      const level = aborted ? 'warn' : res.statusCode >= 500 ? 'error' : res.statusCode >= 400 ? 'warn' : 'info'

      logger[level](
        {
          method: req.method,
          path: req.path,
          route: labels.route,
          status: aborted ? 499 : res.statusCode,
          durationMs: Math.round(durationSeconds * 1e6) / 1e3,
          ip: ctx?.ip, // already hashed in requestContext
          userAgent: req.get('user-agent'),
          contentLength: res.getHeader('content-length'),
        },
        aborted ? 'request aborted by client' : 'request completed'
      )
    }

    res.on('finish', () => record(false))
    res.on('close', () => record(!res.writableFinished))

    next()
  }
}

/**
 * `GET /metrics`.
 *
 * Guarded by a bearer token in production (enforced by `env.ts`, which refuses to
 * start otherwise). An open metrics endpoint hands an attacker your route table, your
 * traffic volumes, your error rates and your deploy cadence — it is reconnaissance,
 * served as JSON. Compared with `timingSafeEqual` so the token cannot be recovered
 * byte-by-byte.
 */
export function metricsHandler(): RequestHandler {
  return async (req: Request, res: Response) => {
    if (!env.METRICS_ENABLED) {
      res.status(404).end()
      return
    }

    if (env.METRICS_AUTH_TOKEN && !hasValidMetricsToken(req)) {
      res.setHeader('WWW-Authenticate', 'Bearer realm="metrics"')
      res.status(401).end()
      return
    }

    res.setHeader('Content-Type', registry.contentType)
    res.end(await registry.metrics())
  }
}

function hasValidMetricsToken(req: Request): boolean {
  const header = req.get('authorization')
  const presented = header?.startsWith('Bearer ') ? header.slice(7) : null
  if (!presented) return false

  const a = Buffer.from(presented)
  const b = Buffer.from(env.METRICS_AUTH_TOKEN!)
  return a.length === b.length && timingSafeEqual(a, b)
}
