import type { NextFunction, Request, RequestHandler, Response } from 'express'
import { timingSafeEqual } from 'node:crypto'
import { env } from '../config/env'
import { logger } from '../observability/logger'
import {
  httpRequestDuration,
  httpRequestsInFlight,
  httpRequestsTotal,
  registry,
} from '../observability/metrics'
import { getContext } from '../observability/requestContext'

const QUIET_PATHS = new Set(['/health', '/health/live', '/health/ready', '/metrics'])

function routeLabel(req: Request): string {
  const route = (req as Request & { route?: { path?: string } }).route?.path
  if (!route) return req.route ? req.path : '__unmatched__'

  return `${req.baseUrl}${route}`.replace(/\/$/, '') || '/'
}

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
        status_code: String(aborted ? 499 : res.statusCode),
      }

      httpRequestsInFlight.dec({ method: req.method })
      httpRequestDuration.observe(labels, durationSeconds)
      httpRequestsTotal.inc(labels)

      const ctx = getContext()
      const level = aborted
        ? 'warn'
        : res.statusCode >= 500
          ? 'error'
          : res.statusCode >= 400
            ? 'warn'
            : 'info'

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
