import type { NextFunction, Request, Response } from 'express'
import { randomUUID } from 'node:crypto'
import { hashIp } from '../core/crypto/encryption'
import { runWithContext } from '../observability/requestContext'

/** Accept an inbound id only if it looks like one — it ends up in logs and headers. */
const SAFE_ID = /^[A-Za-z0-9._-]{8,128}$/

/** W3C traceparent: `00-<32 hex trace-id>-<16 hex span-id>-<2 hex flags>` */
const TRACEPARENT = /^00-([0-9a-f]{32})-([0-9a-f]{16})-[0-9a-f]{2}$/

/**
 * Establishes the AsyncLocalStorage context for the request. Must be mounted before
 * anything that logs, so every line downstream carries the correlation ids.
 */
export function requestContext(req: Request, res: Response, next: NextFunction): void {
  const inbound = req.get('x-request-id')
  const requestId = inbound && SAFE_ID.test(inbound) ? inbound : randomUUID()

  const traceparent = req.get('traceparent')
  const match = traceparent ? TRACEPARENT.exec(traceparent) : null

  req.requestId = requestId
  // Echo it back so a client can quote it in a support ticket.
  res.setHeader('x-request-id', requestId)

  runWithContext(
    {
      requestId,
      traceId: match?.[1],
      spanId: match?.[2],
      // `req.ip` is only trustworthy because `trust proxy` is set to an exact hop
      // count in app.ts. Hashed immediately: raw IPs are personal data under GDPR.
      ip: req.ip ? hashIp(req.ip) : undefined,
      userAgent: req.get('user-agent'),
      method: req.method,
      startedAt: performance.now(),
    },
    () => next()
  )
}
