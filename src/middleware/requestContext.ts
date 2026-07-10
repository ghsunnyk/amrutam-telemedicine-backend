import type { NextFunction, Request, Response } from 'express'
import { randomUUID } from 'node:crypto'
import { hashIp } from '../core/crypto/encryption'
import { runWithContext } from '../observability/requestContext'

const SAFE_ID = /^[A-Za-z0-9._-]{8,128}$/

const TRACEPARENT = /^00-([0-9a-f]{32})-([0-9a-f]{16})-[0-9a-f]{2}$/

export function requestContext(req: Request, res: Response, next: NextFunction): void {
  const inbound = req.get('x-request-id')
  const requestId = inbound && SAFE_ID.test(inbound) ? inbound : randomUUID()

  const traceparent = req.get('traceparent')
  const match = traceparent ? TRACEPARENT.exec(traceparent) : null

  req.requestId = requestId
  res.setHeader('x-request-id', requestId)

  runWithContext(
    {
      requestId,
      traceId: match?.[1],
      spanId: match?.[2],
      ip: req.ip ? hashIp(req.ip) : undefined,
      userAgent: req.get('user-agent'),
      method: req.method,
      startedAt: performance.now(),
    },
    () => next()
  )
}
