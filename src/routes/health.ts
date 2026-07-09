import { Router } from 'express'
import type { Container } from '../container'
import { createLogger } from '../observability/logger'

const log = createLogger('health')

/**
 * Liveness and readiness are different questions and must not share an endpoint.
 *
 *   /health/live  — "is this process wedged?" Never touches a dependency. If it fails,
 *                   the orchestrator kills the pod. Making it check Postgres would
 *                   turn a database blip into a cluster-wide restart storm.
 *
 *   /health/ready — "should this pod receive traffic?" Checks the dependencies it
 *                   cannot serve without. Failing removes the pod from the load
 *                   balancer; it stays alive and rejoins when the check passes.
 *
 * `draining` is set during graceful shutdown: readiness starts failing immediately, so
 * the load balancer stops sending new requests while in-flight ones finish.
 */
let draining = false

export const beginDraining = (): void => {
  draining = true
}

export function createHealthRouter(container: Container): Router {
  const router = Router()
  const startedAt = Date.now()

  router.get('/live', (_req, res) => {
    res.json({ status: 'ok', uptimeSeconds: Math.floor((Date.now() - startedAt) / 1000) })
  })

  router.get('/ready', async (_req, res) => {
    if (draining) {
      res.status(503).json({ status: 'draining' })
      return
    }

    try {
      // A trivial query, not `$connect()`: we need to know a connection can be checked
      // out of the pool *and* the server answers, which is what a request will need.
      await container.db.$queryRaw`SELECT 1`
      res.json({ status: 'ok', checks: { database: 'ok' } })
    } catch (err) {
      log.error({ err }, 'Readiness check failed')
      res.status(503).json({ status: 'unavailable', checks: { database: 'failed' } })
    }
  })

  // Kept for humans and for the smoke test in CI.
  router.get('/', (_req, res) => {
    res.json({ status: draining ? 'draining' : 'ok' })
  })

  return router
}
