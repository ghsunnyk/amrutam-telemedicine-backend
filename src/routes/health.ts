import { Router } from 'express'
import type { Container } from '../container'
import { createLogger } from '../observability/logger'

const log = createLogger('health')

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
      await container.db.$queryRaw`SELECT 1`
      res.json({ status: 'ok', checks: { database: 'ok' } })
    } catch (err) {
      log.error({ err }, 'Readiness check failed')
      res.status(503).json({ status: 'unavailable', checks: { database: 'failed' } })
    }
  })

  router.get('/', (_req, res) => {
    res.json({ status: draining ? 'draining' : 'ok' })
  })

  return router
}
