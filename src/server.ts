import type { Server } from 'node:http'
import { createApp } from './app'
import { env } from './config/env'
import { createContainer, type Container } from './container'
import { logger } from './observability/logger'
import { beginDraining } from './routes/health'

const READINESS_PROPAGATION_MS = 5_000

export async function start(): Promise<{ server: Server; container: Container }> {
  const container = await createContainer()
  const app = createApp(container)

  const server = await new Promise<Server>((resolve, reject) => {
    const s = app.listen(env.PORT, () => resolve(s))
    s.on('error', reject)
  })

  server.headersTimeout = 20_000
  server.requestTimeout = 30_000
  server.keepAliveTimeout = 65_000

  logger.info({ port: env.PORT, env: env.NODE_ENV, pid: process.pid }, 'Server listening')

  installShutdownHandlers(server, container)

  return { server, container }
}

function installShutdownHandlers(server: Server, container: Container): void {
  let shuttingDown = false

  const shutdown = async (signal: string): Promise<void> => {
    if (shuttingDown) {
      logger.warn({ signal }, 'Shutdown already in progress')
      return
    }
    shuttingDown = true
    logger.info({ signal }, 'Shutting down')

    const killTimer = setTimeout(() => {
      logger.fatal('Graceful shutdown timed out — forcing exit')
      process.exit(1)
    }, env.SHUTDOWN_TIMEOUT_MS)
    killTimer.unref()

    try {
      beginDraining()
      await sleep(READINESS_PROPAGATION_MS)

      await new Promise<void>((resolve, reject) => {
        server.close(err => (err ? reject(err) : resolve()))
      })
      logger.info('HTTP server closed')

      await container.shutdown()

      clearTimeout(killTimer)
      logger.info('Shutdown complete')
      process.exit(0)
    } catch (err) {
      logger.error({ err }, 'Error during shutdown')
      process.exit(1)
    }
  }

  process.on('SIGTERM', () => void shutdown('SIGTERM'))
  process.on('SIGINT', () => void shutdown('SIGINT'))

  process.on('uncaughtException', err => {
    logger.fatal({ err }, 'Uncaught exception — exiting')
    process.exit(1)
  })

  process.on('unhandledRejection', reason => {
    logger.fatal({ err: reason }, 'Unhandled promise rejection — exiting')
    process.exit(1)
  })
}

const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms))
