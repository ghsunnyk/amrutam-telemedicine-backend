import type { Server } from 'node:http'
import { env } from './config/env'
import { createApp } from './app'
import { createContainer, type Container } from './container'
import { logger } from './observability/logger'
import { beginDraining } from './routes/health'

/**
 * Graceful shutdown, in the order that matters:
 *
 *   1. Fail readiness. The load balancer stops routing new requests to this pod.
 *   2. Wait one readiness interval so it actually notices — closing the listener
 *      immediately drops requests that were already in flight to us.
 *   3. Stop accepting new connections; let in-flight requests finish.
 *   4. Close the database pool.
 *   5. If any of that takes longer than SHUTDOWN_TIMEOUT_MS, exit non-zero anyway.
 *
 * Skipping step 1 is why deploys show a spike of 502s that nobody can reproduce.
 */
const READINESS_PROPAGATION_MS = 5_000

export async function start(): Promise<{ server: Server; container: Container }> {
  const container = await createContainer()
  const app = createApp(container)

  const server = await new Promise<Server>((resolve, reject) => {
    const s = app.listen(env.PORT, () => resolve(s))
    s.on('error', reject)
  })

  // Slowloris: a client that opens a connection and dribbles headers forever holds a
  // socket. Node's defaults (headersTimeout 60s, requestTimeout 300s) are generous.
  server.headersTimeout = 20_000
  server.requestTimeout = 30_000
  // Must exceed the upstream load balancer's idle timeout, or the LB will reuse a
  // connection we are simultaneously closing and the client sees a 502.
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

    // Hard deadline. If the graceful path hangs (a request stuck on a lock), we still
    // exit — the orchestrator is about to SIGKILL us anyway, and exiting cleanly here
    // at least lets us log why.
    const killTimer = setTimeout(() => {
      logger.fatal('Graceful shutdown timed out — forcing exit')
      process.exit(1)
    }, env.SHUTDOWN_TIMEOUT_MS)
    killTimer.unref()

    try {
      beginDraining()
      await sleep(READINESS_PROPAGATION_MS)

      await new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()))
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

  /**
   * An uncaught exception means some code path threw where nobody could catch it. The
   * process is now in an unknown state — a half-applied transaction, a released lock
   * we still think we hold. Log and die; the orchestrator restarts us clean.
   * Continuing is how a crash becomes data corruption.
   */
  process.on('uncaughtException', (err) => {
    logger.fatal({ err }, 'Uncaught exception — exiting')
    process.exit(1)
  })

  process.on('unhandledRejection', (reason) => {
    logger.fatal({ err: reason }, 'Unhandled promise rejection — exiting')
    process.exit(1)
  })
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))
