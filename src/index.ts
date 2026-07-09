import { logger } from './observability/logger'
import { start } from './server'

/**
 * Entry point. Kept trivial on purpose: everything worth testing lives in `createApp`
 * and `createContainer`, both of which an integration test constructs directly
 * without ever binding a port.
 */
start().catch((err: unknown) => {
  logger.fatal({ err }, 'Failed to start server')
  process.exit(1)
})
