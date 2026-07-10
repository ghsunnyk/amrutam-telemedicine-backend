import { logger } from './observability/logger'
import { start } from './server'

start().catch((err: unknown) => {
  logger.fatal({ err }, 'Failed to start server')
  process.exit(1)
})
