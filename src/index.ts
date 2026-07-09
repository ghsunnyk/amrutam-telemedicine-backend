import app from './app'
import { PORT } from './utils/env'
import { info } from './utils/logger'

app.listen(PORT, () => {
  info(`🚀 Server running at http://localhost:${PORT}`)
})
