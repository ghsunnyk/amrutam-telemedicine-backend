import express from 'express'
import cors from 'cors'
import morgan from 'morgan'

import router from './routes'

import { notFoundHandler } from './errors/notFoundHandler'

const app = express()

app.use(cors())
app.use(morgan('tiny'))
app.use(express.json())
app.use(express.urlencoded({ extended: true }))

app.use('/api/v1', router)

app.use(notFoundHandler)

export default app
