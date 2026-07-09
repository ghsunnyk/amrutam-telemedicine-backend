import { Router } from 'express'

const router = Router()

router.get('/', (_req, res) => {
  res.json({ message: 'Welcome to the Amrutam Telemedicine API' })
})

router.get('/health', (_req, res) => {
  res.json({ status: 'ok' })
})

export default router
