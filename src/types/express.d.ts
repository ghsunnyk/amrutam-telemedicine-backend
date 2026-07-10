import type { Role } from '../generated/prisma/enums'

export interface AuthContext {
  userId: string
  role: Role
  sessionId: string
  mfaSatisfied: boolean
  issuedAt: number
}

declare global {
  namespace Express {
    interface Request {
      auth?: AuthContext
      requestId: string
      idempotency?: { key: string; scope: string }
    }
  }
}

export {}
