import type { Request, Response } from 'express'
import { UnauthenticatedError } from '../../core/errors'
import { sendSuccess } from '../../core/http'
import type { BookConsultationInput } from './consultation.schemas'
import type { ConsultationService } from './consultation.service'

export class ConsultationController {
  constructor(private readonly consultations: ConsultationService) {}

  book = async (req: Request, res: Response): Promise<void> => {
    const result = await this.consultations.book(
      requireAuth(req).userId,
      req.body as BookConsultationInput
    )
    sendSuccess(res, result, { status: 201 })
  }

  getById = async (req: Request, res: Response): Promise<void> => {
    const auth = requireAuth(req)
    const consultation = await this.consultations.getById(
      auth.userId,
      auth.role,
      getConsultationId(req)
    )
    sendSuccess(res, consultation)
  }
}

function getConsultationId(req: Request): string {
  const { consultationId } = req.params
  if (typeof consultationId !== 'string') throw new Error('Invalid consultationId')
  return consultationId
}

function requireAuth(req: Request): NonNullable<Request['auth']> {
  if (!req.auth) throw new UnauthenticatedError()
  return req.auth
}
