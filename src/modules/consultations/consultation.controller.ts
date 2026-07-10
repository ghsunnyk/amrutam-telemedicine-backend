import type { Request, Response } from 'express'
import { UnauthenticatedError } from '../../core/errors'
import { sendSuccess } from '../../core/http'
import type {
  BookConsultationInput,
  CancelConsultationInput,
  CompleteConsultationInput,
} from './consultation.schemas'
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

  start = async (req: Request, res: Response): Promise<void> => {
    await this.consultations.start(requireAuth(req).userId, getConsultationId(req))
    res.status(204).end()
  }

  complete = async (req: Request, res: Response): Promise<void> => {
    await this.consultations.complete(
      requireAuth(req).userId,
      getConsultationId(req),
      req.body as CompleteConsultationInput
    )
    res.status(204).end()
  }

  cancel = async (req: Request, res: Response): Promise<void> => {
    const auth = requireAuth(req)
    const { reason } = req.body as CancelConsultationInput
    await this.consultations.cancel(auth.userId, auth.role, getConsultationId(req), reason)
    res.status(204).end()
  }

  markNoShow = async (req: Request, res: Response): Promise<void> => {
    await this.consultations.markNoShow(requireAuth(req).userId, getConsultationId(req))
    res.status(204).end()
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
