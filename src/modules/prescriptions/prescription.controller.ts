import type { Request, Response } from 'express'
import { UnauthenticatedError } from '../../core/errors'
import { sendSuccess } from '../../core/http'
import type {
  CreatePrescriptionInput,
  RevokePrescriptionInput,
  UpdatePrescriptionInput,
} from './prescription.schemas'
import type { PrescriptionService } from './prescription.service'

export class PrescriptionController {
  constructor(private readonly prescriptions: PrescriptionService) {}

  create = async (req: Request, res: Response): Promise<void> => {
    const result = await this.prescriptions.create(
      requireAuth(req).userId,
      getConsultationId(req),
      req.body as CreatePrescriptionInput
    )
    sendSuccess(res, result, { status: 201 })
  }

  update = async (req: Request, res: Response): Promise<void> => {
    await this.prescriptions.update(
      requireAuth(req).userId,
      getPrescriptionId(req),
      req.body as UpdatePrescriptionInput
    )
    res.status(204).end()
  }

  issue = async (req: Request, res: Response): Promise<void> => {
    await this.prescriptions.issue(requireAuth(req).userId, getPrescriptionId(req))
    res.status(204).end()
  }

  revoke = async (req: Request, res: Response): Promise<void> => {
    const { reason } = req.body as RevokePrescriptionInput
    await this.prescriptions.revoke(requireAuth(req).userId, getPrescriptionId(req), reason)
    res.status(204).end()
  }

  getByConsultation = async (req: Request, res: Response): Promise<void> => {
    const auth = requireAuth(req)
    const prescription = await this.prescriptions.getByConsultation(
      auth.userId,
      auth.role,
      getConsultationId(req)
    )
    sendSuccess(res, prescription)
  }
}

function getConsultationId(req: Request): string {
  const { consultationId } = req.params
  if (typeof consultationId !== 'string') throw new Error('Invalid consultationId')
  return consultationId
}

function getPrescriptionId(req: Request): string {
  const { prescriptionId } = req.params
  if (typeof prescriptionId !== 'string') throw new Error('Invalid prescriptionId')
  return prescriptionId
}

function requireAuth(req: Request): NonNullable<Request['auth']> {
  if (!req.auth) throw new UnauthenticatedError()
  return req.auth
}
