import type { Request, Response } from 'express'
import { UnauthenticatedError } from '../../core/errors'
import { sendSuccess } from '../../core/http'
import type { RefundPaymentInput } from './payment.schemas'
import type { PaymentService } from './payment.service'

export class PaymentController {
  constructor(private readonly payments: PaymentService) {}

  pay = async (req: Request, res: Response): Promise<void> => {
    const receipt = await this.payments.pay(requireAuth(req).userId, getConsultationId(req))
    sendSuccess(res, receipt)
  }

  refund = async (req: Request, res: Response): Promise<void> => {
    const { reason } = req.body as RefundPaymentInput
    await this.payments.refund(requireAuth(req).userId, getConsultationId(req), reason)
    res.status(202).end()
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
