import type { Request, Response } from 'express'
import { UnauthenticatedError } from '../../core/errors'
import { sendSuccess } from '../../core/http'
import { validatedQuery } from '../../middleware/validate'
import type {
  CreateAvailabilityRuleInput,
  GenerateSlotsInput,
  ListSlotsQuery,
  ReleaseHoldInput,
} from './availability.schemas'
import type { AvailabilityService } from './availability.service'

export class AvailabilityController {
  constructor(private readonly availability: AvailabilityService) {}

  createRule = async (req: Request, res: Response): Promise<void> => {
    const result = await this.availability.createRule(
      requireAuth(req).userId,
      req.body as CreateAvailabilityRuleInput
    )
    sendSuccess(res, result, { status: 201 })
  }

  deleteRule = async (req: Request, res: Response): Promise<void> => {
    await this.availability.deleteRule(requireAuth(req).userId, getSlotId(req))
    res.status(204).end()
  }

  generateSlots = async (req: Request, res: Response): Promise<void> => {
    const { horizonDays } = req.body as GenerateSlotsInput
    const result = await this.availability.generateSlots(requireAuth(req).userId, horizonDays)
    sendSuccess(res, result)
  }

  listSlots = async (req: Request, res: Response): Promise<void> => {
    const query = validatedQuery<ListSlotsQuery>(req)
    const slots = await this.availability.listAvailableSlots(getSlotId(req), query)
    sendSuccess(res, slots)
  }

  holdSlot = async (req: Request, res: Response): Promise<void> => {
    const held = await this.availability.holdSlot(requireAuth(req).userId, getSlotId(req))
    sendSuccess(res, held, { status: 201 })
  }

  releaseHold = async (req: Request, res: Response): Promise<void> => {
    const { holdToken } = req.body as ReleaseHoldInput
    await this.availability.releaseHold(requireAuth(req).userId, getSlotId(req), holdToken)
    res.status(204).end()
  }
}

function getSlotId(req: Request): string {
  const { slotId } = req.params
  if (typeof slotId !== 'string') throw new Error('Invalid slotId')
  return slotId
}

function requireAuth(req: Request): NonNullable<Request['auth']> {
  if (!req.auth) throw new UnauthenticatedError()
  return req.auth
}
