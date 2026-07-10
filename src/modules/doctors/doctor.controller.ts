import type { Request, Response } from 'express'
import { UnauthenticatedError } from '../../core/errors'
import { sendSuccess } from '../../core/http'
import { validatedQuery } from '../../middleware/validate'
import type {
  ApplyAsDoctorInput,
  RejectDoctorInput,
  SearchDoctorsQuery,
  UpdateDoctorProfileInput,
} from './doctor.schemas'
import type { DoctorService } from './doctor.service'

export class DoctorController {
  constructor(private readonly doctors: DoctorService) {}

  apply = async (req: Request, res: Response): Promise<void> => {
    const result = await this.doctors.applyAsDoctor(
      requireAuth(req).userId,
      req.body as ApplyAsDoctorInput
    )
    sendSuccess(res, result, { status: 201 })
  }

  updateProfile = async (req: Request, res: Response): Promise<void> => {
    await this.doctors.updateProfile(requireAuth(req).userId, req.body as UpdateDoctorProfileInput)
    res.status(204).end()
  }

  verify = async (req: Request, res: Response): Promise<void> => {
    await this.doctors.verify(getDoctorId(req), requireAuth(req).userId)
    res.status(204).end()
  }

  reject = async (req: Request, res: Response): Promise<void> => {
    const { reason } = req.body as RejectDoctorInput
    await this.doctors.reject(getDoctorId(req), requireAuth(req).userId, reason)
    res.status(204).end()
  }

  search = async (req: Request, res: Response): Promise<void> => {
    const query = validatedQuery<SearchDoctorsQuery>(req)
    const result = await this.doctors.search(query)
    sendSuccess(res, result.items, {
      meta: { nextCursor: result.nextCursor, hasMore: result.hasMore },
    })
  }

  getById = async (req: Request, res: Response): Promise<void> => {
    const doctor = await this.doctors.getById(getDoctorId(req))
    sendSuccess(res, doctor)
  }
}

function getDoctorId(req: Request): string {
  const { doctorId } = req.params
  if (typeof doctorId !== 'string') throw new Error('Invalid doctorId')
  return doctorId
}

function requireAuth(req: Request): NonNullable<Request['auth']> {
  if (!req.auth) throw new UnauthenticatedError()
  return req.auth
}
