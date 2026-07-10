import type { Request, Response } from 'express'
import { sendSuccess } from '../../core/http'
import { validatedQuery } from '../../middleware/validate'
import type { TimeseriesQuery, TopDoctorsQuery } from './analytics.schemas'
import type { AnalyticsService } from './analytics.service'

export class AnalyticsController {
  constructor(private readonly analytics: AnalyticsService) {}

  overview = async (_req: Request, res: Response): Promise<void> => {
    sendSuccess(res, await this.analytics.overview())
  }

  timeseries = async (req: Request, res: Response): Promise<void> => {
    const { days } = validatedQuery<TimeseriesQuery>(req)
    sendSuccess(res, await this.analytics.consultationsTimeseries(days))
  }

  topDoctors = async (req: Request, res: Response): Promise<void> => {
    const { limit } = validatedQuery<TopDoctorsQuery>(req)
    sendSuccess(res, await this.analytics.topDoctors(limit))
  }
}
