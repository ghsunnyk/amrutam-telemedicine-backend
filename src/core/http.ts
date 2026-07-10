import type { NextFunction, Request, RequestHandler, Response } from 'express'

export interface SuccessBody<T> {
  success: true
  data: T
  meta?: Record<string, unknown>
}

export interface ErrorBody {
  success: false
  error: {
    code: string
    message: string
    details?: unknown
  }
  requestId?: string
}

export function sendSuccess<T>(
  res: Response,
  data: T,
  options: { status?: number; meta?: Record<string, unknown> } = {}
): void {
  const body: SuccessBody<T> = { success: true, data }
  if (options.meta) body.meta = options.meta
  res.status(options.status ?? 200).json(body)
}

export const asyncHandler =
  <Req extends Request = Request>(
    fn: (req: Req, res: Response, next: NextFunction) => Promise<unknown>
  ): RequestHandler =>
  (req, res, next) => {
    void Promise.resolve(fn(req as Req, res, next)).catch(next)
  }

export interface Paginated<T> {
  items: T[]
  nextCursor: string | null
  hasMore: boolean
}

export const encodeCursor = (value: Record<string, unknown>): string =>
  Buffer.from(JSON.stringify(value), 'utf8').toString('base64url')

export function decodeCursor<T = Record<string, unknown>>(cursor: string): T | null {
  try {
    return JSON.parse(Buffer.from(cursor, 'base64url').toString('utf8')) as T
  } catch {
    return null
  }
}
