import { Request, Response } from 'express'

export function notFoundHandler(req: Request, res: Response) {
  res.status(404).json({
    success: false,
    code: 'NOT_FOUND',
    message: `Cannot ${req.method} ${req.originalUrl}`,
  })
}
