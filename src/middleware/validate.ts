import type { NextFunction, Request, RequestHandler, Response } from 'express'
import { type ZodError, type ZodType } from 'zod'
import { ValidationError } from '../core/errors'

type Source = 'body' | 'query' | 'params'

export function validate<T>(schema: ZodType<T>, source: Source = 'body'): RequestHandler {
  return (req: Request, _res: Response, next: NextFunction) => {
    const result = schema.safeParse(req[source])

    if (!result.success) {
      return next(new ValidationError('Request validation failed', formatZodError(result.error)))
    }

    if (source === 'query') {
      Object.defineProperty(req, 'validatedQuery', {
        value: result.data,
        writable: false,
        configurable: true,
      })
    } else {
      req[source] = result.data as never
    }

    next()
  }
}

export const validatedQuery = <T>(req: Request): T =>
  (req as unknown as { validatedQuery: T }).validatedQuery

export function formatZodError(error: ZodError): { fields: Record<string, string[]> } {
  const fields: Record<string, string[]> = {}

  for (const issue of error.issues) {
    const key = issue.path.length ? issue.path.join('.') : '_'
    ;(fields[key] ??= []).push(issue.message)
  }

  return { fields }
}
