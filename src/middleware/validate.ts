import type { NextFunction, Request, RequestHandler, Response } from 'express'
import { type ZodError, type ZodType } from 'zod'
import { ValidationError } from '../core/errors'

type Source = 'body' | 'query' | 'params'

/**
 * Parse-don't-validate: the handler receives the *parsed* value, so coercions and
 * defaults from the schema are what the rest of the code sees. Unknown keys are
 * rejected by the schemas themselves (`.strict()`), which is the mass-assignment
 * defence — a `role` field smuggled into a registration body is a 400, not a silent
 * privilege escalation.
 */
export function validate<T>(schema: ZodType<T>, source: Source = 'body'): RequestHandler {
  return (req: Request, _res: Response, next: NextFunction) => {
    const result = schema.safeParse(req[source])

    if (!result.success) {
      return next(new ValidationError('Request validation failed', formatZodError(result.error)))
    }

    // Express 5 makes `req.query` a getter. Assigning to it throws, so parsed query
    // values are stashed where `validatedQuery` can find them.
    if (source === 'query') {
      Object.defineProperty(req, 'validatedQuery', { value: result.data, writable: false, configurable: true })
    } else {
      req[source] = result.data as never
    }

    next()
  }
}

/** Typed accessor for whatever `validate(schema, 'query')` produced. */
export const validatedQuery = <T>(req: Request): T =>
  (req as unknown as { validatedQuery: T }).validatedQuery

/**
 * Flatten Zod issues into `{ field: [messages] }`.
 *
 * Only the path and the message escape — never the received value. Echoing input back
 * is how a validation error becomes a reflected-XSS vector in a client that renders
 * error details, and how a rejected password ends up in an error-tracking dashboard.
 */
export function formatZodError(error: ZodError): { fields: Record<string, string[]> } {
  const fields: Record<string, string[]> = {}

  for (const issue of error.issues) {
    const key = issue.path.length ? issue.path.join('.') : '_'
    ;(fields[key] ??= []).push(issue.message)
  }

  return { fields }
}
