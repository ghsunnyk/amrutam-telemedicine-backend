import { AsyncLocalStorage } from 'node:async_hooks'

/**
 * Ambient per-request context. Threading a request id through every function
 * signature is noise; an AsyncLocalStorage keeps the logger, the audit service and
 * the metrics layer able to correlate without polluting domain code.
 *
 * Nothing in here is trusted for authorisation — `userId` is set *after* the auth
 * middleware verifies the token, and guards read the verified `req.auth`, not this.
 */
export interface RequestContext {
  requestId: string
  traceId?: string
  spanId?: string
  userId?: string
  userRole?: string
  ip?: string
  userAgent?: string
  method?: string
  route?: string
  startedAt: number
}

const storage = new AsyncLocalStorage<RequestContext>()

export const runWithContext = <T>(ctx: RequestContext, fn: () => T): T => storage.run(ctx, fn)

export const getContext = (): RequestContext | undefined => storage.getStore()

export const getRequestId = (): string | undefined => storage.getStore()?.requestId

/**
 * Mutates the *current* store in place. Used by the auth middleware once the
 * caller's identity is known, so log lines emitted later in the request carry it.
 */
export function setContext(patch: Partial<RequestContext>): void {
  const store = storage.getStore()
  if (store) Object.assign(store, patch)
}
