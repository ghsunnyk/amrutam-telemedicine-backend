import { AsyncLocalStorage } from 'node:async_hooks'

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

export function setContext(patch: Partial<RequestContext>): void {
  const store = storage.getStore()
  if (store) Object.assign(store, patch)
}
