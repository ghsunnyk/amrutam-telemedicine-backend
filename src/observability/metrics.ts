import { Counter, Gauge, Histogram, Registry, collectDefaultMetrics } from 'prom-client'
import { env } from '../config/env'

export const registry = new Registry()

registry.setDefaultLabels({ service: env.OTEL_SERVICE_NAME, env: env.NODE_ENV })

if (env.METRICS_ENABLED) {
  collectDefaultMetrics({ register: registry, prefix: 'amrutam_' })
}

export const httpRequestDuration = new Histogram({
  name: 'amrutam_http_request_duration_seconds',
  help: 'HTTP request latency',
  labelNames: ['method', 'route', 'status_code'] as const,
  buckets: [0.005, 0.01, 0.025, 0.05, 0.1, 0.15, 0.2, 0.3, 0.5, 0.75, 1, 2.5, 5, 10],
  registers: [registry],
})

export const httpRequestsTotal = new Counter({
  name: 'amrutam_http_requests_total',
  help: 'Total HTTP requests',
  labelNames: ['method', 'route', 'status_code'] as const,
  registers: [registry],
})

export const httpRequestsInFlight = new Gauge({
  name: 'amrutam_http_requests_in_flight',
  help: 'In-flight HTTP requests',
  labelNames: ['method'] as const,
  registers: [registry],
})

export const httpErrorsTotal = new Counter({
  name: 'amrutam_http_errors_total',
  help: 'Errors returned to clients, by application error code',
  labelNames: ['code', 'status_code'] as const,
  registers: [registry],
})

export const dbQueryDuration = new Histogram({
  name: 'amrutam_db_query_duration_seconds',
  help: 'Prisma query latency by model and action',
  labelNames: ['model', 'action'] as const,
  buckets: [0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5],
  registers: [registry],
})

export const dbPoolConnections = new Gauge({
  name: 'amrutam_db_pool_connections',
  help: 'Connection pool utilisation',
  labelNames: ['state'] as const, // active | idle
  registers: [registry],
})

export const dbTransactionRetries = new Counter({
  name: 'amrutam_db_transaction_retries_total',
  help: 'Serialisation/deadlock retries, by outcome',
  labelNames: ['outcome'] as const, // retried | exhausted
  registers: [registry],
})

export const authAttemptsTotal = new Counter({
  name: 'amrutam_auth_attempts_total',
  help: 'Authentication attempts',
  labelNames: ['event', 'outcome'] as const, // event: login|refresh|mfa|register
  registers: [registry],
})

export const authTokenRefreshReuseTotal = new Counter({
  name: 'amrutam_auth_refresh_reuse_detected_total',
  help: 'Refresh-token reuse detections (a spike means token theft — page someone)',
  registers: [registry],
})

export const bookingAttemptsTotal = new Counter({
  name: 'amrutam_booking_attempts_total',
  help: 'Slot booking attempts',
  labelNames: ['outcome'] as const,
  registers: [registry],
})

export const bookingSlotContentionTotal = new Counter({
  name: 'amrutam_booking_slot_contention_total',
  help: 'Bookings that lost the race for a slot',
  registers: [registry],
})

export const consultationsTotal = new Counter({
  name: 'amrutam_consultations_total',
  help: 'Consultation lifecycle transitions',
  labelNames: ['status'] as const,
  registers: [registry],
})

export const paymentsTotal = new Counter({
  name: 'amrutam_payments_total',
  help: 'Payment outcomes',
  labelNames: ['provider', 'status'] as const,
  registers: [registry],
})

export const idempotencyHitsTotal = new Counter({
  name: 'amrutam_idempotency_hits_total',
  help: 'Idempotent request outcomes',
  labelNames: ['outcome'] as const,
  registers: [registry],
})

export const rateLimitRejectionsTotal = new Counter({
  name: 'amrutam_rate_limit_rejections_total',
  help: 'Requests rejected by the rate limiter',
  labelNames: ['policy'] as const,
  registers: [registry],
})

export const jobsProcessedTotal = new Counter({
  name: 'amrutam_jobs_processed_total',
  help: 'Background jobs processed',
  labelNames: ['type', 'outcome'] as const,
  registers: [registry],
})

export const jobDuration = new Histogram({
  name: 'amrutam_job_duration_seconds',
  help: 'Background job execution time',
  labelNames: ['type'] as const,
  buckets: [0.01, 0.05, 0.1, 0.5, 1, 5, 15, 60, 300],
  registers: [registry],
})

export const jobQueueDepth = new Gauge({
  name: 'amrutam_job_queue_depth',
  help: 'Jobs waiting to run, by queue and status',
  labelNames: ['queue', 'status'] as const,
  registers: [registry],
})

export const outboxLagSeconds = new Gauge({
  name: 'amrutam_outbox_lag_seconds',
  help: 'Age of the oldest pending outbox event',
  registers: [registry],
})

export const outboxEventsTotal = new Counter({
  name: 'amrutam_outbox_events_total',
  help: 'Outbox events by status transition',
  labelNames: ['event_type', 'outcome'] as const,
  registers: [registry],
})

export const auditLogWritesTotal = new Counter({
  name: 'amrutam_audit_log_writes_total',
  help: 'Audit log writes',
  labelNames: ['outcome'] as const,
  registers: [registry],
})
