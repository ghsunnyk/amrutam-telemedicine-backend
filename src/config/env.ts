import { config as loadDotenv } from 'dotenv'
import { z } from 'zod'

// Only load .env off disk outside production. In production the orchestrator
// injects env vars from the secret store, and a stray .env would silently win.
if (process.env.NODE_ENV !== 'production') {
  loadDotenv({ quiet: true })
}

/** Trailing `# comment` is legal in .env but dotenv keeps it for unquoted values. */
const stripInlineComment = (v: unknown) =>
  typeof v === 'string' ? v.replace(/\s+#.*$/, '').trim() : v

const int = (opts?: { min?: number; max?: number }) =>
  z.preprocess(stripInlineComment, z.coerce.number().int().min(opts?.min ?? 0).max(opts?.max ?? Number.MAX_SAFE_INTEGER))

const bool = z.preprocess(
  (v) => (typeof v === 'string' ? stripInlineComment(v) === 'true' : v),
  z.boolean()
)

/** A base64 secret that must decode to exactly `bytes` bytes. */
const base64Key = (bytes: number) =>
  z
    .string()
    .transform((v, ctx) => {
      const buf = Buffer.from(v, 'base64')
      if (buf.length !== bytes) {
        ctx.addIssue({
          code: 'custom',
          message: `must be ${bytes} base64-encoded bytes, got ${buf.length}`,
        })
        return z.NEVER
      }
      return buf
    })

const csv = z.string().transform((v) =>
  v
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
)

const schema = z
  .object({
    NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
    PORT: int({ min: 1, max: 65535 }).default(3000),
    LOG_LEVEL: z.enum(['trace', 'debug', 'info', 'warn', 'error', 'fatal', 'silent']).default('info'),

    DATABASE_URL: z.string().startsWith('postgres'),
    SHADOW_DATABASE_URL: z.string().startsWith('postgres').optional(),
    DATABASE_POOL_SIZE: int({ min: 1, max: 500 }).default(20),
    DATABASE_STATEMENT_TIMEOUT_MS: int({ min: 100 }).default(10_000),

    JWT_ACCESS_SECRET: z.string().min(32, 'needs >= 32 chars of entropy'),
    JWT_ACCESS_TTL: int({ min: 60, max: 3600 }).default(900),
    JWT_REFRESH_TTL: int({ min: 3600 }).default(1_209_600),
    JWT_ISSUER: z.string().min(1).default('amrutam.health'),
    JWT_AUDIENCE: z.string().min(1).default('amrutam-api'),

    ENCRYPTION_KEK: base64Key(32),
    ENCRYPTION_KEK_ID: z.string().min(1),
    BLIND_INDEX_PEPPER: base64Key(32),
    IP_HASH_SALT: base64Key(16),

    ARGON2_MEMORY_COST: int({ min: 8192 }).default(19_456),
    ARGON2_TIME_COST: int({ min: 1, max: 10 }).default(2),
    ARGON2_PARALLELISM: int({ min: 1, max: 16 }).default(1),
    MAX_FAILED_LOGINS: int({ min: 1, max: 100 }).default(5),
    ACCOUNT_LOCK_MINUTES: int({ min: 1 }).default(15),
    MFA_ISSUER: z.string().min(1).default('Amrutam'),
    MFA_WINDOW: int({ min: 0, max: 5 }).default(1),

    RATE_LIMIT_ENABLED: bool.default(true),
    RATE_LIMIT_GLOBAL_CAPACITY: int({ min: 1 }).default(300),
    RATE_LIMIT_GLOBAL_REFILL_PER_SEC: z.preprocess(stripInlineComment, z.coerce.number().positive()).default(5),

    IDEMPOTENCY_TTL_HOURS: int({ min: 1, max: 720 }).default(24),

    OTEL_ENABLED: bool.default(false),
    OTEL_SERVICE_NAME: z.string().default('amrutam-api'),
    OTEL_EXPORTER_OTLP_ENDPOINT: z.string().url().optional(),
    METRICS_ENABLED: bool.default(true),
    METRICS_AUTH_TOKEN: z.string().optional(),

    CORS_ORIGINS: csv.default(['http://localhost:3000']),
    BODY_LIMIT: z.string().default('100kb'),
    TRUST_PROXY_HOPS: int({ min: 0, max: 10 }).default(1),
    SHUTDOWN_TIMEOUT_MS: int({ min: 1000 }).default(15_000),

    WORKER_ENABLED: bool.default(true),
    WORKER_CONCURRENCY: int({ min: 1, max: 100 }).default(5),
    WORKER_POLL_INTERVAL_MS: int({ min: 100 }).default(1000),
    SLOT_HORIZON_DAYS: int({ min: 1, max: 365 }).default(60),
  })
  // Guard rails that only matter in production. Failing startup here is the whole
  // point: a misconfigured prod box should never accept a single request.
  .superRefine((cfg, ctx) => {
    if (cfg.NODE_ENV !== 'production') return

    if (cfg.CORS_ORIGINS.includes('*')) {
      ctx.addIssue({ code: 'custom', path: ['CORS_ORIGINS'], message: 'wildcard origin is forbidden in production' })
    }
    if (cfg.JWT_ACCESS_SECRET.startsWith('CHANGE_ME')) {
      ctx.addIssue({ code: 'custom', path: ['JWT_ACCESS_SECRET'], message: 'placeholder secret in production' })
    }
    if (cfg.METRICS_ENABLED && !cfg.METRICS_AUTH_TOKEN) {
      ctx.addIssue({
        code: 'custom',
        path: ['METRICS_AUTH_TOKEN'],
        message: 'required when METRICS_ENABLED in production — /metrics leaks cardinality and topology',
      })
    }
    if (cfg.CORS_ORIGINS.some((o) => o.startsWith('http://'))) {
      ctx.addIssue({ code: 'custom', path: ['CORS_ORIGINS'], message: 'plaintext http origin in production' })
    }
  })

export type Env = z.infer<typeof schema>

function loadEnv(): Env {
  const parsed = schema.safeParse(process.env)

  if (!parsed.success) {
    const details = parsed.error.issues
      .map((i) => `  • ${i.path.join('.') || '(root)'}: ${i.message}`)
      .join('\n')
    // Deliberately not the logger: config is what the logger is built from.
    console.error(`\nInvalid environment configuration:\n${details}\n`)
    process.exit(1)
  }

  return parsed.data
}

export const env = loadEnv()

export const isProduction = env.NODE_ENV === 'production'
export const isTest = env.NODE_ENV === 'test'
export const isDevelopment = env.NODE_ENV === 'development'
