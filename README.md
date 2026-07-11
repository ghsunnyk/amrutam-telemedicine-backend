# Amrutam — Telemedicine Backend

Production-grade backend for Amrutam's telemedicine platform: patient/doctor
lifecycle, availability & booking, payments with saga-based compensation,
consultations, prescriptions, and admin analytics.

**Stack:** Node.js (TypeScript, strict) · Express · PostgreSQL (Prisma ORM,
`pg` driver) · Zod validation · Pino logging · Prometheus metrics.

---

## 1. Prerequisites

- Node.js 20+
- PostgreSQL 15+
- npm

## 2. Setup

```bash
git clone https://github.com/ghsunnyk/amrutam-telemedicine-backend
cd amrutam-telemedicine-backend
npm install
cp .env.example .env
```

Fill in the secrets `.env.example` marks `CHANGE_ME`. Generate real values with:

```bash
openssl rand -base64 32   # ENCRYPTION_KEK, BLIND_INDEX_PEPPER, JWT_ACCESS_SECRET
openssl rand -base64 16   # IP_HASH_SALT
```

Create the database, then run migrations:

```bash
createdb amrutam
npx prisma migrate deploy   # or `migrate dev` while iterating locally
```

> **Seed data:** `prisma.config.ts` points at `prisma/seed.ts` (creates the
> initial `Specialization` rows and an admin user). This script is not yet
> checked in — add it before demoing doctor search/filtering, since
> `Doctor.specializations` requires existing `Specialization` rows to attach to.

Start the server:

```bash
npm run dev     # ts-node / tsx watch mode
npm run build && npm start   # production
```

The API listens on `PORT` (default `3000`) at `http://localhost:3000/api/v1`.

## 3. Environment variables

All variables are validated at startup via `src/config/env.ts` (Zod) — the
process refuses to boot on a missing or malformed value, and production adds
extra guardrails (no wildcard CORS, no placeholder JWT secret, metrics must be
token-protected). See `.env.example` for the full list with defaults. Key ones:

| Variable                                                   | Purpose                                                                                    |
| ---------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| `DATABASE_URL`                                             | Postgres connection string                                                                 |
| `JWT_ACCESS_SECRET` / `JWT_ACCESS_TTL` / `JWT_REFRESH_TTL` | Auth tokens                                                                                |
| `ENCRYPTION_KEK` / `ENCRYPTION_KEK_ID`                     | Wraps per-row data-encryption keys (envelope encryption) for PHI/PII columns               |
| `BLIND_INDEX_PEPPER`                                       | HMAC pepper for searchable-but-encrypted fields (phone, doctor registration number)        |
| `IP_HASH_SALT`                                             | One-way hash for IPs stored in audit logs / refresh tokens                                 |
| `RATE_LIMIT_*`                                             | Token-bucket rate limiting (Postgres-backed, see `consume_rate_limit_token` function)      |
| `WORKER_ENABLED` / `WORKER_CONCURRENCY`                    | In-process background job worker                                                           |
| `METRICS_AUTH_TOKEN`                                       | Required in production if `METRICS_ENABLED=true` — `/metrics` is unauthenticated otherwise |

## 4. Architecture at a glance

```
src/
├── app.ts               Express app: middleware pipeline, route mounting
├── server.ts             HTTP server lifecycle, graceful shutdown
├── container.ts          Dependency injection root — wires every service
├── config/env.ts          Zod-validated environment config
├── core/
│   ├── errors.ts          Typed AppError hierarchy → consistent HTTP responses
│   ├── http.ts            Response envelope, cursor pagination helpers
│   ├── crypto/            Envelope encryption, argon2 passwords, TOTP, HMAC signing
│   └── timezone.ts        IANA-timezone-aware slot generation (no date library dependency)
├── db/prisma.ts           Pool + Prisma client, query timing, retryable-transaction helper
├── middleware/            authenticate, authorize (RBAC), rateLimit, idempotency, validate, errorHandler
├── modules/
│   ├── auth/              Registration, login, MFA (TOTP + recovery codes), refresh-token rotation
│   ├── doctors/            Application → admin verification, profile, search/filter (keyset pagination)
│   ├── availability/       Recurring rules → materialized slots, hold/release (optimistic CAS)
│   ├── consultations/      Booking, lifecycle (start/complete/cancel/no-show)
│   ├── payments/            Mock provider + saga (AUTHORIZE → CAPTURE → CONFIRM, with compensation)
│   ├── prescriptions/       Draft → issue (HMAC-signed) → revoke
│   ├── analytics/           Admin dashboards (cached aggregate queries)
│   └── audit/                Structured, PII-redacted audit trail
├── workers/                Postgres-backed job queue (SKIP LOCKED), hold-expiry sweeper, outbox publisher
└── observability/           pino logger, prom-client metrics, AsyncLocalStorage request context
```

Full write-up: see `docs/architecture.md` (diagrams, data model, concurrency
strategy, retry/backoff, DR).

## 5. API documentation

The full contract is in [`openapi.yaml`](./openapi.yaml). View it locally:

```bash
npx @redocly/cli preview-docs openapi.yaml
```

or import it into Postman/Insomnia directly.

## 6. Key design decisions worth knowing before you read the code

- **Slot booking concurrency**: no locks — a conditional `UPDATE ... WHERE
status = 'AVAILABLE' OR (status = 'HELD' AND hold_expires_at < now())`
  followed by checking `rowCount === 1`. Two concurrent requests racing on
  the same slot resolve to exactly one winner at the database level; the
  loser gets `409 SLOT_UNAVAILABLE`, never a double booking.
- **Payments are a saga, not a single transaction**: `AUTHORIZE → CAPTURE →
CONFIRM_CONSULTATION`, tracked in `saga_instances`. A failure at any step
  triggers `compensate()`, which only reverses steps that actually completed
  (e.g. refund if captured, but just mark `FAILED` if it never got that far).
- **Idempotency** is required (not optional) on `POST /consultations` and
  `POST /consultations/:id/pay` via the `Idempotency-Key` header — a retried
  request replays the original response instead of double-booking or
  double-charging.
- **Envelope encryption**: every PHI/PII column (diagnosis, symptoms, phone,
  doctor registration number, prescription items) is encrypted with a
  per-deployment data key wrapped by `ENCRYPTION_KEK`. Key rotation re-wraps
  the DEK without touching encrypted rows; ciphertext is self-describing
  (key version embedded in the blob), so decryption never needs a side
  lookup.
- **The worker runs in-process** with the API server for this submission
  (`WORKER_ENABLED=true` starts a `SKIP LOCKED`-based poller inside the same
  Node process). At real scale you'd split this into a dedicated worker
  deployment — the queue table (`Job`) already supports multiple concurrent
  pollers safely, so that split is a deployment change, not a code change.

## 7. Testing

Not yet implemented in this snapshot — planned: Vitest + Supertest against a
disposable Postgres (via `testcontainers` or a CI service container), covering
at minimum: concurrent slot-hold race, refresh-token reuse detection,
idempotent booking replay, and the payment saga's compensation path.

## 8. Known limitations

- DST edge cases in `zonedWallTimeToUtc` are handled for standard IANA zones
  but not exhaustively fuzz-tested against exotic transition rules.
- Payment provider is mocked (`MOCK` provider, always succeeds) — Razorpay/
  Stripe integration would replace `chargeWithProvider()` and move `CAPTURE`
  behind a webhook rather than a synchronous call.
- No Redis; the analytics cache is process-local (fine for one instance, not
  yet safe against thundering-herd cache misses across replicas).
- Dockerfile / docker-compose / CI pipeline are tracked separately and not
  included in this snapshot.
