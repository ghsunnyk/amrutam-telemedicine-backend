-- ---------------------------------------------------------------------------
-- Extensions. Kept here (not run by hand) so a fresh database is reproducible
-- from `prisma migrate deploy` alone.
--   citext    — case-insensitive email, enforced by the type rather than by
--               remembering to lower() at every call site
--   pgcrypto  — gen_random_uuid() for server-side id generation
--   pg_trgm   — trigram GIN indexes behind doctor name/headline search
--   btree_gist — lets an EXCLUDE constraint mix `=` (doctor_id) with `&&` (time range)
-- ---------------------------------------------------------------------------
CREATE EXTENSION IF NOT EXISTS "citext";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";
CREATE EXTENSION IF NOT EXISTS "btree_gist";

-- CreateEnum
CREATE TYPE "role" AS ENUM ('PATIENT', 'DOCTOR', 'ADMIN');

-- CreateEnum
CREATE TYPE "user_status" AS ENUM ('PENDING_VERIFICATION', 'ACTIVE', 'SUSPENDED', 'DEACTIVATED');

-- CreateEnum
CREATE TYPE "doctor_verification_status" AS ENUM ('PENDING', 'VERIFIED', 'REJECTED', 'SUSPENDED');

-- CreateEnum
CREATE TYPE "slot_status" AS ENUM ('AVAILABLE', 'HELD', 'BOOKED', 'BLOCKED');

-- CreateEnum
CREATE TYPE "consultation_status" AS ENUM ('PENDING_PAYMENT', 'SCHEDULED', 'IN_PROGRESS', 'COMPLETED', 'CANCELLED', 'NO_SHOW', 'EXPIRED');

-- CreateEnum
CREATE TYPE "consultation_mode" AS ENUM ('VIDEO', 'AUDIO', 'CHAT', 'IN_PERSON');

-- CreateEnum
CREATE TYPE "cancelled_by" AS ENUM ('PATIENT', 'DOCTOR', 'SYSTEM', 'ADMIN');

-- CreateEnum
CREATE TYPE "prescription_status" AS ENUM ('DRAFT', 'ISSUED', 'REVOKED');

-- CreateEnum
CREATE TYPE "payment_status" AS ENUM ('PENDING', 'AUTHORIZED', 'CAPTURED', 'FAILED', 'REFUND_PENDING', 'REFUNDED', 'PARTIALLY_REFUNDED');

-- CreateEnum
CREATE TYPE "payment_provider" AS ENUM ('RAZORPAY', 'STRIPE', 'MOCK');

-- CreateEnum
CREATE TYPE "encryption_key_status" AS ENUM ('ACTIVE', 'RETIRED', 'COMPROMISED');

-- CreateEnum
CREATE TYPE "idempotency_status" AS ENUM ('IN_PROGRESS', 'COMPLETED');

-- CreateEnum
CREATE TYPE "job_status" AS ENUM ('PENDING', 'RUNNING', 'SUCCEEDED', 'FAILED', 'DEAD');

-- CreateEnum
CREATE TYPE "outbox_status" AS ENUM ('PENDING', 'PUBLISHED', 'FAILED');

-- CreateEnum
CREATE TYPE "saga_status" AS ENUM ('RUNNING', 'COMPLETED', 'COMPENSATING', 'COMPENSATED', 'FAILED');

-- CreateTable
CREATE TABLE "users" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "email" CITEXT NOT NULL,
    "password_hash" TEXT,
    "role" "role" NOT NULL,
    "status" "user_status" NOT NULL DEFAULT 'PENDING_VERIFICATION',
    "email_verified_at" TIMESTAMPTZ(3),
    "mfa_enabled" BOOLEAN NOT NULL DEFAULT false,
    "mfa_secret_enc" BYTEA,
    "mfa_enrolled_at" TIMESTAMPTZ(3),
    "mfa_last_used_step" BIGINT,
    "failed_login_count" INTEGER NOT NULL DEFAULT 0,
    "locked_until" TIMESTAMPTZ(3),
    "tokens_valid_from" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,
    "deleted_at" TIMESTAMPTZ(3),

    CONSTRAINT "users_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "profiles" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "user_id" UUID NOT NULL,
    "first_name" TEXT NOT NULL,
    "last_name" TEXT NOT NULL,
    "phone_hash" TEXT,
    "phone_enc" BYTEA,
    "date_of_birth_enc" BYTEA,
    "gender_enc" BYTEA,
    "address_enc" BYTEA,
    "avatar_url" TEXT,
    "timezone" TEXT NOT NULL DEFAULT 'Asia/Kolkata',
    "locale" TEXT NOT NULL DEFAULT 'en-IN',
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "profiles_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "refresh_tokens" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "user_id" UUID NOT NULL,
    "family_id" UUID NOT NULL,
    "token_hash" TEXT NOT NULL,
    "expires_at" TIMESTAMPTZ(3) NOT NULL,
    "revoked_at" TIMESTAMPTZ(3),
    "rotated_at" TIMESTAMPTZ(3),
    "revoked_reason" TEXT,
    "user_agent" TEXT,
    "ip_hash" TEXT,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "refresh_tokens_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "mfa_recovery_codes" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "user_id" UUID NOT NULL,
    "code_hash" TEXT NOT NULL,
    "used_at" TIMESTAMPTZ(3),
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "mfa_recovery_codes_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "verification_tokens" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "user_id" UUID NOT NULL,
    "purpose" TEXT NOT NULL,
    "token_hash" TEXT NOT NULL,
    "expires_at" TIMESTAMPTZ(3) NOT NULL,
    "consumed_at" TIMESTAMPTZ(3),
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "verification_tokens_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "doctors" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "user_id" UUID NOT NULL,
    "registration_number_hash" TEXT NOT NULL,
    "registration_number_enc" BYTEA NOT NULL,
    "registration_council" TEXT NOT NULL,
    "verification_status" "doctor_verification_status" NOT NULL DEFAULT 'PENDING',
    "verified_at" TIMESTAMPTZ(3),
    "verified_by_user_id" UUID,
    "rejection_reason" TEXT,
    "headline" TEXT,
    "bio" TEXT,
    "years_of_experience" INTEGER NOT NULL DEFAULT 0,
    "languages" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "qualifications" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "city" TEXT,
    "state" TEXT,
    "country" TEXT NOT NULL DEFAULT 'IN',
    "consultation_fee_minor" INTEGER NOT NULL,
    "currency" CHAR(3) NOT NULL DEFAULT 'INR',
    "rating_avg" DECIMAL(3,2) NOT NULL DEFAULT 0,
    "rating_count" INTEGER NOT NULL DEFAULT 0,
    "slot_hold_minutes" INTEGER NOT NULL DEFAULT 10,
    "slot_duration_minutes" INTEGER NOT NULL DEFAULT 30,
    "is_accepting_patients" BOOLEAN NOT NULL DEFAULT true,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,
    "version" INTEGER NOT NULL DEFAULT 0,

    CONSTRAINT "doctors_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "specializations" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "slug" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT,

    CONSTRAINT "specializations_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "doctor_specializations" (
    "doctor_id" UUID NOT NULL,
    "specialization_id" UUID NOT NULL,

    CONSTRAINT "doctor_specializations_pkey" PRIMARY KEY ("doctor_id","specialization_id")
);

-- CreateTable
CREATE TABLE "availability_rules" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "doctor_id" UUID NOT NULL,
    "weekday" INTEGER NOT NULL,
    "start_minute" INTEGER NOT NULL,
    "end_minute" INTEGER NOT NULL,
    "timezone" TEXT NOT NULL DEFAULT 'Asia/Kolkata',
    "slot_duration_minutes" INTEGER NOT NULL DEFAULT 30,
    "effective_from" TIMESTAMPTZ(3) NOT NULL,
    "effective_to" TIMESTAMPTZ(3),
    "is_active" BOOLEAN NOT NULL DEFAULT true,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "availability_rules_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "availability_slots" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "doctor_id" UUID NOT NULL,
    "start_at" TIMESTAMPTZ(3) NOT NULL,
    "end_at" TIMESTAMPTZ(3) NOT NULL,
    "status" "slot_status" NOT NULL DEFAULT 'AVAILABLE',
    "held_by_user_id" UUID,
    "hold_expires_at" TIMESTAMPTZ(3),
    "hold_token" UUID,
    "source_rule_id" UUID,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,
    "version" INTEGER NOT NULL DEFAULT 0,

    CONSTRAINT "availability_slots_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "consultations" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "reference" TEXT NOT NULL,
    "patient_id" UUID NOT NULL,
    "doctor_id" UUID NOT NULL,
    "slot_id" UUID NOT NULL,
    "status" "consultation_status" NOT NULL DEFAULT 'PENDING_PAYMENT',
    "mode" "consultation_mode" NOT NULL DEFAULT 'VIDEO',
    "scheduled_start" TIMESTAMPTZ(3) NOT NULL,
    "scheduled_end" TIMESTAMPTZ(3) NOT NULL,
    "started_at" TIMESTAMPTZ(3),
    "ended_at" TIMESTAMPTZ(3),
    "fee_minor" INTEGER NOT NULL,
    "currency" CHAR(3) NOT NULL DEFAULT 'INR',
    "chief_complaint_enc" BYTEA,
    "symptoms_enc" BYTEA,
    "diagnosis_enc" BYTEA,
    "doctor_notes_enc" BYTEA,
    "follow_up_notes_enc" BYTEA,
    "cancelled_at" TIMESTAMPTZ(3),
    "cancelled_by" "cancelled_by",
    "cancelled_reason" TEXT,
    "expires_at" TIMESTAMPTZ(3),
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,
    "version" INTEGER NOT NULL DEFAULT 0,

    CONSTRAINT "consultations_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "prescriptions" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "consultation_id" UUID NOT NULL,
    "doctor_id" UUID NOT NULL,
    "status" "prescription_status" NOT NULL DEFAULT 'DRAFT',
    "items_enc" BYTEA NOT NULL,
    "advice_enc" BYTEA,
    "signature" BYTEA,
    "signature_key_id" TEXT,
    "issued_at" TIMESTAMPTZ(3),
    "valid_until" TIMESTAMPTZ(3),
    "revoked_at" TIMESTAMPTZ(3),
    "revoked_reason" TEXT,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,
    "version" INTEGER NOT NULL DEFAULT 0,

    CONSTRAINT "prescriptions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "payments" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "consultation_id" UUID NOT NULL,
    "user_id" UUID NOT NULL,
    "provider" "payment_provider" NOT NULL,
    "status" "payment_status" NOT NULL DEFAULT 'PENDING',
    "amount_minor" INTEGER NOT NULL,
    "currency" CHAR(3) NOT NULL DEFAULT 'INR',
    "refunded_amount_minor" INTEGER NOT NULL DEFAULT 0,
    "provider_order_id" TEXT,
    "provider_payment_id" TEXT,
    "failure_code" TEXT,
    "failure_message" TEXT,
    "idempotency_key" TEXT,
    "authorized_at" TIMESTAMPTZ(3),
    "captured_at" TIMESTAMPTZ(3),
    "refunded_at" TIMESTAMPTZ(3),
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,
    "version" INTEGER NOT NULL DEFAULT 0,

    CONSTRAINT "payments_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "reviews" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "consultation_id" UUID NOT NULL,
    "rating" INTEGER NOT NULL,
    "comment" TEXT,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "reviews_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "audit_logs" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "actor_id" UUID,
    "actor_role" "role",
    "action" TEXT NOT NULL,
    "resource_type" TEXT NOT NULL,
    "resource_id" TEXT,
    "metadata" JSONB,
    "ip_hash" TEXT,
    "user_agent" TEXT,
    "request_id" TEXT,
    "trace_id" TEXT,
    "outcome" TEXT NOT NULL DEFAULT 'SUCCESS',

    CONSTRAINT "audit_logs_pkey" PRIMARY KEY ("id","created_at")
) PARTITION BY RANGE ("created_at");
-- ^ Hand-edited: Prisma cannot express declarative partitioning.
--   audit_logs is append-only and unbounded (~50M rows/yr at target volume), so it
--   is range-partitioned by month. Retention then becomes DETACH + archive instead
--   of a DELETE that would bloat the heap and thrash autovacuum. Postgres requires
--   the partition key in every unique constraint, which is why the primary key is
--   (id, created_at) rather than (id) — see the AuditLog model.
--   Partitions themselves are created below and maintained by ensure_audit_partitions().

-- CreateTable
CREATE TABLE "encryption_keys" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "version" INTEGER NOT NULL,
    "wrapped_dek" BYTEA NOT NULL,
    "algorithm" TEXT NOT NULL DEFAULT 'aes-256-gcm',
    "kek_id" TEXT NOT NULL,
    "status" "encryption_key_status" NOT NULL DEFAULT 'ACTIVE',
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "retired_at" TIMESTAMPTZ(3),
    "expires_at" TIMESTAMPTZ(3),

    CONSTRAINT "encryption_keys_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "idempotency_keys" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "scope" TEXT NOT NULL,
    "key" TEXT NOT NULL,
    "request_hash" TEXT NOT NULL,
    "status" "idempotency_status" NOT NULL DEFAULT 'IN_PROGRESS',
    "response_status" INTEGER,
    "response_body" JSONB,
    "locked_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "locked_by" TEXT,
    "expires_at" TIMESTAMPTZ(3) NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "idempotency_keys_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "rate_limit_buckets" (
    "id" TEXT NOT NULL,
    "tokens" DOUBLE PRECISION NOT NULL,
    "last_refill_at" TIMESTAMPTZ(3) NOT NULL,
    "expires_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "rate_limit_buckets_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "jobs" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "queue" TEXT NOT NULL DEFAULT 'default',
    "type" TEXT NOT NULL,
    "payload" JSONB NOT NULL,
    "status" "job_status" NOT NULL DEFAULT 'PENDING',
    "attempts" INTEGER NOT NULL DEFAULT 0,
    "max_attempts" INTEGER NOT NULL DEFAULT 5,
    "run_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "locked_at" TIMESTAMPTZ(3),
    "locked_by" TEXT,
    "lease_until" TIMESTAMPTZ(3),
    "last_error" TEXT,
    "completed_at" TIMESTAMPTZ(3),
    "dedupe_key" TEXT,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "jobs_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "outbox_events" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "aggregate_type" TEXT NOT NULL,
    "aggregate_id" TEXT NOT NULL,
    "event_type" TEXT NOT NULL,
    "payload" JSONB NOT NULL,
    "status" "outbox_status" NOT NULL DEFAULT 'PENDING',
    "attempts" INTEGER NOT NULL DEFAULT 0,
    "available_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "published_at" TIMESTAMPTZ(3),
    "last_error" TEXT,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "outbox_events_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "saga_instances" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "type" TEXT NOT NULL,
    "correlation_id" TEXT NOT NULL,
    "status" "saga_status" NOT NULL DEFAULT 'RUNNING',
    "current_step" TEXT NOT NULL,
    "completed_steps" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "context" JSONB NOT NULL,
    "last_error" TEXT,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,
    "completed_at" TIMESTAMPTZ(3),

    CONSTRAINT "saga_instances_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "users_email_key" ON "users"("email");

-- CreateIndex
CREATE INDEX "users_status_role_idx" ON "users"("status", "role");

-- CreateIndex
CREATE INDEX "users_created_at_idx" ON "users"("created_at");

-- CreateIndex
CREATE UNIQUE INDEX "profiles_user_id_key" ON "profiles"("user_id");

-- CreateIndex
CREATE UNIQUE INDEX "profiles_phone_hash_key" ON "profiles"("phone_hash");

-- CreateIndex
CREATE UNIQUE INDEX "refresh_tokens_token_hash_key" ON "refresh_tokens"("token_hash");

-- CreateIndex
CREATE INDEX "refresh_tokens_user_id_revoked_at_idx" ON "refresh_tokens"("user_id", "revoked_at");

-- CreateIndex
CREATE INDEX "refresh_tokens_family_id_idx" ON "refresh_tokens"("family_id");

-- CreateIndex
CREATE INDEX "refresh_tokens_expires_at_idx" ON "refresh_tokens"("expires_at");

-- CreateIndex
CREATE INDEX "mfa_recovery_codes_user_id_used_at_idx" ON "mfa_recovery_codes"("user_id", "used_at");

-- CreateIndex
CREATE UNIQUE INDEX "verification_tokens_token_hash_key" ON "verification_tokens"("token_hash");

-- CreateIndex
CREATE INDEX "verification_tokens_user_id_purpose_idx" ON "verification_tokens"("user_id", "purpose");

-- CreateIndex
CREATE INDEX "verification_tokens_expires_at_idx" ON "verification_tokens"("expires_at");

-- CreateIndex
CREATE UNIQUE INDEX "doctors_user_id_key" ON "doctors"("user_id");

-- CreateIndex
CREATE UNIQUE INDEX "doctors_registration_number_hash_key" ON "doctors"("registration_number_hash");

-- CreateIndex
CREATE INDEX "doctors_verification_status_is_accepting_patients_idx" ON "doctors"("verification_status", "is_accepting_patients");

-- CreateIndex
CREATE INDEX "doctors_city_consultation_fee_minor_idx" ON "doctors"("city", "consultation_fee_minor");

-- CreateIndex
CREATE INDEX "doctors_rating_avg_rating_count_idx" ON "doctors"("rating_avg" DESC, "rating_count" DESC);

-- CreateIndex
CREATE UNIQUE INDEX "specializations_slug_key" ON "specializations"("slug");

-- CreateIndex
CREATE INDEX "doctor_specializations_specialization_id_idx" ON "doctor_specializations"("specialization_id");

-- CreateIndex
CREATE INDEX "availability_rules_doctor_id_weekday_is_active_idx" ON "availability_rules"("doctor_id", "weekday", "is_active");

-- CreateIndex
CREATE INDEX "availability_slots_doctor_id_status_start_at_idx" ON "availability_slots"("doctor_id", "status", "start_at");

-- CreateIndex
CREATE INDEX "availability_slots_status_hold_expires_at_idx" ON "availability_slots"("status", "hold_expires_at");

-- CreateIndex
CREATE INDEX "availability_slots_start_at_status_idx" ON "availability_slots"("start_at", "status");

-- CreateIndex
CREATE UNIQUE INDEX "availability_slots_doctor_id_start_at_key" ON "availability_slots"("doctor_id", "start_at");

-- CreateIndex
CREATE UNIQUE INDEX "consultations_reference_key" ON "consultations"("reference");

-- CreateIndex
CREATE UNIQUE INDEX "consultations_slot_id_key" ON "consultations"("slot_id");

-- CreateIndex
CREATE INDEX "consultations_patient_id_status_scheduled_start_idx" ON "consultations"("patient_id", "status", "scheduled_start" DESC);

-- CreateIndex
CREATE INDEX "consultations_doctor_id_status_scheduled_start_idx" ON "consultations"("doctor_id", "status", "scheduled_start" DESC);

-- CreateIndex
CREATE INDEX "consultations_scheduled_start_idx" ON "consultations"("scheduled_start");

-- CreateIndex
CREATE INDEX "consultations_status_expires_at_idx" ON "consultations"("status", "expires_at");

-- CreateIndex
CREATE UNIQUE INDEX "prescriptions_consultation_id_key" ON "prescriptions"("consultation_id");

-- CreateIndex
CREATE INDEX "prescriptions_doctor_id_issued_at_idx" ON "prescriptions"("doctor_id", "issued_at" DESC);

-- CreateIndex
CREATE INDEX "prescriptions_status_idx" ON "prescriptions"("status");

-- CreateIndex
CREATE INDEX "payments_consultation_id_status_idx" ON "payments"("consultation_id", "status");

-- CreateIndex
CREATE INDEX "payments_user_id_created_at_idx" ON "payments"("user_id", "created_at" DESC);

-- CreateIndex
CREATE INDEX "payments_status_created_at_idx" ON "payments"("status", "created_at");

-- CreateIndex
CREATE UNIQUE INDEX "payments_provider_provider_order_id_key" ON "payments"("provider", "provider_order_id");

-- CreateIndex
CREATE UNIQUE INDEX "payments_provider_provider_payment_id_key" ON "payments"("provider", "provider_payment_id");

-- CreateIndex
CREATE UNIQUE INDEX "reviews_consultation_id_key" ON "reviews"("consultation_id");

-- CreateIndex
CREATE INDEX "audit_logs_actor_id_created_at_idx" ON "audit_logs"("actor_id", "created_at" DESC);

-- CreateIndex
CREATE INDEX "audit_logs_resource_type_resource_id_created_at_idx" ON "audit_logs"("resource_type", "resource_id", "created_at" DESC);

-- CreateIndex
CREATE INDEX "audit_logs_action_created_at_idx" ON "audit_logs"("action", "created_at" DESC);

-- CreateIndex
CREATE UNIQUE INDEX "encryption_keys_version_key" ON "encryption_keys"("version");

-- CreateIndex
CREATE INDEX "encryption_keys_status_idx" ON "encryption_keys"("status");

-- CreateIndex
CREATE INDEX "idempotency_keys_expires_at_idx" ON "idempotency_keys"("expires_at");

-- CreateIndex
CREATE UNIQUE INDEX "idempotency_keys_scope_key_key" ON "idempotency_keys"("scope", "key");

-- CreateIndex
CREATE INDEX "rate_limit_buckets_expires_at_idx" ON "rate_limit_buckets"("expires_at");

-- CreateIndex
CREATE UNIQUE INDEX "jobs_dedupe_key_key" ON "jobs"("dedupe_key");

-- CreateIndex
CREATE INDEX "jobs_queue_status_run_at_idx" ON "jobs"("queue", "status", "run_at");

-- CreateIndex
CREATE INDEX "jobs_status_lease_until_idx" ON "jobs"("status", "lease_until");

-- CreateIndex
CREATE INDEX "outbox_events_status_available_at_idx" ON "outbox_events"("status", "available_at");

-- CreateIndex
CREATE INDEX "outbox_events_aggregate_type_aggregate_id_idx" ON "outbox_events"("aggregate_type", "aggregate_id");

-- CreateIndex
CREATE INDEX "saga_instances_status_updated_at_idx" ON "saga_instances"("status", "updated_at");

-- CreateIndex
CREATE UNIQUE INDEX "saga_instances_type_correlation_id_key" ON "saga_instances"("type", "correlation_id");

-- AddForeignKey
ALTER TABLE "profiles" ADD CONSTRAINT "profiles_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "refresh_tokens" ADD CONSTRAINT "refresh_tokens_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "mfa_recovery_codes" ADD CONSTRAINT "mfa_recovery_codes_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "verification_tokens" ADD CONSTRAINT "verification_tokens_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "doctors" ADD CONSTRAINT "doctors_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "doctor_specializations" ADD CONSTRAINT "doctor_specializations_doctor_id_fkey" FOREIGN KEY ("doctor_id") REFERENCES "doctors"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "doctor_specializations" ADD CONSTRAINT "doctor_specializations_specialization_id_fkey" FOREIGN KEY ("specialization_id") REFERENCES "specializations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "availability_rules" ADD CONSTRAINT "availability_rules_doctor_id_fkey" FOREIGN KEY ("doctor_id") REFERENCES "doctors"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "availability_slots" ADD CONSTRAINT "availability_slots_doctor_id_fkey" FOREIGN KEY ("doctor_id") REFERENCES "doctors"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "consultations" ADD CONSTRAINT "consultations_patient_id_fkey" FOREIGN KEY ("patient_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "consultations" ADD CONSTRAINT "consultations_doctor_id_fkey" FOREIGN KEY ("doctor_id") REFERENCES "doctors"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "consultations" ADD CONSTRAINT "consultations_slot_id_fkey" FOREIGN KEY ("slot_id") REFERENCES "availability_slots"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "prescriptions" ADD CONSTRAINT "prescriptions_consultation_id_fkey" FOREIGN KEY ("consultation_id") REFERENCES "consultations"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "prescriptions" ADD CONSTRAINT "prescriptions_doctor_id_fkey" FOREIGN KEY ("doctor_id") REFERENCES "doctors"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "payments" ADD CONSTRAINT "payments_consultation_id_fkey" FOREIGN KEY ("consultation_id") REFERENCES "consultations"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "payments" ADD CONSTRAINT "payments_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "reviews" ADD CONSTRAINT "reviews_consultation_id_fkey" FOREIGN KEY ("consultation_id") REFERENCES "consultations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "audit_logs" ADD CONSTRAINT "audit_logs_actor_id_fkey" FOREIGN KEY ("actor_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- ===========================================================================
-- Hand-written additions. Everything below expresses an invariant or a hot-path
-- optimisation that has no representation in the Prisma schema language.
-- ===========================================================================

-- ---------------------------------------------------------------------------
-- 1. audit_logs partitions + maintenance
-- ---------------------------------------------------------------------------

-- Creates the monthly partition covering `at`, if absent. Idempotent, so the
-- nightly job can call it blindly and a cold start can call it for N months ahead.
CREATE OR REPLACE FUNCTION ensure_audit_partition(at TIMESTAMPTZ)
RETURNS TEXT
LANGUAGE plpgsql
AS $$
DECLARE
  lower_bound DATE := date_trunc('month', at)::DATE;
  upper_bound DATE := (date_trunc('month', at) + INTERVAL '1 month')::DATE;
  part_name   TEXT := format('audit_logs_%s', to_char(lower_bound, 'YYYY_MM'));
BEGIN
  IF to_regclass(format('public.%I', part_name)) IS NULL THEN
    EXECUTE format(
      'CREATE TABLE %I PARTITION OF audit_logs FOR VALUES FROM (%L) TO (%L)',
      part_name, lower_bound, upper_bound
    );
  END IF;
  RETURN part_name;
END;
$$;

-- Keep `months_ahead` future partitions warm. If a row ever arrives for a month
-- with no partition, the INSERT fails — so this must always run ahead of the clock.
CREATE OR REPLACE FUNCTION ensure_audit_partitions(months_ahead INT DEFAULT 3)
RETURNS VOID
LANGUAGE plpgsql
AS $$
DECLARE
  i INT;
BEGIN
  FOR i IN 0..months_ahead LOOP
    PERFORM ensure_audit_partition(now() + (i || ' months')::INTERVAL);
  END LOOP;
END;
$$;

-- Bootstrap: last month (late-arriving writes) through three months out.
SELECT ensure_audit_partition(now() - INTERVAL '1 month');
SELECT ensure_audit_partitions(3);

-- Safety net so an INSERT can never fail on a missing partition. Rows landing here
-- are an alertable bug (the maintenance job stopped), not data loss. Note this must
-- exist *before* any DETACH-based retention runs, and attaching a new partition
-- whose range overlaps rows in the default partition requires a scan of it — which
-- is why we keep it empty and alert on `count(*) > 0`.
CREATE TABLE IF NOT EXISTS audit_logs_default PARTITION OF audit_logs DEFAULT;

-- ---------------------------------------------------------------------------
-- 2. Domain invariants the application must never be able to violate.
--    Application-level validation is for good error messages; these are for
--    correctness under concurrency, bad migrations, and manual psql sessions.
-- ---------------------------------------------------------------------------

ALTER TABLE "availability_slots"
  ADD CONSTRAINT "availability_slots_time_order" CHECK ("end_at" > "start_at"),
  -- A HELD slot without an expiry would be held forever if the sweeper missed it.
  ADD CONSTRAINT "availability_slots_hold_coherent" CHECK (
    ("status" <> 'HELD') OR ("hold_expires_at" IS NOT NULL AND "held_by_user_id" IS NOT NULL)
  );

-- The real defence against double-booking. Two overlapping slots for one doctor
-- cannot exist, whatever the application layer does; concurrent inserts serialise
-- on the index. BLOCKED slots are excluded so a doctor can mark time off over an
-- existing (cancelled) range.
ALTER TABLE "availability_slots"
  ADD CONSTRAINT "availability_slots_no_overlap"
  EXCLUDE USING gist (
    "doctor_id" WITH =,
    tstzrange("start_at", "end_at", '[)') WITH &&
  ) WHERE ("status" <> 'BLOCKED');

ALTER TABLE "consultations"
  ADD CONSTRAINT "consultations_time_order" CHECK ("scheduled_end" > "scheduled_start"),
  ADD CONSTRAINT "consultations_fee_non_negative" CHECK ("fee_minor" >= 0),
  -- Terminal states must carry their evidence.
  ADD CONSTRAINT "consultations_cancellation_coherent" CHECK (
    ("status" <> 'CANCELLED') OR ("cancelled_at" IS NOT NULL AND "cancelled_by" IS NOT NULL)
  );

ALTER TABLE "payments"
  ADD CONSTRAINT "payments_amount_positive" CHECK ("amount_minor" > 0),
  -- You cannot refund more than you captured.
  ADD CONSTRAINT "payments_refund_bounded" CHECK (
    "refunded_amount_minor" >= 0 AND "refunded_amount_minor" <= "amount_minor"
  ),
  ADD CONSTRAINT "payments_refund_status_coherent" CHECK (
    ("status" <> 'REFUNDED') OR ("refunded_amount_minor" = "amount_minor")
  );

ALTER TABLE "doctors"
  ADD CONSTRAINT "doctors_fee_non_negative" CHECK ("consultation_fee_minor" >= 0),
  ADD CONSTRAINT "doctors_rating_range" CHECK ("rating_avg" >= 0 AND "rating_avg" <= 5),
  ADD CONSTRAINT "doctors_experience_sane" CHECK ("years_of_experience" BETWEEN 0 AND 80);

ALTER TABLE "reviews"
  ADD CONSTRAINT "reviews_rating_range" CHECK ("rating" BETWEEN 1 AND 5);

ALTER TABLE "availability_rules"
  ADD CONSTRAINT "availability_rules_weekday_range" CHECK ("weekday" BETWEEN 0 AND 6),
  ADD CONSTRAINT "availability_rules_minute_range" CHECK (
    "start_minute" >= 0 AND "end_minute" <= 1440 AND "end_minute" > "start_minute"
  ),
  ADD CONSTRAINT "availability_rules_slot_duration" CHECK ("slot_duration_minutes" BETWEEN 5 AND 240);

ALTER TABLE "jobs"
  ADD CONSTRAINT "jobs_attempts_bounded" CHECK ("attempts" >= 0 AND "attempts" <= "max_attempts");

-- ---------------------------------------------------------------------------
-- 3. Indexes that Prisma's `@@index` cannot express: partial and expression indexes.
--    Partial indexes here are ~10x smaller than their full counterparts because the
--    interesting rows are a tiny minority of the table.
-- ---------------------------------------------------------------------------

-- Slot search only ever asks for AVAILABLE slots in the future.
CREATE INDEX "availability_slots_bookable_idx"
  ON "availability_slots" ("doctor_id", "start_at")
  WHERE "status" = 'AVAILABLE';

-- The hold sweeper: "expired holds", a handful of rows out of millions.
CREATE INDEX "availability_slots_expired_holds_idx"
  ON "availability_slots" ("hold_expires_at")
  WHERE "status" = 'HELD';

-- The job claim query (`FOR UPDATE SKIP LOCKED`) touches only runnable rows.
CREATE INDEX "jobs_claimable_idx"
  ON "jobs" ("queue", "run_at")
  WHERE "status" = 'PENDING';

-- Reclaiming jobs whose worker died mid-lease.
CREATE INDEX "jobs_expired_leases_idx"
  ON "jobs" ("lease_until")
  WHERE "status" = 'RUNNING';

-- The outbox relay drains pending events in insertion order.
CREATE INDEX "outbox_events_unpublished_idx"
  ON "outbox_events" ("available_at", "id")
  WHERE "status" = 'PENDING';

-- Sagas that need resuming after a coordinator crash.
CREATE INDEX "saga_instances_live_idx"
  ON "saga_instances" ("updated_at")
  WHERE "status" IN ('RUNNING', 'COMPENSATING');

-- Live refresh tokens for a user (logout-all, session list). Revoked rows are dead weight.
CREATE INDEX "refresh_tokens_live_idx"
  ON "refresh_tokens" ("user_id", "expires_at")
  WHERE "revoked_at" IS NULL AND "rotated_at" IS NULL;

-- Consultations awaiting payment that the saga will expire.
CREATE INDEX "consultations_expiring_idx"
  ON "consultations" ("expires_at")
  WHERE "status" = 'PENDING_PAYMENT';

-- Only VERIFIED, accepting doctors are ever returned by public search.
CREATE INDEX "doctors_searchable_idx"
  ON "doctors" ("city", "consultation_fee_minor", "rating_avg" DESC)
  WHERE "verification_status" = 'VERIFIED' AND "is_accepting_patients" = true;

-- Fuzzy name/headline search. GIN + trigram makes `ILIKE '%anti%'` an index scan
-- instead of a seq scan, without paying for a full-text tsvector column.
CREATE INDEX "doctors_headline_trgm_idx" ON "doctors" USING gin ("headline" gin_trgm_ops);
CREATE INDEX "profiles_name_trgm_idx"
  ON "profiles" USING gin (("first_name" || ' ' || "last_name") gin_trgm_ops);

-- Soft-deleted users are excluded from every query; keep them out of the index too.
CREATE INDEX "users_active_idx" ON "users" ("email") WHERE "deleted_at" IS NULL;

-- ---------------------------------------------------------------------------
-- 4. Token-bucket rate limiter, evaluated entirely inside Postgres.
--
--    Doing the refill maths in SQL makes check-and-consume a single atomic
--    statement. The obvious application-side version (SELECT, compute, UPDATE) has
--    a read-modify-write race: two concurrent requests both read `tokens = 1` and
--    both proceed. `INSERT … ON CONFLICT DO UPDATE` takes a row lock for the whole
--    statement, so exactly one wins.
--
--    Returns (allowed, tokens_remaining, retry_after_seconds).
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION consume_rate_limit_token(
  p_bucket_id    TEXT,
  p_capacity     DOUBLE PRECISION,
  p_refill_rate  DOUBLE PRECISION,  -- tokens per second
  p_cost         DOUBLE PRECISION,
  p_ttl_seconds  INT
)
RETURNS TABLE (allowed BOOLEAN, tokens_remaining DOUBLE PRECISION, retry_after_seconds DOUBLE PRECISION)
LANGUAGE plpgsql
AS $$
DECLARE
  v_now       TIMESTAMPTZ := clock_timestamp();
  v_ttl       INTERVAL := make_interval(secs => p_ttl_seconds);
  v_tokens    DOUBLE PRECISION;
  v_last      TIMESTAMPTZ;
  v_refilled  DOUBLE PRECISION;
  v_new       DOUBLE PRECISION;
  v_allowed   BOOLEAN;
BEGIN
  -- Take the row lock first, creating the bucket if this is its first request.
  -- The loop handles the race where two callers both miss and one wins the INSERT:
  -- the loser catches unique_violation and comes back around to take the lock.
  LOOP
    SELECT b.tokens, b.last_refill_at INTO v_tokens, v_last
    FROM rate_limit_buckets b
    WHERE b.id = p_bucket_id
    FOR UPDATE;

    EXIT WHEN FOUND;

    BEGIN
      INSERT INTO rate_limit_buckets (id, tokens, last_refill_at, expires_at)
      VALUES (p_bucket_id, p_capacity, v_now, v_now + v_ttl);
      v_tokens := p_capacity;
      v_last   := v_now;
      EXIT;
    EXCEPTION WHEN unique_violation THEN
      -- Someone inserted between our SELECT and INSERT. Retry; the SELECT will
      -- now find the row and block on their lock until they commit.
    END;
  END LOOP;

  -- Lazy refill: we never run a timer, we just credit the elapsed time on access.
  v_refilled := LEAST(
    v_tokens + EXTRACT(EPOCH FROM (v_now - v_last)) * p_refill_rate,
    p_capacity
  );

  v_allowed := v_refilled >= p_cost;
  v_new := CASE WHEN v_allowed THEN v_refilled - p_cost ELSE v_refilled END;

  UPDATE rate_limit_buckets
  SET tokens = v_new, last_refill_at = v_now, expires_at = v_now + v_ttl
  WHERE id = p_bucket_id;

  RETURN QUERY SELECT
    v_allowed,
    v_new,
    CASE
      WHEN v_allowed THEN 0::DOUBLE PRECISION
      WHEN p_refill_rate > 0 THEN (p_cost - v_new) / p_refill_rate
      ELSE p_ttl_seconds::DOUBLE PRECISION
    END;
END;
$$;

-- Reap expired buckets. Called by the maintenance job; without it the table grows
-- without bound at one row per (policy, IP) ever seen.
CREATE OR REPLACE FUNCTION prune_rate_limit_buckets()
RETURNS BIGINT
LANGUAGE plpgsql
AS $$
DECLARE
  v_deleted BIGINT;
BEGIN
  DELETE FROM rate_limit_buckets WHERE expires_at < now();
  GET DIAGNOSTICS v_deleted = ROW_COUNT;
  RETURN v_deleted;
END;
$$;

-- ---------------------------------------------------------------------------
-- 5. `updated_at` maintenance in the database, not the ORM.
--
--    Prisma's `@updatedAt` is applied client-side, so any row touched by raw SQL
--    (the booking path uses SELECT … FOR UPDATE + UPDATE) would keep a stale
--    timestamp, and a NOT NULL column with no default makes a raw INSERT fail
--    outright. A trigger makes the invariant hold no matter who writes the row.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END;
$$;

DO $$
DECLARE
  t TEXT;
BEGIN
  FOR t IN
    SELECT c.table_name
    FROM information_schema.columns c
    JOIN information_schema.tables tt
      ON tt.table_schema = c.table_schema AND tt.table_name = c.table_name
    WHERE c.table_schema = 'public'
      AND c.column_name = 'updated_at'
      AND tt.table_type = 'BASE TABLE'
  LOOP
    EXECUTE format('ALTER TABLE %I ALTER COLUMN updated_at SET DEFAULT now()', t);
    EXECUTE format('DROP TRIGGER IF EXISTS trg_%I_updated_at ON %I', t, t);
    EXECUTE format(
      'CREATE TRIGGER trg_%I_updated_at BEFORE UPDATE ON %I
       FOR EACH ROW EXECUTE FUNCTION set_updated_at()', t, t
    );
  END LOOP;
END;
$$;
