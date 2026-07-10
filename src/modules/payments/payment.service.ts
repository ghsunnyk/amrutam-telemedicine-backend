import { randomUUID } from 'node:crypto'
import {
  ConflictError,
  DependencyFailureError,
  ForbiddenError,
  NotFoundError,
} from '../../core/errors'
import type { Db, Tx } from '../../db/prisma'
import { createLogger } from '../../observability/logger'
import { paymentsTotal } from '../../observability/metrics'
import type { JobQueue } from '../../workers/jobQueue'
import { AuditAction, type AuditService } from '../audit/audit.service'

const log = createLogger('payment')

export interface PaymentReceipt {
  paymentId: string
  consultationId: string
  status: string
  amountMinor: number
  currency: string
}

const SAGA_TYPE = 'booking_payment'
type Step = 'AUTHORIZE' | 'CAPTURE' | 'CONFIRM_CONSULTATION'

export class PaymentService {
  constructor(
    private readonly db: Db,
    private readonly audit: AuditService,
    private readonly jobs: JobQueue | null
  ) {}

  async pay(patientId: string, consultationId: string): Promise<PaymentReceipt> {
    const consultation = await this.db.consultation.findUnique({
      where: { id: consultationId },
      include: { payments: { where: { status: 'PENDING' } } },
    })
    if (!consultation) throw new NotFoundError('Consultation', consultationId)
    if (consultation.patientId !== patientId) {
      throw new ForbiddenError('You do not have access to this consultation')
    }
    if (consultation.status !== 'PENDING_PAYMENT') {
      throw new ConflictError('Consultation is not awaiting payment')
    }
    const payment = consultation.payments[0]
    if (!payment) throw new ConflictError('No pending payment found for this consultation')

    const saga = await this.startSaga(consultationId, { paymentId: payment.id, consultationId })

    try {
      await this.runStep(saga.id, 'AUTHORIZE', async tx => {
        await tx.payment.update({
          where: { id: payment.id },
          data: { status: 'AUTHORIZED', authorizedAt: new Date() },
        })
      })
      await this.audit.recordDetached({
        action: AuditAction.PAYMENT_INITIATED,
        resourceType: 'payment',
        resourceId: payment.id,
        actorId: patientId,
      })

      const charge = await this.chargeWithProvider(payment.amountMinor, payment.currency)
      if (!charge.success) throw new DependencyFailureError('payment_provider')

      await this.runStep(saga.id, 'CAPTURE', async tx => {
        await tx.payment.update({
          where: { id: payment.id },
          data: {
            status: 'CAPTURED',
            capturedAt: new Date(),
            providerPaymentId: charge.providerPaymentId,
          },
        })
      })

      await this.runStep(saga.id, 'CONFIRM_CONSULTATION', async tx => {
        await tx.consultation.update({
          where: { id: consultationId },
          data: { status: 'SCHEDULED' },
        })
      })

      await this.db.sagaInstance.update({
        where: { id: saga.id },
        data: { status: 'COMPLETED', completedAt: new Date() },
      })

      paymentsTotal.inc({ provider: 'MOCK', status: 'CAPTURED' })
      await this.audit.recordDetached({
        action: AuditAction.PAYMENT_CAPTURED,
        resourceType: 'payment',
        resourceId: payment.id,
        actorId: patientId,
      })

      return {
        paymentId: payment.id,
        consultationId,
        status: 'CAPTURED',
        amountMinor: payment.amountMinor,
        currency: payment.currency,
      }
    } catch (err) {
      await this.compensate(saga.id, consultationId, payment.id, err)
      paymentsTotal.inc({ provider: 'MOCK', status: 'FAILED' })
      throw err
    }
  }

  async refund(actorId: string, consultationId: string, reason: string): Promise<void> {
    const consultation = await this.db.consultation.findUnique({
      where: { id: consultationId },
      include: { payments: { where: { status: 'CAPTURED' } } },
    })
    if (!consultation) throw new NotFoundError('Consultation', consultationId)
    const payment = consultation.payments[0]
    if (!payment) throw new ConflictError('No captured payment to refund for this consultation')

    await this.db.payment.update({ where: { id: payment.id }, data: { status: 'REFUND_PENDING' } })

    if (this.jobs) {
      await this.jobs.enqueue(
        'process_refund',
        { paymentId: payment.id, reason },
        { dedupeKey: `refund:${payment.id}` }
      )
    } else {
      await this.db.payment.update({
        where: { id: payment.id },
        data: {
          status: 'REFUNDED',
          refundedAt: new Date(),
          refundedAmountMinor: payment.amountMinor,
        },
      })
    }

    await this.audit.recordDetached({
      action: AuditAction.PAYMENT_REFUNDED,
      resourceType: 'payment',
      resourceId: payment.id,
      actorId,
      metadata: { reason, status: this.jobs ? 'queued' : 'completed' },
    })
  }

  private async chargeWithProvider(
    amountMinor: number,
    currency: string
  ): Promise<{ success: boolean; providerPaymentId?: string }> {
    void amountMinor
    void currency
    // MOCK provider — swap for a Razorpay/Stripe SDK call. A real integration
    // would drive CAPTURE from a webhook instead of this synchronous return,
    // but the saga steps either side of it stay the same.
    return { success: true, providerPaymentId: `mock_${randomUUID()}` }
  }

  private async startSaga(correlationId: string, context: Record<string, unknown>) {
    const existing = await this.db.sagaInstance.findUnique({
      where: { type_correlationId: { type: SAGA_TYPE, correlationId } },
    })
    if (existing?.status === 'COMPLETED') {
      throw new ConflictError('Payment for this consultation has already been processed')
    }
    if (existing?.status === 'RUNNING') {
      throw new ConflictError('Payment for this consultation is already being processed')
    }
    if (existing) {
      return this.db.sagaInstance.update({
        where: { id: existing.id },
        data: {
          status: 'RUNNING',
          currentStep: 'START',
          completedSteps: [],
          lastError: null,
          context: context as never,
        },
      })
    }
    return this.db.sagaInstance.create({
      data: {
        type: SAGA_TYPE,
        correlationId,
        status: 'RUNNING',
        currentStep: 'START',
        context: context as never,
      },
    })
  }

  private async runStep(
    sagaId: string,
    step: Step,
    action: (tx: Tx) => Promise<void>
  ): Promise<void> {
    await this.db.$transaction(async tx => {
      await action(tx)
      const saga = await tx.sagaInstance.findUniqueOrThrow({ where: { id: sagaId } })
      await tx.sagaInstance.update({
        where: { id: sagaId },
        data: { currentStep: step, completedSteps: [...saga.completedSteps, step] },
      })
    })
  }

  private async compensate(
    sagaId: string,
    consultationId: string,
    paymentId: string,
    cause: unknown
  ): Promise<void> {
    const saga = await this.db.sagaInstance.findUnique({ where: { id: sagaId } })
    const completed = new Set(saga?.completedSteps ?? [])
    const message = cause instanceof Error ? cause.message : String(cause)
    log.error(
      { sagaId, consultationId, completed: [...completed], err: cause },
      'Payment saga failed — compensating'
    )

    await this.db.sagaInstance.update({
      where: { id: sagaId },
      data: { status: 'COMPENSATING', lastError: message },
    })

    await this.db.$transaction(async tx => {
      if (completed.has('CAPTURE')) {
        await tx.payment.update({ where: { id: paymentId }, data: { status: 'REFUND_PENDING' } })
      } else {
        await tx.payment.update({
          where: { id: paymentId },
          data: { status: 'FAILED', failureCode: 'CHARGE_FAILED', failureMessage: message },
        })
      }
      const consultation = await tx.consultation.findUnique({ where: { id: consultationId } })
      if (consultation && consultation.status === 'PENDING_PAYMENT') {
        await tx.consultation.update({
          where: { id: consultationId },
          data: {
            status: 'CANCELLED',
            cancelledAt: new Date(),
            cancelledBy: 'SYSTEM',
            cancelledReason: 'payment_failed',
          },
        })
        await tx.availabilitySlot.updateMany({
          where: { id: consultation.slotId, status: 'BOOKED' },
          data: { status: 'AVAILABLE', heldByUserId: null, holdExpiresAt: null, holdToken: null },
        })
      }
      await tx.sagaInstance.update({
        where: { id: sagaId },
        data: { status: 'COMPENSATED', completedAt: new Date() },
      })
    })

    await this.audit.recordDetached({
      action: AuditAction.PAYMENT_FAILED,
      resourceType: 'payment',
      resourceId: paymentId,
      outcome: 'FAILURE',
      metadata: { reason: message },
    })
  }
}
