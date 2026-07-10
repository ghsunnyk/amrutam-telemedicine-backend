import type { Db } from '../../db/prisma'

interface CacheEntry<T> {
  value: T
  expiresAt: number
}

// Process-local TTL cache. Fine for a single instance; behind a load balancer
// with multiple replicas each replica warms its own copy, so swap this for
// Redis (already optional in the schema) once you scale horizontally.
class TtlCache {
  private store = new Map<string, CacheEntry<unknown>>()

  get<T>(key: string): T | undefined {
    const entry = this.store.get(key)
    if (!entry) return undefined
    if (entry.expiresAt < Date.now()) {
      this.store.delete(key)
      return undefined
    }
    return entry.value as T
  }

  set<T>(key: string, value: T, ttlMs: number): void {
    this.store.set(key, { value, expiresAt: Date.now() + ttlMs })
  }
}

export interface AnalyticsOverview {
  users: { total: number; patients: number; doctors: number; admins: number }
  doctors: { pending: number; verified: number; rejected: number }
  consultationsByStatus: Record<string, number>
  revenue: { capturedMinor: number; refundedMinor: number; currency: string }
  today: { consultationsBooked: number; consultationsCompleted: number }
}

export interface TimeseriesPoint {
  date: string
  consultations: number
  revenueMinor: number
}

export interface TopDoctor {
  doctorId: string
  name: string
  consultations: number
  ratingAvg: string
  revenueMinor: number
}

const OVERVIEW_TTL_MS = 30_000
const TIMESERIES_TTL_MS = 60_000
const TOP_DOCTORS_TTL_MS = 60_000

export class AnalyticsService {
  private readonly cache = new TtlCache()

  constructor(private readonly db: Db) {}

  async overview(): Promise<AnalyticsOverview> {
    const cached = this.cache.get<AnalyticsOverview>('overview')
    if (cached) return cached

    const [
      usersByRole,
      doctorsByStatus,
      consultationsByStatus,
      revenue,
      todayBooked,
      todayCompleted,
    ] = await Promise.all([
      this.db.user.groupBy({ by: ['role'], _count: true, where: { deletedAt: null } }),
      this.db.doctor.groupBy({ by: ['verificationStatus'], _count: true }),
      this.db.consultation.groupBy({ by: ['status'], _count: true }),
      this.db.payment.aggregate({
        where: { status: 'CAPTURED' },
        _sum: { amountMinor: true, refundedAmountMinor: true },
      }),
      this.db.consultation.count({ where: { createdAt: { gte: startOfToday() } } }),
      this.db.consultation.count({
        where: { status: 'COMPLETED', endedAt: { gte: startOfToday() } },
      }),
    ])

    const roleCount = (role: string) => usersByRole.find(r => r.role === role)?._count ?? 0
    const statusCount = (status: string) =>
      doctorsByStatus.find(d => d.verificationStatus === status)?._count ?? 0

    const result: AnalyticsOverview = {
      users: {
        total: usersByRole.reduce((sum, r) => sum + r._count, 0),
        patients: roleCount('PATIENT'),
        doctors: roleCount('DOCTOR'),
        admins: roleCount('ADMIN'),
      },
      doctors: {
        pending: statusCount('PENDING'),
        verified: statusCount('VERIFIED'),
        rejected: statusCount('REJECTED'),
      },
      consultationsByStatus: Object.fromEntries(
        consultationsByStatus.map(c => [c.status, c._count])
      ),
      revenue: {
        capturedMinor: revenue._sum.amountMinor ?? 0,
        refundedMinor: revenue._sum.refundedAmountMinor ?? 0,
        currency: 'INR',
      },
      today: { consultationsBooked: todayBooked, consultationsCompleted: todayCompleted },
    }
    this.cache.set('overview', result, OVERVIEW_TTL_MS)
    return result
  }

  async consultationsTimeseries(days: number): Promise<TimeseriesPoint[]> {
    const cacheKey = `timeseries:${days}`
    const cached = this.cache.get<TimeseriesPoint[]>(cacheKey)
    if (cached) return cached

    const rows = await this.db.$queryRaw<
      { day: Date; consultations: bigint; revenue_minor: bigint | null }[]
    >`
      SELECT
        date_trunc('day', c.created_at) AS day,
        count(*)::bigint AS consultations,
        coalesce(sum(p.amount_minor) FILTER (WHERE p.status = 'CAPTURED'), 0)::bigint AS revenue_minor
      FROM consultations c
      LEFT JOIN payments p ON p.consultation_id = c.id
      WHERE c.created_at >= now() - make_interval(days => ${days}::int)
      GROUP BY 1
      ORDER BY 1
    `
    const result = rows.map(r => ({
      date: r.day.toISOString().slice(0, 10),
      consultations: Number(r.consultations),
      revenueMinor: Number(r.revenue_minor ?? 0),
    }))
    this.cache.set(cacheKey, result, TIMESERIES_TTL_MS)
    return result
  }

  async topDoctors(limit: number): Promise<TopDoctor[]> {
    const cacheKey = `top_doctors:${limit}`
    const cached = this.cache.get<TopDoctor[]>(cacheKey)
    if (cached) return cached

    const rows = await this.db.$queryRaw<
      {
        doctor_id: string
        first_name: string
        last_name: string
        consultations: bigint
        rating_avg: string
        revenue_minor: bigint | null
      }[]
    >`
      SELECT
        d.id AS doctor_id,
        pr.first_name,
        pr.last_name,
        count(c.id)::bigint AS consultations,
        d.rating_avg::text AS rating_avg,
        coalesce(sum(p.amount_minor) FILTER (WHERE p.status = 'CAPTURED'), 0)::bigint AS revenue_minor
      FROM doctors d
      JOIN users u ON u.id = d.user_id
      JOIN profiles pr ON pr.user_id = u.id
      LEFT JOIN consultations c ON c.doctor_id = d.id AND c.status = 'COMPLETED'
      LEFT JOIN payments p ON p.consultation_id = c.id
      WHERE d.verification_status = 'VERIFIED'
      GROUP BY d.id, pr.first_name, pr.last_name, d.rating_avg
      ORDER BY consultations DESC
      LIMIT ${limit}::int
    `
    const result = rows.map(r => ({
      doctorId: r.doctor_id,
      name: `${r.first_name} ${r.last_name}`,
      consultations: Number(r.consultations),
      ratingAvg: r.rating_avg,
      revenueMinor: Number(r.revenue_minor ?? 0),
    }))
    this.cache.set(cacheKey, result, TOP_DOCTORS_TTL_MS)
    return result
  }
}

const startOfToday = (): Date => {
  const d = new Date()
  d.setHours(0, 0, 0, 0)
  return d
}
