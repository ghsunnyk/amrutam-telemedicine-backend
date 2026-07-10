const WEEKDAY_INDEX: Record<string, number> = {
  Sun: 0,
  Mon: 1,
  Tue: 2,
  Wed: 3,
  Thu: 4,
  Fri: 5,
  Sat: 6,
}

export interface ZonedDateParts {
  year: number
  month: number
  day: number
  weekday: number
}

export function zonedDateParts(instant: Date, timeZone: string): ZonedDateParts {
  const parts = new Intl.DateTimeFormat('en-US', {
    timeZone,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    weekday: 'short',
  }).formatToParts(instant)

  const map = Object.fromEntries(parts.map(p => [p.type, p.value]))
  return {
    year: Number(map.year),
    month: Number(map.month),
    day: Number(map.day),
    weekday: WEEKDAY_INDEX[map.weekday!]!,
  }
}

function tzOffsetMinutes(instant: Date, timeZone: string): number {
  const parts = new Intl.DateTimeFormat('en-US', {
    timeZone,
    hourCycle: 'h23',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  }).formatToParts(instant)

  const map = Object.fromEntries(parts.map(p => [p.type, p.value]))
  const asUtc = Date.UTC(
    Number(map.year),
    Number(map.month) - 1,
    Number(map.day),
    Number(map.hour),
    Number(map.minute),
    Number(map.second)
  )
  return (asUtc - instant.getTime()) / 60_000
}

export function zonedWallTimeToUtc(
  year: number,
  month: number,
  day: number,
  minuteOfDay: number,
  timeZone: string
): Date {
  const hour = Math.floor(minuteOfDay / 60)
  const minute = minuteOfDay % 60

  const guess = new Date(Date.UTC(year, month - 1, day, hour, minute))
  const offset = tzOffsetMinutes(guess, timeZone)
  return new Date(guess.getTime() - offset * 60_000)
}
