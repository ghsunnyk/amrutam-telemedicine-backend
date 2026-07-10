import { hash, verify } from '@node-rs/argon2'
import { randomBytes } from 'node:crypto'
import { env } from '../../config/env'
import { createLogger } from '../../observability/logger'
import { InternalError } from '../errors'

const log = createLogger('password')

const params = {
  memoryCost: env.ARGON2_MEMORY_COST,
  timeCost: env.ARGON2_TIME_COST,
  parallelism: env.ARGON2_PARALLELISM,
}

let dummyHash: string | null = null

export async function initPasswordHasher(): Promise<void> {
  dummyHash = await hash(randomBytes(32).toString('hex'), params)

  if (!dummyHash.startsWith('$argon2id$')) {
    throw new InternalError(
      `Password hasher produced '${dummyHash.split('$')[1]}', expected argon2id. Refusing to start.`
    )
  }
}

export const hashPassword = (plaintext: string): Promise<string> => hash(plaintext, params)

export async function verifyPassword(plaintext: string, digest: string): Promise<boolean> {
  try {
    return await verify(digest, plaintext)
  } catch (err) {
    log.error({ err }, 'Password verification threw — treating as failure')
    return false
  }
}

export async function fakeVerify(plaintext: string): Promise<false> {
  if (!dummyHash) dummyHash = await hash(randomBytes(32).toString('hex'), params)
  try {
    await verify(dummyHash, plaintext)
  } catch {}
  return false
}

export function needsRehash(digest: string): boolean {
  const m = /^\$argon2id\$v=19\$m=(\d+),t=(\d+),p=(\d+)\$/.exec(digest)
  if (!m) return true

  const [, memory, time, parallelism] = m
  return (
    Number(memory) < params.memoryCost ||
    Number(time) < params.timeCost ||
    Number(parallelism) < params.parallelism
  )
}
