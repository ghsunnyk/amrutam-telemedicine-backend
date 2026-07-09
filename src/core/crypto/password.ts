import { hash, verify } from '@node-rs/argon2'
import { randomBytes } from 'node:crypto'
import { env } from '../../config/env'
import { InternalError } from '../errors'
import { createLogger } from '../../observability/logger'

const log = createLogger('password')

/**
 * Argon2id at OWASP's recommended floor (19 MiB, t=2, p=1).
 *
 * `algorithm` is not passed: argon2id is the library default, and its `Algorithm`
 * enum is an ambient `const enum`, which cannot be referenced under `isolatedModules`.
 * `initPasswordHasher` asserts the default really is argon2id rather than trusting it,
 * so a dependency bump that quietly switched to argon2i would fail at boot instead of
 * silently weakening every password written afterwards.
 *
 * Cost params live in env because the right cost is a property of the box you deploy
 * on, not of the code. They are embedded in the resulting hash string, so raising them
 * later is backwards compatible: old hashes still verify, and `needsRehash` upgrades
 * them on the user's next successful sign-in.
 */
const params = {
  memoryCost: env.ARGON2_MEMORY_COST,
  timeCost: env.ARGON2_TIME_COST,
  parallelism: env.ARGON2_PARALLELISM,
}

/**
 * A pre-computed hash of a random string, used to burn the same CPU time when the
 * email doesn't exist as when it does. Without this, login latency tells an attacker
 * whether an account exists — the classic timing side channel that undoes the
 * generic "Invalid email or password" message.
 */
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
    // A malformed hash in the DB is a data-integrity problem, not a wrong password.
    log.error({ err }, 'Password verification threw — treating as failure')
    return false
  }
}

/**
 * Spend the same time we would have spent verifying a real password.
 * Call this on the "user not found" and "user has no password" branches of login.
 */
export async function fakeVerify(plaintext: string): Promise<false> {
  if (!dummyHash) dummyHash = await hash(randomBytes(32).toString('hex'), params)
  try {
    await verify(dummyHash, plaintext)
  } catch {
    /* expected — we only want the CPU cost */
  }
  return false
}

/** True when a stored hash was produced with weaker params than we now require. */
export function needsRehash(digest: string): boolean {
  const m = /^\$argon2id\$v=19\$m=(\d+),t=(\d+),p=(\d+)\$/.exec(digest)
  if (!m) return true // not argon2id at all — definitely upgrade

  const [, memory, time, parallelism] = m
  return (
    Number(memory) < params.memoryCost ||
    Number(time) < params.timeCost ||
    Number(parallelism) < params.parallelism
  )
}
