// Replay Attack Protection Implementation

import { CRYPTO_CONFIG } from "./constants"
import { getCurrentTimestamp } from "./utils"

interface NonceEntry {
  nonce: string
  timestamp: number
}

interface SequenceState {
  lastSequenceNumber: number
  receivedSequences: Set<number>
}

/**
 * Replay Protection Manager
 * Tracks nonces, timestamps, and sequence numbers to prevent replay attacks
 */
export class ReplayProtectionManager {
  private seenNonces: Map<string, NonceEntry> = new Map()
  private sequenceStates: Map<string, SequenceState> = new Map()
  private cleanupInterval: ReturnType<typeof setInterval> | null = null

  constructor() {
    // Start periodic cleanup of old nonces
    if (typeof window !== "undefined") {
      this.startCleanup()
    }
  }

  /**
   * Start periodic cleanup of expired entries
   */
  private startCleanup(): void {
    this.cleanupInterval = setInterval(() => {
      this.cleanupExpiredNonces()
    }, 60000) // Clean up every minute
  }

  /**
   * Stop cleanup interval
   */
  public destroy(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval)
    }
  }

  /**
   * Remove expired nonces
   */
  private cleanupExpiredNonces(): void {
    const now = getCurrentTimestamp()
    const expiredKeys: string[] = []

    this.seenNonces.forEach((entry, key) => {
      if (now - entry.timestamp > CRYPTO_CONFIG.REPLAY_WINDOW_MS * 2) {
        expiredKeys.push(key)
      }
    })

    expiredKeys.forEach((key) => this.seenNonces.delete(key))
  }

  /**
   * Verify a message is not a replay
   * Checks nonce, timestamp, and sequence number
   */
  public verifyNotReplay(
    conversationId: string,
    nonce: string,
    timestamp: number,
    sequenceNumber: number,
  ): { valid: boolean; reason?: string } {
    // Check 1: Timestamp validation
    const now = getCurrentTimestamp()
    const timeDiff = Math.abs(now - timestamp)

    if (timeDiff > CRYPTO_CONFIG.REPLAY_WINDOW_MS) {
      return {
        valid: false,
        reason: `Timestamp outside valid window: ${timeDiff}ms difference`,
      }
    }

    // Check 2: Nonce validation (prevent exact replays)
    const nonceKey = `${conversationId}:${nonce}`
    if (this.seenNonces.has(nonceKey)) {
      return {
        valid: false,
        reason: "Duplicate nonce detected - replay attack",
      }
    }

    // Check 3: Sequence number validation
    const seqResult = this.validateSequenceNumber(conversationId, sequenceNumber)
    if (!seqResult.valid) {
      return seqResult
    }

    // All checks passed - record the nonce
    this.seenNonces.set(nonceKey, { nonce, timestamp })

    return { valid: true }
  }

  /**
   * Validate sequence number
   */
  private validateSequenceNumber(conversationId: string, sequenceNumber: number): { valid: boolean; reason?: string } {
    let state = this.sequenceStates.get(conversationId)

    if (!state) {
      // First message in conversation
      state = {
        lastSequenceNumber: sequenceNumber,
        receivedSequences: new Set([sequenceNumber]),
      }
      this.sequenceStates.set(conversationId, state)
      return { valid: true }
    }

    // Check if sequence number was already used
    if (state.receivedSequences.has(sequenceNumber)) {
      return {
        valid: false,
        reason: `Sequence number ${sequenceNumber} already used - replay attack`,
      }
    }

    // Check if sequence number is too old (behind the window)
    if (sequenceNumber < state.lastSequenceNumber - CRYPTO_CONFIG.MAX_SEQUENCE_GAP) {
      return {
        valid: false,
        reason: `Sequence number ${sequenceNumber} too old (last: ${state.lastSequenceNumber})`,
      }
    }

    // Check if sequence number is too far ahead
    if (sequenceNumber > state.lastSequenceNumber + CRYPTO_CONFIG.MAX_SEQUENCE_GAP) {
      return {
        valid: false,
        reason: `Sequence number ${sequenceNumber} too far ahead (last: ${state.lastSequenceNumber})`,
      }
    }

    // Valid sequence number - update state
    state.receivedSequences.add(sequenceNumber)
    if (sequenceNumber > state.lastSequenceNumber) {
      state.lastSequenceNumber = sequenceNumber

      // Clean up old sequence numbers from the set
      const minValid = state.lastSequenceNumber - CRYPTO_CONFIG.MAX_SEQUENCE_GAP
      state.receivedSequences.forEach((seq) => {
        if (seq < minValid) {
          state!.receivedSequences.delete(seq)
        }
      })
    }

    return { valid: true }
  }

  /**
   * Get next sequence number for sending
   */
  public getNextSequenceNumber(conversationId: string): number {
    const state = this.sequenceStates.get(conversationId)

    if (!state) {
      const newState: SequenceState = {
        lastSequenceNumber: 1,
        receivedSequences: new Set([1]),
      }
      this.sequenceStates.set(conversationId, newState)
      return 1
    }

    const nextSeq = state.lastSequenceNumber + 1
    state.lastSequenceNumber = nextSeq
    state.receivedSequences.add(nextSeq)

    return nextSeq
  }

  /**
   * Initialize sequence state for a new conversation
   */
  public initializeConversation(conversationId: string, startSequence = 0): void {
    this.sequenceStates.set(conversationId, {
      lastSequenceNumber: startSequence,
      receivedSequences: new Set(),
    })
  }

  /**
   * Get replay protection statistics (for logging/debugging)
   */
  public getStats(): {
    trackedNonces: number
    trackedConversations: number
  } {
    return {
      trackedNonces: this.seenNonces.size,
      trackedConversations: this.sequenceStates.size,
    }
  }
}

// Simplified Replay Protection for testing
/**
 * Simplified Replay Protection for testing
 */
export class ReplayProtection {
  private seenNonces: Set<string> = new Set()
  private sequenceStates: Map<string, { last: number; seen: Set<number> }> = new Map()

  hasSeenNonce(nonce: string): boolean {
    return this.seenNonces.has(nonce)
  }

  recordNonce(nonce: string): void {
    this.seenNonces.add(nonce)
  }

  isTimestampValid(timestamp: number, windowMs: number = CRYPTO_CONFIG.REPLAY_WINDOW_MS): boolean {
    const now = getCurrentTimestamp()
    const diff = Math.abs(now - timestamp)
    return diff <= windowMs
  }

  isSequenceValid(conversationId: string, sequenceNumber: number): boolean {
    const state = this.sequenceStates.get(conversationId)
    if (!state) return true
    return !state.seen.has(sequenceNumber) && sequenceNumber > state.last - CRYPTO_CONFIG.MAX_SEQUENCE_GAP
  }

  recordSequence(conversationId: string, sequenceNumber: number): void {
    let state = this.sequenceStates.get(conversationId)
    if (!state) {
      state = { last: 0, seen: new Set() }
      this.sequenceStates.set(conversationId, state)
    }
    state.seen.add(sequenceNumber)
    if (sequenceNumber > state.last) {
      state.last = sequenceNumber
    }
  }

  validateMessage(message: { nonce: string; timestamp: number; sequenceNumber: number; conversationId: string }): {
    valid: boolean
    reason?: string
  } {
    if (this.hasSeenNonce(message.nonce)) {
      return { valid: false, reason: "Duplicate nonce" }
    }
    if (!this.isTimestampValid(message.timestamp)) {
      return { valid: false, reason: "Invalid timestamp" }
    }
    if (!this.isSequenceValid(message.conversationId, message.sequenceNumber)) {
      return { valid: false, reason: "Invalid sequence" }
    }
    return { valid: true }
  }

  recordMessage(message: { nonce: string; sequenceNumber: number; conversationId: string }): void {
    this.recordNonce(message.nonce)
    this.recordSequence(message.conversationId, message.sequenceNumber)
  }
}

// Singleton instance for client-side use
let replayProtectionInstance: ReplayProtectionManager | null = null

export function getReplayProtectionManager(): ReplayProtectionManager {
  if (!replayProtectionInstance) {
    replayProtectionInstance = new ReplayProtectionManager()
  }
  return replayProtectionInstance
}
