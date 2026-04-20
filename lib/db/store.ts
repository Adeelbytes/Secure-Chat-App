// Centralized in-memory store for the application with filesystem persistence
// Uses module-level singletons for persistence across API calls
// Data is persisted to a JSON file to survive server restarts

import type { EncryptedMessage, EncryptedFile, KeyExchangeMessage as KEXMessage } from "@/lib/types"
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "fs"
import { join } from "path"

export interface StoredUser {
  id: string
  username: string
  passwordHash: string
  salt: string
  publicKey: string
  signaturePublicKey: string
  createdAt: Date
}

export interface Session {
  userId: string
  username: string
  expiresAt: Date
}

export interface NonceRecord {
  nonce: string
  conversationId: string
  timestamp: number
}

export interface SequenceRecord {
  conversationId: string
  lastSequenceNumber: number
  seenSequences: number[]
}

interface SenderSequenceRecord {
  senderId: string
  conversationId: string
  lastSequenceNumber: number
  seenSequences: number[]
}

// Persistence file path
const DATA_DIR = join(process.cwd(), ".data")
const DATA_FILE = join(DATA_DIR, "store.json")

interface PersistedData {
  users: [string, StoredUser][]
  sessions: [string, Session][]
  messages: EncryptedMessage[]
  files: EncryptedFile[]
  keyExchanges: [string, KEXMessage[]][]
}

// Initialize maps and arrays
let users = new Map<string, StoredUser>()
let sessions = new Map<string, Session>()
let messages: EncryptedMessage[] = []
let files: EncryptedFile[] = []
let keyExchanges = new Map<string, KEXMessage[]>()
const seenNonces = new Map<string, NonceRecord>()
const senderSequenceRecords = new Map<string, SenderSequenceRecord>()

// Load persisted data on module initialization
function loadPersistedData(): void {
  try {
    if (existsSync(DATA_FILE)) {
      const rawData = readFileSync(DATA_FILE, "utf-8")
      const data: PersistedData = JSON.parse(rawData)

      // Restore users with Date conversion
      users = new Map(data.users.map(([k, v]) => [k, { ...v, createdAt: new Date(v.createdAt) }]))

      // Restore sessions with Date conversion
      sessions = new Map(data.sessions.map(([k, v]) => [k, { ...v, expiresAt: new Date(v.expiresAt) }]))

      // Restore messages
      messages = data.messages || []

      // Restore files
      files = data.files || []

      // Restore key exchanges
      keyExchanges = new Map(data.keyExchanges || [])

      console.log(`[Store] Loaded ${users.size} users, ${messages.length} messages, ${files.length} files`)
    }
  } catch (error) {
    console.error("[Store] Failed to load persisted data:", error)
  }
}

// Save data to filesystem
function persistData(): void {
  try {
    // Ensure data directory exists
    if (!existsSync(DATA_DIR)) {
      mkdirSync(DATA_DIR, { recursive: true })
    }

    const data: PersistedData = {
      users: Array.from(users.entries()),
      sessions: Array.from(sessions.entries()),
      messages,
      files,
      keyExchanges: Array.from(keyExchanges.entries()),
    }

    writeFileSync(DATA_FILE, JSON.stringify(data, null, 2), "utf-8")
  } catch (error) {
    console.error("[Store] Failed to persist data:", error)
  }
}

// Load data on startup
loadPersistedData()

// User functions
export function getUserByUsername(username: string): StoredUser | undefined {
  return users.get(username)
}

export function getUserById(id: string): StoredUser | undefined {
  for (const user of users.values()) {
    if (user.id === id) return user
  }
  return undefined
}

export function getAllUsers(): StoredUser[] {
  return Array.from(users.values())
}

export function addUser(user: StoredUser): void {
  users.set(user.username, user)
  persistData() // Persist after adding user
}

// Session functions
export function getSession(token: string): Session | undefined {
  const session = sessions.get(token)
  if (session && session.expiresAt > new Date()) {
    return session
  }
  if (session) {
    sessions.delete(token)
    persistData()
  }
  return undefined
}

export function addSession(token: string, session: Session): void {
  sessions.set(token, session)
  persistData() // Persist after adding session
}

export function deleteSession(token: string): void {
  sessions.delete(token)
  persistData() // Persist after deleting session
}

// Message functions
export function addMessage(
  message: Partial<EncryptedMessage> & { id: string; senderId: string; receiverId: string },
): void {
  messages.push(message as EncryptedMessage)
  persistData() // Persist after adding message
}

export function getMessagesForUser(userId: string): EncryptedMessage[] {
  return messages.filter((m) => m.senderId === userId || m.receiverId === userId)
}

export function getMessagesBetweenUsers(userId1: string, userId2: string): EncryptedMessage[] {
  return messages.filter(
    (m) => (m.senderId === userId1 && m.receiverId === userId2) || (m.senderId === userId2 && m.receiverId === userId1),
  )
}

// File functions
export function addFile(file: EncryptedFile): void {
  files.push(file)
  persistData() // Persist after adding file
}

export function getFilesForUser(userId: string): EncryptedFile[] {
  return files.filter((f) => f.senderId === userId || f.receiverId === userId)
}

export function getFileById(id: string): EncryptedFile | undefined {
  return files.find((f) => f.id === id)
}

// Key exchange functions
export function addKeyExchange(conversationKey: string, message: KEXMessage): void {
  if (!keyExchanges.has(conversationKey)) {
    keyExchanges.set(conversationKey, [])
  }
  keyExchanges.get(conversationKey)!.push(message)
  persistData() // Persist after adding key exchange
}

export function getKeyExchangesForConversation(conversationKey: string): KEXMessage[] {
  return keyExchanges.get(conversationKey) || []
}

export function getPendingKeyExchanges(userId: string, partnerId?: string): KEXMessage[] {
  const pending: KEXMessage[] = []
  keyExchanges.forEach((msgs, key) => {
    if (partnerId) {
      const convKey = [userId, partnerId].sort().join(":")
      if (key === convKey) {
        pending.push(...msgs.filter((m) => m.receiverId === userId))
      }
    } else {
      pending.push(...msgs.filter((m) => m.receiverId === userId))
    }
  })
  return pending
}

const REPLAY_WINDOW_MS = 5 * 60 * 1000 // 5 minutes

/**
 * Check if a nonce has been seen before (prevents replay attacks)
 */
export function hasSeenNonce(conversationId: string, nonce: string): boolean {
  const key = `${conversationId}:${nonce}`
  return seenNonces.has(key)
}

/**
 * Record a nonce as seen
 */
export function recordNonce(conversationId: string, nonce: string, timestamp: number): void {
  const key = `${conversationId}:${nonce}`
  seenNonces.set(key, { nonce, conversationId, timestamp })

  // Clean up old nonces periodically
  cleanupOldNonces()
}

/**
 * Validate timestamp is within acceptable window
 */
export function isTimestampValid(timestamp: number): boolean {
  const now = Date.now()
  const diff = Math.abs(now - timestamp)
  return diff <= REPLAY_WINDOW_MS
}

/**
 * Validate sequence number for a specific sender in a conversation
 * Using timestamp-based sequence numbers - just need to ensure they're monotonically increasing
 * and not duplicated, not that they're within a small gap
 */
export function validateSequenceNumber(
  senderId: string,
  conversationId: string,
  sequenceNumber: number,
): { valid: boolean; reason?: string } {
  const key = `${conversationId}:${senderId}`
  const record = senderSequenceRecords.get(key)

  if (!record) {
    // First message from this sender in conversation - initialize
    senderSequenceRecords.set(key, {
      senderId,
      conversationId,
      lastSequenceNumber: sequenceNumber,
      seenSequences: [sequenceNumber],
    })
    return { valid: true }
  }

  // Check if already seen (exact duplicate = replay attack)
  if (record.seenSequences.includes(sequenceNumber)) {
    return { valid: false, reason: `Sequence ${sequenceNumber} already used - replay attack detected` }
  }

  // and not a duplicate. We don't restrict forward progress since timestamps naturally increase.
  const MAX_AGE_MS = 5 * 60 * 1000 // 5 minutes
  if (sequenceNumber < record.lastSequenceNumber - MAX_AGE_MS) {
    return { valid: false, reason: `Sequence ${sequenceNumber} too old (more than 5 minutes behind)` }
  }

  // Valid - record it
  record.seenSequences.push(sequenceNumber)
  if (sequenceNumber > record.lastSequenceNumber) {
    record.lastSequenceNumber = sequenceNumber
  }

  const minValid = record.lastSequenceNumber - MAX_AGE_MS
  record.seenSequences = record.seenSequences.filter((s) => s >= minValid)

  return { valid: true }
}

/**
 * Full replay protection validation
 * Pass senderId to validateSequenceNumber for per-sender tracking
 */
export function validateReplayProtection(
  senderId: string,
  receiverId: string,
  nonce: string,
  timestamp: number,
  sequenceNumber: number,
): { valid: boolean; reason?: string } {
  const conversationId = [senderId, receiverId].sort().join(":")

  // Check timestamp
  if (!isTimestampValid(timestamp)) {
    return { valid: false, reason: "Timestamp outside valid window - possible replay attack" }
  }

  // Check nonce
  if (hasSeenNonce(conversationId, nonce)) {
    return { valid: false, reason: "Duplicate nonce detected - replay attack" }
  }

  const seqResult = validateSequenceNumber(senderId, conversationId, sequenceNumber)
  if (!seqResult.valid) {
    return seqResult
  }

  // Record the nonce
  recordNonce(conversationId, nonce, timestamp)

  return { valid: true }
}

/**
 * Clean up old nonces to prevent memory growth
 */
function cleanupOldNonces(): void {
  const now = Date.now()
  const expireTime = now - REPLAY_WINDOW_MS * 2

  for (const [key, record] of seenNonces.entries()) {
    if (record.timestamp < expireTime) {
      seenNonces.delete(key)
    }
  }
}

export function getReplayProtectionStats(): { nonces: number; conversations: number } {
  return {
    nonces: seenNonces.size,
    conversations: senderSequenceRecords.size,
  }
}
