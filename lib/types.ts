// Core types for the secure messaging system

export interface User {
  id: string
  username: string
  passwordHash: string
  publicKey: string // Base64 encoded public key
  signaturePublicKey: string // Base64 encoded signature verification key
  createdAt: Date
  lastLogin: Date
}

export interface UserInfo {
  id: string
  username: string
  publicKey: string
  signaturePublicKey: string
}

export interface KeyPair {
  publicKey: CryptoKey
  privateKey: CryptoKey
}

export interface ExportedKeyPair {
  publicKey: string // Base64 encoded
  privateKey: string // Base64 encoded (encrypted for storage)
}

export interface SessionKey {
  visiblepartner_id: string
  sharedSecret: ArrayBuffer
  derivedKey: CryptoKey
  timestamp: number
  sequenceNumber: number
}

export interface EncryptedMessage {
  id: string
  senderId: string
  receiverId: string
  ciphertext: string // Base64 encoded
  iv: string // Base64 encoded
  authTag: string // Base64 encoded (part of GCM)
  nonce: string // For replay protection
  timestamp: number
  sequenceNumber: number
  signature: string // Digital signature for authenticity
  isFile?: boolean
  fileName?: string
  fileType?: string
  fileId?: string
  fileSize?: number
}

export interface KeyExchangeMessage {
  type: "KEY_EXCHANGE_INIT" | "KEY_EXCHANGE_RESPONSE" | "KEY_CONFIRMATION"
  senderId: string
  receiverId: string
  publicKey: string // Ephemeral ECDH public key
  signature: string // Signed with long-term signing key
  timestamp: number
  nonce: string
}

export interface EncryptedFile {
  id: string
  senderId: string
  receiverId: string
  fileName: string // Encrypted or plaintext for display
  fileType?: string // MIME type for proper reconstruction
  fileSize: number
  encryptedMetadata?: string // Encrypted JSON with name, type, size
  metadataIv?: string // Added metadataIv field
  encryptedData?: string // Added for direct storage
  iv?: string // Added for direct storage
  chunks: EncryptedChunk[]
  timestamp: number
  signature: string
  nonce?: string
}

export interface EncryptedChunk {
  index: number
  ciphertext: string
  iv: string
  authTag: string
}

export interface SecurityLog {
  id: string
  eventType: SecurityEventType
  userId?: string
  targetUserId?: string
  ipAddress: string
  timestamp: Date
  details: string
  success: boolean
}

export interface LogEntry {
  id: string
  eventType: SecurityEventType
  userId?: string
  targetUserId?: string
  ipAddress: string
  timestamp: Date
  details: string
  success: boolean
}

export type SecurityEventType =
  | "AUTH_ATTEMPT"
  | "AUTH_SUCCESS"
  | "AUTH_FAILURE"
  | "KEY_EXCHANGE_INIT"
  | "KEY_EXCHANGE_COMPLETE"
  | "KEY_EXCHANGE_FAILURE"
  | "MESSAGE_DECRYPT_FAILURE"
  | "REPLAY_ATTACK_DETECTED"
  | "INVALID_SIGNATURE"
  | "MITM_ATTEMPT_DETECTED"
  | "FILE_UPLOAD"
  | "FILE_DOWNLOAD"
  | "METADATA_ACCESS"
  | "MESSAGE_SENT"
  | "MESSAGE_SEND_FAILURE"
  | "FILE_UPLOAD_FAILURE"
  | "MESSAGE_FAILED"
  | "FILE_ENCRYPTED"
  | "FILE_ENCRYPTION_FAILED"
  | "FILE_DECRYPTION_FAILED"
  | "FILE_DECRYPTED"
  | "MESSAGE_ENCRYPTED"

export interface ThreatModel {
  threat: string
  category:
    | "Spoofing"
    | "Tampering"
    | "Repudiation"
    | "Information Disclosure"
    | "Denial of Service"
    | "Elevation of Privilege"
  vulnerableComponent: string
  countermeasure: string
  implemented: boolean
}

export interface ChatMessage {
  id: string
  senderId: string
  receiverId: string
  encryptedContent: string
  content?: string // Decrypted content (populated client-side)
  decryptedContent?: string // Added decryptedContent field for compatibility
  iv?: string // Added iv field
  signature?: string // Added signature field
  nonce?: string // Added nonce field
  timestamp: number | Date // Allow both number and Date
  isEncrypted?: boolean
  decryptionFailed?: boolean
  isFile?: boolean
  fileName?: string
  fileType?: string
  fileSize?: number
  fileId?: string
}
