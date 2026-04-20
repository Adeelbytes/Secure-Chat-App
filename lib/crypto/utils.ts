// Cryptographic utility functions using Web Crypto API

import { CRYPTO_CONFIG } from "./constants"

/**
 * Convert ArrayBuffer to Base64 string
 */
export function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer)
  let binary = ""
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i])
  }
  return btoa(binary)
}

/**
 * Convert Base64 string to ArrayBuffer
 */
export function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binary = atob(base64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes.buffer
}

/**
 * Generate cryptographically secure random bytes
 */
export function generateRandomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length)
  crypto.getRandomValues(bytes)
  return bytes
}

/**
 * Generate a unique nonce for replay protection
 */
export function generateNonce(): string {
  const nonce = generateRandomBytes(CRYPTO_CONFIG.NONCE_LENGTH)
  return arrayBufferToBase64(nonce.buffer)
}

/**
 * Generate a fresh IV for AES-GCM encryption
 */
export function generateIV(): Uint8Array {
  return generateRandomBytes(CRYPTO_CONFIG.IV_LENGTH)
}

/**
 * Get current timestamp in milliseconds
 */
export function getCurrentTimestamp(): number {
  return Date.now()
}

/**
 * Check if timestamp is within valid window
 */
export function isTimestampValid(timestamp: number, windowMs: number = CRYPTO_CONFIG.REPLAY_WINDOW_MS): boolean {
  const now = getCurrentTimestamp()
  const diff = Math.abs(now - timestamp)
  return diff <= windowMs
}

/**
 * Concatenate multiple ArrayBuffers
 */
export function concatArrayBuffers(...buffers: ArrayBuffer[]): ArrayBuffer {
  const totalLength = buffers.reduce((sum, buf) => sum + buf.byteLength, 0)
  const result = new Uint8Array(totalLength)
  let offset = 0
  for (const buffer of buffers) {
    result.set(new Uint8Array(buffer), offset)
    offset += buffer.byteLength
  }
  return result.buffer
}

/**
 * Compare two ArrayBuffers in constant time (timing-safe comparison)
 */
export function constantTimeCompare(a: ArrayBuffer, b: ArrayBuffer): boolean {
  const aBytes = new Uint8Array(a)
  const bBytes = new Uint8Array(b)

  if (aBytes.length !== bBytes.length) {
    return false
  }

  let result = 0
  for (let i = 0; i < aBytes.length; i++) {
    result |= aBytes[i] ^ bBytes[i]
  }

  return result === 0
}

/**
 * Hash data using SHA-256
 */
export async function sha256(data: ArrayBuffer | string): Promise<ArrayBuffer> {
  const buffer = typeof data === "string" ? new TextEncoder().encode(data) : data
  return await crypto.subtle.digest("SHA-256", buffer)
}

/**
 * Generate a unique message ID
 */
export function generateMessageId(): string {
  const timestamp = Date.now().toString(36)
  const random = generateRandomBytes(8)
  const randomStr = arrayBufferToBase64(random.buffer).replace(/[+/=]/g, "")
  return `msg_${timestamp}_${randomStr}`
}

/**
 * Generate a unique file ID
 */
export function generateFileId(): string {
  const timestamp = Date.now().toString(36)
  const random = generateRandomBytes(8)
  const randomStr = arrayBufferToBase64(random.buffer).replace(/[+/=]/g, "")
  return `file_${timestamp}_${randomStr}`
}

export { CRYPTO_CONFIG }
