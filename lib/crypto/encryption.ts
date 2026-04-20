// AES-256-GCM Encryption Implementation for E2E Messaging

import { CRYPTO_CONFIG } from "./constants"
import {
  arrayBufferToBase64,
  base64ToArrayBuffer,
  generateIV,
  generateNonce,
  getCurrentTimestamp,
  generateMessageId,
} from "./utils"
import { signData, verifySignature } from "./signatures"
import type { EncryptedMessage } from "../types"

/**
 * Encrypt a message using AES-256-GCM
 * @param plaintext Message to encrypt
 * @param sessionKey AES-256-GCM session key
 * @param senderId Sender's user ID
 * @param receiverId Receiver's user ID
 * @param signingKey Sender's ECDSA private key for signing
 * @param sequenceNumber Message sequence number for replay protection
 * @returns Encrypted message object
 */
export async function encryptMessage(
  plaintext: string,
  sessionKey: CryptoKey,
  senderId: string,
  receiverId: string,
  signingKey?: CryptoKey,
  sequenceNumber?: number,
): Promise<EncryptedMessage> {
  // Generate fresh IV (never reuse with same key!)
  const iv = generateIV()

  // Generate nonce for replay protection
  const nonce = generateNonce()

  // Get timestamp
  const timestamp = getCurrentTimestamp()
  const seqNum = sequenceNumber ?? 1

  // Create Associated Authenticated Data (AAD)
  const aad = new TextEncoder().encode(
    JSON.stringify({
      senderId,
      receiverId,
      nonce,
      timestamp,
      sequenceNumber: seqNum,
    }),
  )

  // Encrypt plaintext
  const plaintextBytes = new TextEncoder().encode(plaintext)

  const ciphertext = await crypto.subtle.encrypt(
    {
      name: CRYPTO_CONFIG.AES_GCM.name,
      iv: iv,
      additionalData: aad,
      tagLength: CRYPTO_CONFIG.AES_GCM.tagLength,
    },
    sessionKey,
    plaintextBytes,
  )

  // Sign if signing key provided
  let signature = ""
  if (signingKey) {
    const signatureData = new TextEncoder().encode(
      `${arrayBufferToBase64(ciphertext)}|${arrayBufferToBase64(iv.buffer)}|${nonce}|${timestamp}|${seqNum}`,
    )
    signature = await signData(signatureData, signingKey)
  }

  return {
    id: generateMessageId(),
    senderId,
    receiverId,
    ciphertext: arrayBufferToBase64(ciphertext),
    iv: arrayBufferToBase64(iv.buffer),
    authTag: "",
    nonce,
    timestamp,
    sequenceNumber: seqNum,
    signature,
  }
}

/**
 * Decrypt a message using AES-256-GCM
 * @param encryptedMessage Encrypted message object
 * @param sessionKey AES-256-GCM session key
 * @param senderSigningKey Sender's ECDSA public key for verification
 * @param expectedSequenceNumber Expected sequence number for replay protection
 * @returns Decrypted plaintext or null if verification fails
 */
export async function decryptMessage(
  encryptedMessage: EncryptedMessage,
  sessionKey: CryptoKey,
  senderSigningKey?: CryptoKey,
  expectedSequenceNumber?: number,
): Promise<string | null> {
  // Verify signature if key provided
  if (senderSigningKey && encryptedMessage.signature) {
    const signatureData = new TextEncoder().encode(
      `${encryptedMessage.ciphertext}|${encryptedMessage.iv}|${encryptedMessage.nonce}|${encryptedMessage.timestamp}|${encryptedMessage.sequenceNumber}`,
    )

    const isSignatureValid = await verifySignature(signatureData, encryptedMessage.signature, senderSigningKey)

    if (!isSignatureValid) {
      console.error("[v0] Message decryption: Invalid signature")
      return null
    }
  }

  // Verify timestamp if checking
  if (expectedSequenceNumber !== undefined) {
    const now = getCurrentTimestamp()
    const timeDiff = Math.abs(now - encryptedMessage.timestamp)
    if (timeDiff > CRYPTO_CONFIG.REPLAY_WINDOW_MS) {
      console.error("[v0] Message decryption: Timestamp outside valid window")
      return null
    }

    if (encryptedMessage.sequenceNumber < expectedSequenceNumber) {
      console.error("[v0] Message decryption: Sequence number too low")
      return null
    }
  }

  // Reconstruct AAD
  const aad = new TextEncoder().encode(
    JSON.stringify({
      senderId: encryptedMessage.senderId,
      receiverId: encryptedMessage.receiverId,
      nonce: encryptedMessage.nonce,
      timestamp: encryptedMessage.timestamp,
      sequenceNumber: encryptedMessage.sequenceNumber,
    }),
  )

  try {
    const ciphertext = base64ToArrayBuffer(encryptedMessage.ciphertext)
    const iv = new Uint8Array(base64ToArrayBuffer(encryptedMessage.iv))

    const plaintextBuffer = await crypto.subtle.decrypt(
      {
        name: CRYPTO_CONFIG.AES_GCM.name,
        iv: iv,
        additionalData: aad,
        tagLength: CRYPTO_CONFIG.AES_GCM.tagLength,
      },
      sessionKey,
      ciphertext,
    )

    return new TextDecoder().decode(plaintextBuffer)
  } catch (error) {
    console.error("[v0] Message decryption failed:", error)
    return null
  }
}

/**
 * Encrypt raw data (for file chunks)
 */
export async function encryptData(
  data: ArrayBuffer,
  sessionKey: CryptoKey,
): Promise<{ ciphertext: ArrayBuffer; iv: Uint8Array }> {
  const iv = generateIV()

  const ciphertext = await crypto.subtle.encrypt(
    {
      name: CRYPTO_CONFIG.AES_GCM.name,
      iv: iv,
      tagLength: CRYPTO_CONFIG.AES_GCM.tagLength,
    },
    sessionKey,
    data,
  )

  return { ciphertext, iv }
}

/**
 * Decrypt raw data (for file chunks)
 */
export async function decryptData(
  ciphertext: ArrayBuffer,
  iv: Uint8Array,
  sessionKey: CryptoKey,
): Promise<ArrayBuffer | null> {
  try {
    return await crypto.subtle.decrypt(
      {
        name: CRYPTO_CONFIG.AES_GCM.name,
        iv: iv,
        tagLength: CRYPTO_CONFIG.AES_GCM.tagLength,
      },
      sessionKey,
      ciphertext,
    )
  } catch (error) {
    console.error("[v0] Data decryption failed:", error)
    return null
  }
}
