// Custom Key Exchange Protocol Implementation
// ECDH + Digital Signatures + HKDF for session key derivation

import { CRYPTO_CONFIG } from "./constants"
import { arrayBufferToBase64, generateNonce, getCurrentTimestamp, isTimestampValid, sha256 } from "./utils"
import { generateEphemeralKeyPair, exportPublicKey, importPublicKey } from "./key-generation"
import { signData, verifySignature } from "./signatures"
import type { KeyPair, KeyExchangeMessage } from "../types"

/**
 * Custom Key Exchange Protocol - SecureKEX v1
 *
 * Protocol Flow:
 * 1. Alice generates ephemeral ECDH key pair
 * 2. Alice sends KEY_EXCHANGE_INIT with:
 *    - Ephemeral public key
 *    - Timestamp
 *    - Nonce
 *    - Digital signature (signed with long-term signing key)
 * 3. Bob verifies signature and timestamp
 * 4. Bob generates his ephemeral ECDH key pair
 * 5. Bob computes shared secret using ECDH
 * 6. Bob derives session key using HKDF
 * 7. Bob sends KEY_EXCHANGE_RESPONSE with:
 *    - Ephemeral public key
 *    - Timestamp
 *    - Nonce
 *    - Digital signature
 * 8. Alice verifies signature and timestamp
 * 9. Alice computes shared secret and derives session key
 * 10. Both parties send KEY_CONFIRMATION with HMAC of session info
 */

export interface KeyExchangeState {
  ephemeralKeyPair: KeyPair
  peerPublicKey?: CryptoKey
  sharedSecret?: ArrayBuffer
  sessionKey?: CryptoKey
  nonce: string
  peerNonce?: string
  timestamp: number
  confirmed: boolean
}

/**
 * Initialize key exchange - Step 1 & 2
 * Generates ephemeral key pair and creates signed init message
 */
export async function initiateKeyExchange(
  senderId: string,
  receiverId: string,
  signingPrivateKey: CryptoKey,
): Promise<{ state: KeyExchangeState; message: KeyExchangeMessage }> {
  // Generate ephemeral ECDH key pair
  const ephemeralKeyPair = await generateEphemeralKeyPair()
  const publicKeyBase64 = await exportPublicKey(ephemeralKeyPair.publicKey)

  const nonce = generateNonce()
  const timestamp = getCurrentTimestamp()

  // Create data to sign: senderId || receiverId || publicKey || timestamp || nonce
  const dataToSign = new TextEncoder().encode(`${senderId}|${receiverId}|${publicKeyBase64}|${timestamp}|${nonce}`)

  // Sign with long-term signing key
  const signature = await signData(dataToSign, signingPrivateKey)

  const message: KeyExchangeMessage = {
    type: "KEY_EXCHANGE_INIT",
    senderId,
    receiverId,
    publicKey: publicKeyBase64,
    signature,
    timestamp,
    nonce,
  }

  const state: KeyExchangeState = {
    ephemeralKeyPair,
    nonce,
    timestamp,
    confirmed: false,
  }

  return { state, message }
}

/**
 * Respond to key exchange - Steps 3-7
 * Verifies init message, computes shared secret, creates response
 */
export async function respondToKeyExchange(
  initMessage: KeyExchangeMessage,
  myId: string,
  signingPrivateKey: CryptoKey,
  peerSigningPublicKey: CryptoKey,
): Promise<{ state: KeyExchangeState; message: KeyExchangeMessage; sessionKey: CryptoKey } | null> {
  // Verify this message is for us
  if (initMessage.receiverId !== myId || initMessage.type !== "KEY_EXCHANGE_INIT") {
    console.error("[v0] Key exchange: Invalid receiver or message type")
    return null
  }

  // Verify timestamp is within valid window (prevents replay attacks)
  if (!isTimestampValid(initMessage.timestamp)) {
    console.error("[v0] Key exchange: Timestamp outside valid window - possible replay attack")
    return null
  }

  // Verify signature (prevents MITM attacks)
  const dataToVerify = new TextEncoder().encode(
    `${initMessage.senderId}|${initMessage.receiverId}|${initMessage.publicKey}|${initMessage.timestamp}|${initMessage.nonce}`,
  )

  const isValid = await verifySignature(dataToVerify, initMessage.signature, peerSigningPublicKey)

  if (!isValid) {
    console.error("[v0] Key exchange: Invalid signature - possible MITM attack")
    return null
  }

  // Import peer's ephemeral public key
  const peerPublicKey = await importPublicKey(initMessage.publicKey, "ECDH")

  // Generate our ephemeral key pair
  const ephemeralKeyPair = await generateEphemeralKeyPair()
  const myPublicKeyBase64 = await exportPublicKey(ephemeralKeyPair.publicKey)

  // Compute shared secret using ECDH
  const sharedSecret = await computeSharedSecret(ephemeralKeyPair.privateKey, peerPublicKey)

  // Derive session key using HKDF
  const sessionKey = await deriveSessionKey(sharedSecret, initMessage.nonce, initMessage.senderId, myId)

  const nonce = generateNonce()
  const timestamp = getCurrentTimestamp()

  // Create signed response
  const dataToSign = new TextEncoder().encode(
    `${myId}|${initMessage.senderId}|${myPublicKeyBase64}|${timestamp}|${nonce}|${initMessage.nonce}`,
  )

  const signature = await signData(dataToSign, signingPrivateKey)

  const message: KeyExchangeMessage = {
    type: "KEY_EXCHANGE_RESPONSE",
    senderId: myId,
    receiverId: initMessage.senderId,
    publicKey: myPublicKeyBase64,
    signature,
    timestamp,
    nonce,
  }

  const state: KeyExchangeState = {
    ephemeralKeyPair,
    peerPublicKey,
    sharedSecret,
    sessionKey,
    nonce,
    peerNonce: initMessage.nonce,
    timestamp,
    confirmed: false,
  }

  return { state, message, sessionKey }
}

/**
 * Complete key exchange - Steps 8-9
 * Verifies response, computes shared secret on initiator side
 */
export async function completeKeyExchange(
  responseMessage: KeyExchangeMessage,
  state: KeyExchangeState,
  myId: string,
  peerSigningPublicKey: CryptoKey,
): Promise<{ sessionKey: CryptoKey; state: KeyExchangeState } | null> {
  // Verify message type and receiver
  if (responseMessage.receiverId !== myId || responseMessage.type !== "KEY_EXCHANGE_RESPONSE") {
    console.error("[v0] Key exchange completion: Invalid receiver or message type")
    return null
  }

  // Verify timestamp
  if (!isTimestampValid(responseMessage.timestamp)) {
    console.error("[v0] Key exchange completion: Timestamp outside valid window")
    return null
  }

  // Verify signature including our original nonce (prevents replay)
  const dataToVerify = new TextEncoder().encode(
    `${responseMessage.senderId}|${myId}|${responseMessage.publicKey}|${responseMessage.timestamp}|${responseMessage.nonce}|${state.nonce}`,
  )

  const isValid = await verifySignature(dataToVerify, responseMessage.signature, peerSigningPublicKey)

  if (!isValid) {
    console.error("[v0] Key exchange completion: Invalid signature - possible MITM attack")
    return null
  }

  // Import peer's ephemeral public key
  const peerPublicKey = await importPublicKey(responseMessage.publicKey, "ECDH")

  // Compute shared secret
  const sharedSecret = await computeSharedSecret(state.ephemeralKeyPair.privateKey, peerPublicKey)

  // Derive session key using same parameters as responder
  const sessionKey = await deriveSessionKey(sharedSecret, state.nonce, myId, responseMessage.senderId)

  const updatedState: KeyExchangeState = {
    ...state,
    peerPublicKey,
    sharedSecret,
    sessionKey,
    peerNonce: responseMessage.nonce,
    confirmed: true,
  }

  return { sessionKey, state: updatedState }
}

/**
 * Compute ECDH shared secret
 * Made public for testing
 */
export async function computeSharedSecret(privateKey: CryptoKey, peerPublicKey: CryptoKey): Promise<ArrayBuffer> {
  return await crypto.subtle.deriveBits(
    {
      name: CRYPTO_CONFIG.ECDH.name,
      public: peerPublicKey,
    },
    privateKey,
    256, // 256 bits for P-256 curve
  )
}

/**
 * Derive session key using HKDF
 * Includes context information for key separation
 * Made public for testing
 */
export async function deriveSessionKey(
  sharedSecret: ArrayBuffer,
  nonce: string,
  senderId: string,
  receiverId: string,
): Promise<CryptoKey> {
  // Create context info from all participants - sort IDs for consistency
  const sortedIds = [senderId, receiverId].sort().join(":")
  const contextInfo = `${nonce}|${sortedIds}`

  // Create info parameter with context
  const info = new TextEncoder().encode(`SecureMessaging-SessionKey-v1|${contextInfo}`)

  // Generate salt from context
  const salt = await sha256(contextInfo)

  // Import shared secret as HKDF key material
  const keyMaterial = await crypto.subtle.importKey("raw", sharedSecret, "HKDF", false, ["deriveKey"])

  // Derive AES-GCM key using HKDF
  return await crypto.subtle.deriveKey(
    {
      name: CRYPTO_CONFIG.HKDF.name,
      hash: CRYPTO_CONFIG.HKDF.hash,
      salt: new Uint8Array(salt),
      info: info,
    },
    keyMaterial,
    {
      name: CRYPTO_CONFIG.AES_GCM.name,
      length: CRYPTO_CONFIG.AES_GCM.length,
    },
    true,
    ["encrypt", "decrypt"],
  )
}

/**
 * Generate key confirmation message
 * Both parties compute HMAC of session info to confirm key agreement
 */
export async function generateKeyConfirmation(
  sessionKey: CryptoKey,
  myId: string,
  peerId: string,
  myNonce: string,
  peerNonce: string,
): Promise<string> {
  // Create confirmation data
  const confirmationData = new TextEncoder().encode(`KEY_CONFIRM|${myId}|${peerId}|${myNonce}|${peerNonce}`)

  // Export session key temporarily for HMAC
  const keyData = await crypto.subtle.exportKey("raw", sessionKey)

  // Import as HMAC key
  const hmacKey = await crypto.subtle.importKey("raw", keyData, { name: "HMAC", hash: "SHA-256" }, false, ["sign"])

  // Generate confirmation MAC
  const mac = await crypto.subtle.sign("HMAC", hmacKey, confirmationData)

  return arrayBufferToBase64(mac)
}

/**
 * Verify key confirmation from peer
 */
export async function verifyKeyConfirmation(
  confirmation: string,
  sessionKey: CryptoKey,
  peerId: string,
  myId: string,
  peerNonce: string,
  myNonce: string,
): Promise<boolean> {
  // Compute expected confirmation (note: IDs are swapped from peer's perspective)
  const expectedConfirmation = await generateKeyConfirmation(sessionKey, peerId, myId, peerNonce, myNonce)

  return confirmation === expectedConfirmation
}

/**
 * Create a key exchange message (for testing)
 * Added helper function for tests
 */
export async function createKeyExchangeMessage(
  type: "KEY_EXCHANGE_INIT" | "KEY_EXCHANGE_RESPONSE" | "KEY_CONFIRMATION",
  senderId: string,
  receiverId: string,
  publicKey: string,
  signingPrivateKey: CryptoKey,
): Promise<KeyExchangeMessage> {
  const nonce = generateNonce()
  const timestamp = getCurrentTimestamp()

  const dataToSign = new TextEncoder().encode(`${senderId}|${receiverId}|${publicKey}|${timestamp}|${nonce}`)
  const signature = await signData(dataToSign, signingPrivateKey)

  return {
    type,
    senderId,
    receiverId,
    publicKey,
    signature,
    timestamp,
    nonce,
  }
}

export { generateNonce }
