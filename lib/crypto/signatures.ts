// Digital Signature Implementation using ECDSA P-256

import { CRYPTO_CONFIG } from "./constants"
import { arrayBufferToBase64, base64ToArrayBuffer } from "./utils"

/**
 * Sign data using ECDSA with SHA-256
 * @param data Data to sign
 * @param privateKey ECDSA private key
 * @returns Base64 encoded signature
 */
export async function signData(data: ArrayBuffer | Uint8Array, privateKey: CryptoKey): Promise<string> {
  const signature = await crypto.subtle.sign(
    {
      name: CRYPTO_CONFIG.ECDSA.name,
      hash: CRYPTO_CONFIG.ECDSA.hash,
    },
    privateKey,
    data,
  )

  return arrayBufferToBase64(signature)
}

/**
 * Sign a string message using ECDSA with SHA-256
 * Added helper function for signing string messages
 * @param message String message to sign
 * @param privateKey ECDSA private key
 * @returns Base64 encoded signature
 */
export async function signMessage(message: string, privateKey: CryptoKey): Promise<string> {
  const data = new TextEncoder().encode(message)
  return signData(data, privateKey)
}

/**
 * Verify ECDSA signature
 * @param data Original data that was signed
 * @param signatureBase64 Base64 encoded signature
 * @param publicKey ECDSA public key
 * @returns true if signature is valid
 */
export async function verifySignature(
  data: ArrayBuffer | Uint8Array | string,
  signatureBase64: string,
  publicKey: CryptoKey,
): Promise<boolean> {
  try {
    const signature = base64ToArrayBuffer(signatureBase64)
    const dataBuffer = typeof data === "string" ? new TextEncoder().encode(data) : data

    return await crypto.subtle.verify(
      {
        name: CRYPTO_CONFIG.ECDSA.name,
        hash: CRYPTO_CONFIG.ECDSA.hash,
      },
      publicKey,
      signature,
      dataBuffer,
    )
  } catch (error) {
    console.error("[v0] Signature verification failed:", error)
    return false
  }
}

/**
 * Create a signed message envelope
 */
export async function createSignedEnvelope(
  payload: object,
  privateKey: CryptoKey,
): Promise<{ payload: string; signature: string }> {
  const payloadString = JSON.stringify(payload)
  const payloadBytes = new TextEncoder().encode(payloadString)
  const signature = await signData(payloadBytes, privateKey)

  return {
    payload: payloadString,
    signature,
  }
}

/**
 * Verify and extract signed message envelope
 */
export async function verifySignedEnvelope<T>(
  envelope: { payload: string; signature: string },
  publicKey: CryptoKey,
): Promise<T | null> {
  const payloadBytes = new TextEncoder().encode(envelope.payload)
  const isValid = await verifySignature(payloadBytes, envelope.signature, publicKey)

  if (!isValid) {
    return null
  }

  return JSON.parse(envelope.payload) as T
}
