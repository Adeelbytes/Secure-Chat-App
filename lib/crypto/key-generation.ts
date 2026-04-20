// Key generation using Web Crypto API
// Implements RSA-2048 and ECC P-256 key pairs

import { CRYPTO_CONFIG } from "./constants"
import { arrayBufferToBase64, base64ToArrayBuffer } from "./utils"
import type { KeyPair, ExportedKeyPair } from "../types"

/**
 * Generate ECDH key pair for key exchange
 * Uses P-256 curve as required by project specifications
 */
export async function generateECDHKeyPair(): Promise<KeyPair> {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: CRYPTO_CONFIG.ECDH.name,
      namedCurve: CRYPTO_CONFIG.ECDH.namedCurve,
    },
    true, // extractable
    ["deriveBits", "deriveKey"],
  )

  return {
    publicKey: keyPair.publicKey,
    privateKey: keyPair.privateKey,
  }
}

/**
 * Generate ECDSA key pair for digital signatures
 * Uses P-256 curve as required by project specifications
 */
export async function generateSigningKeyPair(): Promise<KeyPair> {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: CRYPTO_CONFIG.ECDSA.name,
      namedCurve: CRYPTO_CONFIG.ECDSA.namedCurve,
    },
    true, // extractable
    ["sign", "verify"],
  )

  return {
    publicKey: keyPair.publicKey,
    privateKey: keyPair.privateKey,
  }
}

/**
 * Generate RSA-2048 key pair (alternative to ECC)
 */
export async function generateRSAKeyPair(): Promise<KeyPair> {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: CRYPTO_CONFIG.RSA.name,
      modulusLength: CRYPTO_CONFIG.RSA.modulusLength,
      publicExponent: CRYPTO_CONFIG.RSA.publicExponent,
      hash: CRYPTO_CONFIG.RSA.hash,
    },
    true, // extractable
    ["encrypt", "decrypt"],
  )

  return {
    publicKey: keyPair.publicKey,
    privateKey: keyPair.privateKey,
  }
}

/**
 * Export public key to Base64 string for transmission
 */
export async function exportPublicKey(key: CryptoKey): Promise<string> {
  const exported = await crypto.subtle.exportKey("spki", key)
  return arrayBufferToBase64(exported)
}

/**
 * Export private key to Base64 string (for encrypted storage)
 */
export async function exportPrivateKey(key: CryptoKey): Promise<string> {
  const exported = await crypto.subtle.exportKey("pkcs8", key)
  return arrayBufferToBase64(exported)
}

/**
 * Import public key from Base64 string
 */
export async function importPublicKey(base64Key: string, algorithm: "ECDH" | "ECDSA" | "RSA"): Promise<CryptoKey> {
  const keyData = base64ToArrayBuffer(base64Key)

  let algorithmParams: EcKeyImportParams | RsaHashedImportParams
  let keyUsages: KeyUsage[]

  switch (algorithm) {
    case "ECDH":
      algorithmParams = {
        name: CRYPTO_CONFIG.ECDH.name,
        namedCurve: CRYPTO_CONFIG.ECDH.namedCurve,
      }
      keyUsages = []
      break
    case "ECDSA":
      algorithmParams = {
        name: CRYPTO_CONFIG.ECDSA.name,
        namedCurve: CRYPTO_CONFIG.ECDSA.namedCurve,
      }
      keyUsages = ["verify"]
      break
    case "RSA":
      algorithmParams = {
        name: CRYPTO_CONFIG.RSA.name,
        hash: CRYPTO_CONFIG.RSA.hash,
      }
      keyUsages = ["encrypt"]
      break
  }

  return await crypto.subtle.importKey("spki", keyData, algorithmParams, true, keyUsages)
}

/**
 * Import private key from Base64 string
 */
export async function importPrivateKey(base64Key: string, algorithm: "ECDH" | "ECDSA" | "RSA"): Promise<CryptoKey> {
  const keyData = base64ToArrayBuffer(base64Key)

  let algorithmParams: EcKeyImportParams | RsaHashedImportParams
  let keyUsages: KeyUsage[]

  switch (algorithm) {
    case "ECDH":
      algorithmParams = {
        name: CRYPTO_CONFIG.ECDH.name,
        namedCurve: CRYPTO_CONFIG.ECDH.namedCurve,
      }
      keyUsages = ["deriveBits", "deriveKey"]
      break
    case "ECDSA":
      algorithmParams = {
        name: CRYPTO_CONFIG.ECDSA.name,
        namedCurve: CRYPTO_CONFIG.ECDSA.namedCurve,
      }
      keyUsages = ["sign"]
      break
    case "RSA":
      algorithmParams = {
        name: CRYPTO_CONFIG.RSA.name,
        hash: CRYPTO_CONFIG.RSA.hash,
      }
      keyUsages = ["decrypt"]
      break
  }

  return await crypto.subtle.importKey("pkcs8", keyData, algorithmParams, true, keyUsages)
}

/**
 * Generate ephemeral ECDH key pair for a single key exchange session
 */
export async function generateEphemeralKeyPair(): Promise<KeyPair> {
  return await generateECDHKeyPair()
}

/**
 * Export key pair to storable format
 */
export async function exportKeyPair(keyPair: KeyPair): Promise<ExportedKeyPair> {
  const publicKey = await exportPublicKey(keyPair.publicKey)
  const privateKey = await exportPrivateKey(keyPair.privateKey)

  return { publicKey, privateKey }
}
