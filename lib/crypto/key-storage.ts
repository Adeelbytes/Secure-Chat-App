// Secure Key Storage using IndexedDB with encryption

import { CRYPTO_CONFIG } from "./constants"
import { arrayBufferToBase64, base64ToArrayBuffer, generateRandomBytes } from "./utils"
import { exportPrivateKey, importPrivateKey } from "./key-generation"

const DB_NAME = "SecureMessagingKeyStore"
const DB_VERSION = 1
const STORE_NAME = "keys"

interface StoredKey {
  id: string
  encryptedKey: string
  iv: string
  salt: string
  keyType: "ECDH" | "ECDSA" | "RSA"
}

/**
 * Open IndexedDB database
 */
async function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION)

    request.onerror = () => reject(request.error)
    request.onsuccess = () => resolve(request.result)

    request.onupgradeneeded = (event) => {
      const db = (event.target as IDBOpenDBRequest).result
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME, { keyPath: "id" })
      }
    }
  })
}

/**
 * Derive encryption key from password using PBKDF2
 */
async function deriveKeyFromPassword(password: string, salt: ArrayBuffer): Promise<CryptoKey> {
  const passwordKey = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, [
    "deriveKey",
  ])

  return await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: 100000, // High iteration count for security
      hash: "SHA-256",
    },
    passwordKey,
    {
      name: CRYPTO_CONFIG.AES_GCM.name,
      length: CRYPTO_CONFIG.AES_GCM.length,
    },
    false,
    ["encrypt", "decrypt"],
  )
}

/**
 * Store private key securely in IndexedDB
 * Key is encrypted with a key derived from the user's password
 */
export async function storePrivateKey(
  keyId: string,
  privateKey: CryptoKey,
  password: string,
  keyType: "ECDH" | "ECDSA" | "RSA",
): Promise<void> {
  // Export private key
  const exportedKey = await exportPrivateKey(privateKey)
  const keyData = base64ToArrayBuffer(exportedKey)

  // Generate random salt and IV
  const salt = generateRandomBytes(32)
  const iv = generateRandomBytes(12)

  // Derive encryption key from password
  const encryptionKey = await deriveKeyFromPassword(password, salt.buffer)

  // Encrypt the private key
  const encryptedKey = await crypto.subtle.encrypt(
    {
      name: CRYPTO_CONFIG.AES_GCM.name,
      iv: iv,
      tagLength: CRYPTO_CONFIG.AES_GCM.tagLength,
    },
    encryptionKey,
    keyData,
  )

  // Store in IndexedDB
  const db = await openDatabase()
  const transaction = db.transaction(STORE_NAME, "readwrite")
  const store = transaction.objectStore(STORE_NAME)

  const storedKey: StoredKey = {
    id: keyId,
    encryptedKey: arrayBufferToBase64(encryptedKey),
    iv: arrayBufferToBase64(iv.buffer),
    salt: arrayBufferToBase64(salt.buffer),
    keyType,
  }

  return new Promise((resolve, reject) => {
    const request = store.put(storedKey)
    request.onerror = () => reject(request.error)
    request.onsuccess = () => {
      db.close()
      resolve()
    }
  })
}

/**
 * Retrieve and decrypt private key from IndexedDB
 */
export async function retrievePrivateKey(keyId: string, password: string): Promise<CryptoKey | null> {
  const db = await openDatabase()
  const transaction = db.transaction(STORE_NAME, "readonly")
  const store = transaction.objectStore(STORE_NAME)

  const storedKey = await new Promise<StoredKey | undefined>((resolve, reject) => {
    const request = store.get(keyId)
    request.onerror = () => reject(request.error)
    request.onsuccess = () => resolve(request.result)
  })

  db.close()

  if (!storedKey) {
    return null
  }

  try {
    // Derive decryption key from password
    const salt = base64ToArrayBuffer(storedKey.salt)
    const decryptionKey = await deriveKeyFromPassword(password, salt)

    // Decrypt the private key
    const encryptedKey = base64ToArrayBuffer(storedKey.encryptedKey)
    const iv = new Uint8Array(base64ToArrayBuffer(storedKey.iv))

    const decryptedKeyData = await crypto.subtle.decrypt(
      {
        name: CRYPTO_CONFIG.AES_GCM.name,
        iv: iv,
        tagLength: CRYPTO_CONFIG.AES_GCM.tagLength,
      },
      decryptionKey,
      encryptedKey,
    )

    // Import the private key
    const exportedKey = arrayBufferToBase64(decryptedKeyData)
    return await importPrivateKey(exportedKey, storedKey.keyType)
  } catch (error) {
    console.error("[v0] Failed to retrieve private key:", error)
    return null
  }
}

/**
 * Delete a stored key
 */
export async function deleteStoredKey(keyId: string): Promise<void> {
  const db = await openDatabase()
  const transaction = db.transaction(STORE_NAME, "readwrite")
  const store = transaction.objectStore(STORE_NAME)

  return new Promise((resolve, reject) => {
    const request = store.delete(keyId)
    request.onerror = () => reject(request.error)
    request.onsuccess = () => {
      db.close()
      resolve()
    }
  })
}

/**
 * Check if a key exists in storage
 */
export async function hasStoredKey(keyId: string): Promise<boolean> {
  const db = await openDatabase()
  const transaction = db.transaction(STORE_NAME, "readonly")
  const store = transaction.objectStore(STORE_NAME)

  return new Promise((resolve, reject) => {
    const request = store.get(keyId)
    request.onerror = () => reject(request.error)
    request.onsuccess = () => {
      db.close()
      resolve(!!request.result)
    }
  })
}

/**
 * Store session key for a conversation
 */
export async function storeSessionKey(conversationId: string, sessionKey: CryptoKey, password: string): Promise<void> {
  const exportedKey = await crypto.subtle.exportKey("raw", sessionKey)
  const salt = generateRandomBytes(32)
  const iv = generateRandomBytes(12)

  const encryptionKey = await deriveKeyFromPassword(password, salt.buffer)

  const encryptedKey = await crypto.subtle.encrypt(
    {
      name: CRYPTO_CONFIG.AES_GCM.name,
      iv: iv,
      tagLength: CRYPTO_CONFIG.AES_GCM.tagLength,
    },
    encryptionKey,
    exportedKey,
  )

  const db = await openDatabase()
  const transaction = db.transaction(STORE_NAME, "readwrite")
  const store = transaction.objectStore(STORE_NAME)

  const storedKey: StoredKey = {
    id: `session_${conversationId}`,
    encryptedKey: arrayBufferToBase64(encryptedKey),
    iv: arrayBufferToBase64(iv.buffer),
    salt: arrayBufferToBase64(salt.buffer),
    keyType: "ECDH", // Session keys are symmetric but stored similarly
  }

  return new Promise((resolve, reject) => {
    const request = store.put(storedKey)
    request.onerror = () => reject(request.error)
    request.onsuccess = () => {
      db.close()
      resolve()
    }
  })
}

/**
 * Retrieve session key for a conversation
 */
export async function retrieveSessionKey(conversationId: string, password: string): Promise<CryptoKey | null> {
  const db = await openDatabase()
  const transaction = db.transaction(STORE_NAME, "readonly")
  const store = transaction.objectStore(STORE_NAME)

  const storedKey = await new Promise<StoredKey | undefined>((resolve, reject) => {
    const request = store.get(`session_${conversationId}`)
    request.onerror = () => reject(request.error)
    request.onsuccess = () => resolve(request.result)
  })

  db.close()

  if (!storedKey) {
    return null
  }

  try {
    const salt = base64ToArrayBuffer(storedKey.salt)
    const decryptionKey = await deriveKeyFromPassword(password, salt)

    const encryptedKey = base64ToArrayBuffer(storedKey.encryptedKey)
    const iv = new Uint8Array(base64ToArrayBuffer(storedKey.iv))

    const decryptedKeyData = await crypto.subtle.decrypt(
      {
        name: CRYPTO_CONFIG.AES_GCM.name,
        iv: iv,
        tagLength: CRYPTO_CONFIG.AES_GCM.tagLength,
      },
      decryptionKey,
      encryptedKey,
    )

    // Import as AES-GCM key
    return await crypto.subtle.importKey(
      "raw",
      decryptedKeyData,
      {
        name: CRYPTO_CONFIG.AES_GCM.name,
        length: CRYPTO_CONFIG.AES_GCM.length,
      },
      true,
      ["encrypt", "decrypt"],
    )
  } catch (error) {
    console.error("[v0] Failed to retrieve session key:", error)
    return null
  }
}
