// Session key storage using IndexedDB
// Persists session keys so they survive page reload/logout

const DB_NAME = "secure_messaging_sessions"
const DB_VERSION = 1
const STORE_NAME = "session_keys"

interface StoredSessionKey {
  conversationId: string
  keyData: ArrayBuffer
  createdAt: number
  userId: string
}

function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION)

    request.onerror = () => reject(request.error)
    request.onsuccess = () => resolve(request.result)

    request.onupgradeneeded = (event) => {
      const db = (event.target as IDBOpenDBRequest).result
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        const store = db.createObjectStore(STORE_NAME, { keyPath: "conversationId" })
        store.createIndex("userId", "userId", { unique: false })
      }
    }
  })
}

export async function storeSessionKey(conversationId: string, sessionKey: CryptoKey, userId: string): Promise<void> {
  try {
    const db = await openDatabase()
    const keyData = await crypto.subtle.exportKey("raw", sessionKey)

    const stored: StoredSessionKey = {
      conversationId,
      keyData,
      createdAt: Date.now(),
      userId,
    }

    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, "readwrite")
      const store = tx.objectStore(STORE_NAME)
      const request = store.put(stored)
      request.onerror = () => reject(request.error)
      request.onsuccess = () => {
        db.close()
        resolve()
      }
    })
  } catch (error) {
    console.error("[v0] Failed to store session key:", error)
  }
}

export async function retrieveSessionKey(conversationId: string): Promise<CryptoKey | null> {
  try {
    const db = await openDatabase()

    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, "readonly")
      const store = tx.objectStore(STORE_NAME)
      const request = store.get(conversationId)

      request.onerror = () => reject(request.error)
      request.onsuccess = async () => {
        const stored = request.result as StoredSessionKey | undefined
        db.close()

        if (!stored) {
          resolve(null)
          return
        }

        // Import the key
        try {
          const key = await crypto.subtle.importKey("raw", stored.keyData, { name: "AES-GCM", length: 256 }, true, [
            "encrypt",
            "decrypt",
          ])
          resolve(key)
        } catch {
          resolve(null)
        }
      }
    })
  } catch (error) {
    console.error("[v0] Failed to retrieve session key:", error)
    return null
  }
}

export async function getSessionKeysForUser(userId: string): Promise<Map<string, CryptoKey>> {
  const keys = new Map<string, CryptoKey>()

  try {
    const db = await openDatabase()

    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, "readonly")
      const store = tx.objectStore(STORE_NAME)
      const index = store.index("userId")
      const request = index.getAll(userId)

      request.onerror = () => reject(request.error)
      request.onsuccess = async () => {
        const results = request.result as StoredSessionKey[]
        db.close()

        for (const stored of results) {
          try {
            const key = await crypto.subtle.importKey("raw", stored.keyData, { name: "AES-GCM", length: 256 }, true, [
              "encrypt",
              "decrypt",
            ])
            const ids = stored.conversationId.split(":")
            const partnerId = ids.find((id) => id !== userId)
            if (partnerId) {
              keys.set(partnerId, key)
            }
            // Also store by conversation ID for backward compatibility
            keys.set(stored.conversationId, key)
          } catch {
            // Skip invalid keys
          }
        }

        resolve(keys)
      }
    })
  } catch (error) {
    console.error("[v0] Failed to get session keys:", error)
    return keys
  }
}

export async function deleteSessionKey(conversationId: string): Promise<void> {
  try {
    const db = await openDatabase()

    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, "readwrite")
      const store = tx.objectStore(STORE_NAME)
      const request = store.delete(conversationId)
      request.onerror = () => reject(request.error)
      request.onsuccess = () => {
        db.close()
        resolve()
      }
    })
  } catch (error) {
    console.error("[v0] Failed to delete session key:", error)
  }
}

export async function clearSessionKeysForUser(userId: string): Promise<void> {
  try {
    const db = await openDatabase()

    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, "readwrite")
      const store = tx.objectStore(STORE_NAME)
      const index = store.index("userId")
      const request = index.getAllKeys(userId)

      request.onerror = () => reject(request.error)
      request.onsuccess = () => {
        const keys = request.result
        keys.forEach((key) => store.delete(key))
        tx.oncomplete = () => {
          db.close()
          resolve()
        }
      }
    })
  } catch (error) {
    console.error("[v0] Failed to clear session keys:", error)
  }
}
