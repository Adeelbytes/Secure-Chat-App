"use client"

import { useState, useEffect, useCallback } from "react"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { LoginForm } from "@/components/auth/login-form"
import { RegisterForm } from "@/components/auth/register-form"
import { UserList } from "@/components/chat/user-list"
import { MessageList } from "@/components/chat/message-list"
import { MessageInput } from "@/components/chat/message-input"
import { FileUploadButton } from "@/components/chat/file-upload-button"
import { KeyExchangeDialog } from "@/components/chat/key-exchange-dialog"
import { SecurityLogs } from "@/components/security/security-logs"
import { storeSessionKey, getSessionKeysForUser } from "@/lib/crypto/session-storage"
import type { LogEntry, SecurityEventType } from "@/lib/types"
import { Terminal, Skull, Zap, Radio, Eye, EyeOff, Power } from "lucide-react"

// Types
interface UserInfo {
  id: string
  username: string
  publicKey: string
  signaturePublicKey: string
}

interface ChatMessage {
  id: string
  senderId: string
  receiverId: string
  encryptedContent: string
  iv: string
  timestamp: Date
  signature: string
  nonce: string
  isFile?: boolean
  fileName?: string
  fileType?: string
  fileId?: string
  fileSize?: number
  decryptedContent?: string
  content?: string
  decryptionFailed?: boolean
}

type KeyExchangeState = "idle" | "initiating" | "responding" | "complete" | "error"

function getConversationId(userId1: string, userId2: string): string {
  return [userId1, userId2].sort().join(":")
}

async function loadPrivateKeys(
  username: string,
  password: string,
): Promise<{ ecdh: CryptoKey; ecdsa: CryptoKey } | null> {
  try {
    const db = await new Promise<IDBDatabase>((resolve, reject) => {
      const request = indexedDB.open("SecureMessagingKeys", 1)
      request.onerror = () => reject(request.error)
      request.onsuccess = () => resolve(request.result)
      request.onupgradeneeded = (event) => {
        const database = (event.target as IDBOpenDBRequest).result
        if (!database.objectStoreNames.contains("keys")) {
          database.createObjectStore("keys", { keyPath: "id" })
        }
      }
    })

    const tx = db.transaction("keys", "readonly")
    const store = tx.objectStore("keys")

    const keyData = await new Promise<
      | {
          id: string
          salt: number[]
          ecdhKey: { iv: number[]; data: number[] }
          ecdsaKey: { iv: number[]; data: number[] }
        }
      | undefined
    >((resolve, reject) => {
      const request = store.get(username)
      request.onsuccess = () => resolve(request.result)
      request.onerror = () => reject(request.error)
    })

    db.close()

    if (!keyData) return null

    const encoder = new TextEncoder()
    const passwordKey = await window.crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, [
      "deriveKey",
    ])

    const salt = new Uint8Array(keyData.salt)
    const derivedKey = await window.crypto.subtle.deriveKey(
      { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
      passwordKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"],
    )

    const ecdhIv = new Uint8Array(keyData.ecdhKey.iv)
    const ecdhData = new Uint8Array(keyData.ecdhKey.data)
    const ecdhDecrypted = await window.crypto.subtle.decrypt({ name: "AES-GCM", iv: ecdhIv }, derivedKey, ecdhData)
    const ecdhKey = await window.crypto.subtle.importKey(
      "pkcs8",
      ecdhDecrypted,
      { name: "ECDH", namedCurve: "P-256" },
      true,
      ["deriveBits"],
    )

    const ecdsaIv = new Uint8Array(keyData.ecdsaKey.iv)
    const ecdsaData = new Uint8Array(keyData.ecdsaKey.data)
    const ecdsaDecrypted = await window.crypto.subtle.decrypt({ name: "AES-GCM", iv: ecdsaIv }, derivedKey, ecdsaData)
    const ecdsaKey = await window.crypto.subtle.importKey(
      "pkcs8",
      ecdsaDecrypted,
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign"],
    )

    return { ecdh: ecdhKey, ecdsa: ecdsaKey }
  } catch (err) {
    console.error("Failed to load private keys:", err)
    return null
  }
}

async function encryptMessage(plaintext: string, sessionKey: CryptoKey): Promise<{ encrypted: string; iv: string }> {
  const encoder = new TextEncoder()
  const iv = window.crypto.getRandomValues(new Uint8Array(12))
  const encrypted = await window.crypto.subtle.encrypt({ name: "AES-GCM", iv }, sessionKey, encoder.encode(plaintext))
  return {
    encrypted: btoa(String.fromCharCode(...new Uint8Array(encrypted))),
    iv: btoa(String.fromCharCode(...iv)),
  }
}

async function decryptMessage(encryptedContent: string, ivBase64: string, sessionKey: CryptoKey): Promise<string> {
  const decoder = new TextDecoder()
  const encrypted = Uint8Array.from(atob(encryptedContent), (c) => c.charCodeAt(0))
  const iv = Uint8Array.from(atob(ivBase64), (c) => c.charCodeAt(0))
  const decrypted = await window.crypto.subtle.decrypt({ name: "AES-GCM", iv }, sessionKey, encrypted)
  return decoder.decode(decrypted)
}

async function signMessage(data: string, signingKey: CryptoKey): Promise<string> {
  const encoder = new TextEncoder()
  const signature = await window.crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    signingKey,
    encoder.encode(data),
  )
  return btoa(String.fromCharCode(...new Uint8Array(signature)))
}

function generateNonce(): string {
  const nonce = window.crypto.getRandomValues(new Uint8Array(16))
  return btoa(String.fromCharCode(...nonce))
}

function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer)
  let binary = ""
  const chunkSize = 8192
  for (let i = 0; i < bytes.length; i += chunkSize) {
    const chunk = bytes.subarray(i, Math.min(i + chunkSize, bytes.length))
    binary += String.fromCharCode.apply(null, Array.from(chunk))
  }
  return btoa(binary)
}

function uint8ArrayToBase64(arr: Uint8Array): string {
  let binary = ""
  const chunkSize = 8192
  for (let i = 0; i < arr.length; i += chunkSize) {
    const chunk = arr.subarray(i, Math.min(i + chunkSize, arr.length))
    binary += String.fromCharCode.apply(null, Array.from(chunk))
  }
  return btoa(binary)
}

export default function SecureMessagingApp() {
  // Auth state
  const [currentUser, setCurrentUser] = useState<UserInfo | null>(null)
  const [sessionToken, setSessionToken] = useState<string | null>(null)
  const [userPassword, setUserPassword] = useState<string | null>(null)
  const [authTab, setAuthTab] = useState<"login" | "register">("login")

  // Chat state
  const [selectedUser, setSelectedUser] = useState<UserInfo | null>(null)
  const [messages, setMessages] = useState<ChatMessage[]>([])
  const [keyExchangeStatus, setKeyExchangeStatus] = useState<Map<string, "none" | "pending" | "complete">>(new Map())
  const [sessionKeys, setSessionKeys] = useState<Map<string, CryptoKey>>(new Map())

  // Key exchange dialog state
  const [keyExchangeDialogOpen, setKeyExchangeDialogOpen] = useState(false)
  const [keyExchangeState, setKeyExchangeState] = useState<KeyExchangeState>("idle")

  // Security logs
  const [securityLogs, setSecurityLogs] = useState<LogEntry[]>([])

  // Private keys (loaded from IndexedDB)
  const [privateKeys, setPrivateKeys] = useState<{
    ecdh: CryptoKey | null
    ecdsa: CryptoKey | null
  }>({ ecdh: null, ecdsa: null })

  useEffect(() => {
    if (currentUser && userPassword) {
      loadPrivateKeys(currentUser.username, userPassword)
        .then((keys) => {
          if (keys) {
            setPrivateKeys(keys)
            addSecurityLog("AUTH_SUCCESS", `Private keys loaded for ${currentUser.username}`, true)
          }
        })
        .catch((err) => {
          console.error("Failed to load private keys:", err)
          addSecurityLog(
            "AUTH_FAILURE",
            `Failed to load private keys: ${err instanceof Error ? err.message : "Unknown"}`,
            false,
          )
        })

      getSessionKeysForUser(currentUser.id)
        .then((storedKeys) => {
          if (storedKeys.size > 0) {
            setSessionKeys(storedKeys)
            // Update key exchange status for loaded keys
            const newStatus = new Map(keyExchangeStatus)
            storedKeys.forEach((_, key) => {
              // Key could be conversation ID or partner ID
              if (key.includes(":")) {
                // It's a conversation ID
                newStatus.set(key, "complete")
              }
            })
            setKeyExchangeStatus(newStatus)
            addSecurityLog("KEY_EXCHANGE_COMPLETE", `Loaded ${storedKeys.size} persisted session keys`, true)
          }
        })
        .catch((err) => {
          console.error("Failed to load session keys:", err)
        })
    }
  }, [currentUser, userPassword])

  useEffect(() => {
    if (!currentUser || !selectedUser) return

    const conversationId = getConversationId(currentUser.id, selectedUser.id)
    const sessionKey = sessionKeys.get(conversationId)

    if (!sessionKey) {
      return
    }

    const fetchMessages = async () => {
      try {
        const response = await fetch(`/api/messages?partnerId=${selectedUser.id}`, {
          headers: sessionToken ? { Authorization: `Bearer ${sessionToken}` } : {},
        })
        if (response.ok) {
          const data = await response.json()
          const apiMessages = data.messages || []

          const decryptedMessages = await Promise.all(
            apiMessages.map(
              async (msg: {
                id: string
                senderId: string
                receiverId: string
                ciphertext?: string
                encryptedContent?: string
                iv: string
                timestamp: number
                signature: string
                nonce: string
                isFile?: boolean
                fileName?: string
                fileType?: string
                fileId?: string
                fileSize?: number
              }) => {
                const chatMsg: ChatMessage = {
                  id: msg.id,
                  senderId: msg.senderId,
                  receiverId: msg.receiverId,
                  encryptedContent: msg.ciphertext || msg.encryptedContent || "",
                  iv: msg.iv,
                  timestamp: new Date(msg.timestamp),
                  signature: msg.signature,
                  nonce: msg.nonce,
                  isFile: msg.isFile,
                  fileName: msg.fileName,
                  fileType: msg.fileType,
                  fileId: msg.fileId,
                  fileSize: msg.fileSize,
                }
                try {
                  if (!msg.isFile && chatMsg.encryptedContent) {
                    const decrypted = await decryptMessage(chatMsg.encryptedContent, chatMsg.iv, sessionKey)
                    return { ...chatMsg, decryptedContent: decrypted }
                  }
                  return chatMsg
                } catch (e) {
                  console.error("[v0] Decryption failed for message:", msg.id, e)
                  return { ...chatMsg, decryptedContent: "[Decryption failed]", decryptionFailed: true }
                }
              },
            ),
          )
          setMessages(decryptedMessages)
        }
      } catch (err) {
        console.error("Failed to fetch messages:", err)
      }
    }

    fetchMessages()
    const interval = setInterval(fetchMessages, 2000)
    return () => clearInterval(interval)
  }, [currentUser, selectedUser, sessionKeys])

  const addSecurityLog = useCallback(
    (eventType: SecurityEventType, details: string, success: boolean) => {
      const log: LogEntry = {
        id: `log_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        eventType,
        userId: currentUser?.id,
        ipAddress: "127.0.0.1",
        timestamp: new Date(),
        details,
        success,
      }
      setSecurityLogs((prev) => [log, ...prev].slice(0, 1000))
    },
    [currentUser],
  )

  const handleLogin = (
    user: { id: string; username: string; publicKey: string; signaturePublicKey: string },
    token: string,
    password: string,
  ) => {
    setCurrentUser(user)
    setSessionToken(token)
    setUserPassword(password)
    addSecurityLog("AUTH_SUCCESS", `User ${user.username} logged in`, true)
  }

  const handleRegister = (user: { id: string; username: string; publicKey: string; signaturePublicKey: string }) => {
    setAuthTab("login")
    addSecurityLog("AUTH_SUCCESS", `User ${user.username} registered`, true)
  }

  const handleLogout = () => {
    setCurrentUser(null)
    setSessionToken(null)
    setUserPassword(null)
    setSelectedUser(null)
    setMessages([])
    setSessionKeys(new Map())
    setKeyExchangeStatus(new Map())
    setPrivateKeys({ ecdh: null, ecdsa: null })
    addSecurityLog("AUTH_SUCCESS", "User logged out", true)
  }

  const handleSelectUser = async (user: UserInfo) => {
    setSelectedUser(user)
    setMessages([])

    if (!currentUser || !privateKeys.ecdh) return

    const convId = getConversationId(currentUser.id, user.id)

    // Check if we already have a session key
    if (sessionKeys.has(convId)) {
      setKeyExchangeStatus((prev) => new Map(prev).set(convId, "complete"))
      return
    }

    // This allows both parties to derive the same key without explicit "key exchange"
    try {
      const peerPublicKeyBytes = Uint8Array.from(atob(user.publicKey), (c) => c.charCodeAt(0))
      const peerPublicKey = await window.crypto.subtle.importKey(
        "spki",
        peerPublicKeyBytes,
        { name: "ECDH", namedCurve: "P-256" },
        true,
        [],
      )

      // Derive shared secret using ECDH
      const sharedSecret = await window.crypto.subtle.deriveBits(
        { name: "ECDH", public: peerPublicKey },
        privateKeys.ecdh,
        256,
      )

      // Use sorted IDs for consistent key derivation on both sides
      const info = new TextEncoder().encode(`SecureMessaging-SessionKey-v1|${convId}`)

      const keyMaterial = await window.crypto.subtle.importKey("raw", sharedSecret, "HKDF", false, ["deriveKey"])

      const sessionKey = await window.crypto.subtle.deriveKey(
        {
          name: "HKDF",
          hash: "SHA-256",
          salt: new Uint8Array(32),
          info: info,
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"],
      )

      // Store the derived key
      setSessionKeys((prev) => new Map(prev).set(convId, sessionKey))
      setKeyExchangeStatus((prev) => new Map(prev).set(convId, "complete"))

      // Persist to IndexedDB
      await storeSessionKey(convId, sessionKey, currentUser.id)

      // Log automatic key exchange to server (for audit/proof)
      if (privateKeys.ecdsa && sessionToken) {
        try {
          const nonce = generateNonce()
          const timestamp = Date.now()
          const signatureData = `${currentUser.id}|${user.id}|${timestamp}|${nonce}`
          const signature = await signMessage(signatureData, privateKeys.ecdsa)

          await fetch("/api/key-exchange", {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              Authorization: `Bearer ${sessionToken}`,
            },
            body: JSON.stringify({
              type: "KEY_EXCHANGE_AUTO",
              senderId: currentUser.id,
              receiverId: user.id,
              signature,
              timestamp,
              nonce,
            }),
          })
        } catch (apiErr) {
          console.error("Failed to log automatic key exchange:", apiErr)
          // Don't fail the entire key exchange if logging fails
        }
      }

      addSecurityLog("KEY_EXCHANGE_COMPLETE", `Session key derived for conversation with ${user.username}`, true)
    } catch (err) {
      console.error("Failed to derive session key:", err)
      addSecurityLog(
        "KEY_EXCHANGE_FAILURE",
        `Failed to derive key: ${err instanceof Error ? err.message : "Unknown"}`,
        false,
      )
    }
  }

  const handleInitiateKeyExchange = async () => {
    if (!currentUser || !selectedUser || !privateKeys.ecdh || !privateKeys.ecdsa) {
      setKeyExchangeState("error")
      return
    }

    setKeyExchangeState("initiating")

    try {
      const convId = getConversationId(currentUser.id, selectedUser.id)

      // Derive session key using peer's public key
      const peerPublicKeyBytes = Uint8Array.from(atob(selectedUser.publicKey), (c) => c.charCodeAt(0))
      const peerPublicKey = await window.crypto.subtle.importKey(
        "spki",
        peerPublicKeyBytes,
        { name: "ECDH", namedCurve: "P-256" },
        true,
        [],
      )

      const sharedSecret = await window.crypto.subtle.deriveBits(
        { name: "ECDH", public: peerPublicKey },
        privateKeys.ecdh,
        256,
      )

      const info = new TextEncoder().encode(`SecureMessaging-SessionKey-v1|${convId}`)
      const keyMaterial = await window.crypto.subtle.importKey("raw", sharedSecret, "HKDF", false, ["deriveKey"])

      const sessionKey = await window.crypto.subtle.deriveKey(
        {
          name: "HKDF",
          hash: "SHA-256",
          salt: new Uint8Array(32),
          info: info,
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"],
      )

      setSessionKeys((prev) => new Map(prev).set(convId, sessionKey))
      setKeyExchangeStatus((prev) => new Map(prev).set(convId, "complete"))

      // Persist to IndexedDB
      await storeSessionKey(convId, sessionKey, currentUser.id)

      // Log key exchange to server (for audit)
      const nonce = generateNonce()
      const timestamp = Date.now()
      const signatureData = `${currentUser.id}|${selectedUser.id}|${timestamp}|${nonce}`
      const signature = await signMessage(signatureData, privateKeys.ecdsa)

      await fetch("/api/key-exchange", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(sessionToken ? { Authorization: `Bearer ${sessionToken}` } : {}),
        },
        body: JSON.stringify({
          type: "KEY_EXCHANGE_INIT",
          senderId: currentUser.id,
          receiverId: selectedUser.id,
          signature,
          timestamp,
          nonce,
        }),
      })

      setKeyExchangeState("complete")
      addSecurityLog("KEY_EXCHANGE_COMPLETE", `Key exchange completed with ${selectedUser.username}`, true)

      setTimeout(() => {
        setKeyExchangeDialogOpen(false)
        setKeyExchangeState("idle")
      }, 1500)
    } catch (err) {
      console.error("Key exchange failed:", err)
      setKeyExchangeState("error")
      addSecurityLog(
        "KEY_EXCHANGE_FAILURE",
        `Key exchange failed: ${err instanceof Error ? err.message : "Unknown error"}`,
        false,
      )
    }
  }

  const handleSendMessage = async (content: string) => {
    if (!currentUser || !selectedUser) return

    const convId = getConversationId(currentUser.id, selectedUser.id)
    const sessionKey = sessionKeys.get(convId)
    if (!sessionKey || !privateKeys.ecdsa) {
      console.error("[v0] No session key for conversation:", convId)
      return
    }

    try {
      const { encrypted, iv } = await encryptMessage(content, sessionKey)
      const nonce = generateNonce()
      const timestamp = Date.now()
      const signatureData = `${encrypted}|${iv}|${nonce}|${timestamp}`
      const signature = await signMessage(signatureData, privateKeys.ecdsa)
      const messageId = `msg_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`

      const response = await fetch("/api/messages", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(sessionToken ? { Authorization: `Bearer ${sessionToken}` } : {}),
        },
        body: JSON.stringify({
          id: messageId,
          senderId: currentUser.id,
          receiverId: selectedUser.id,
          ciphertext: encrypted,
          iv,
          authTag: "",
          signature,
          nonce,
          timestamp,
          sequenceNumber: timestamp,
        }),
      })

      if (!response.ok) {
        const errorData = await response.json()
        throw new Error(errorData.error || "Failed to send message")
      }

      // Add message optimistically
      const newMessage: ChatMessage = {
        id: messageId,
        senderId: currentUser.id,
        receiverId: selectedUser.id,
        encryptedContent: encrypted,
        iv,
        timestamp: new Date(timestamp),
        signature,
        nonce,
        decryptedContent: content,
      }

      setMessages((prev) => [...prev, newMessage])
      addSecurityLog("MESSAGE_SENT", `Encrypted message sent to ${selectedUser.username}`, true)
    } catch (err) {
      console.error("Failed to send message:", err)
      addSecurityLog(
        "MESSAGE_FAILED",
        `Failed to send message: ${err instanceof Error ? err.message : "Unknown error"}`,
        false,
      )
      throw err
    }
  }

  const handleSendFile = async (file: File): Promise<void> => {
    if (!currentUser || !selectedUser) return

    const convId = getConversationId(currentUser.id, selectedUser.id)
    const sessionKey = sessionKeys.get(convId)
    if (!sessionKey || !privateKeys.ecdsa) {
      throw new Error("No session key established")
    }

    try {
      const fileBuffer = await file.arrayBuffer()
      const iv = window.crypto.getRandomValues(new Uint8Array(12))
      const encryptedFile = await window.crypto.subtle.encrypt({ name: "AES-GCM", iv }, sessionKey, fileBuffer)

      const encryptedBase64 = arrayBufferToBase64(encryptedFile)
      const ivBase64 = uint8ArrayToBase64(iv)

      // Encrypt file metadata
      const metadata = JSON.stringify({
        name: file.name,
        type: file.type,
        size: file.size,
      })
      const metadataIv = window.crypto.getRandomValues(new Uint8Array(12))
      const encryptedMetadata = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: metadataIv },
        sessionKey,
        new TextEncoder().encode(metadata),
      )

      const metadataBase64 = arrayBufferToBase64(encryptedMetadata)
      const metadataIvBase64 = uint8ArrayToBase64(metadataIv)

      const nonce = generateNonce()
      const timestamp = Date.now()
      const signatureData = `${encryptedBase64.slice(0, 100)}|${ivBase64}|${nonce}|${timestamp}`
      const signature = await signMessage(signatureData, privateKeys.ecdsa)
      const fileId = `file_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`

      const response = await fetch("/api/files", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(sessionToken ? { Authorization: `Bearer ${sessionToken}` } : {}),
        },
        body: JSON.stringify({
          id: fileId,
          senderId: currentUser.id,
          receiverId: selectedUser.id,
          encryptedData: encryptedBase64,
          iv: ivBase64,
          encryptedMetadata: metadataBase64,
          metadataIv: metadataIvBase64,
          signature,
          nonce,
          timestamp,
          sequenceNumber: timestamp,
          fileName: file.name,
          fileType: file.type,
          fileSize: file.size,
        }),
      })

      if (!response.ok) {
        throw new Error("Failed to upload file")
      }

      // Add file message locally
      const fileMessage: ChatMessage = {
        id: `msg_${fileId}`,
        senderId: currentUser.id,
        receiverId: selectedUser.id,
        encryptedContent: "",
        iv: ivBase64,
        timestamp: new Date(timestamp),
        signature,
        nonce,
        isFile: true,
        fileName: file.name,
        fileType: file.type,
        fileId,
        fileSize: file.size,
      }

      setMessages((prev) => [...prev, fileMessage])
      addSecurityLog("FILE_ENCRYPTED", `Encrypted file sent: ${file.name}`, true)
    } catch (err) {
      console.error("Failed to send file:", err)
      addSecurityLog(
        "FILE_ENCRYPTION_FAILED",
        `Failed to encrypt file: ${err instanceof Error ? err.message : "Unknown error"}`,
        false,
      )
      throw err
    }
  }

  const handleDownloadFile = async (message: ChatMessage) => {
    if (!currentUser || !message.fileId) return

    const convId = getConversationId(message.senderId, message.receiverId)
    const sessionKey = sessionKeys.get(convId)
    if (!sessionKey) {
      console.error("[v0] No session key for file download:", convId)
      addSecurityLog("FILE_DECRYPTION_FAILED", "No session key for file decryption", false)
      return
    }

    try {
      const response = await fetch(`/api/files?id=${message.fileId}`, {
        headers: sessionToken ? { Authorization: `Bearer ${sessionToken}` } : {},
      })
      if (!response.ok) throw new Error("Failed to fetch file")

      const fileData = await response.json()

      // Decrypt file
      const encryptedBytes = Uint8Array.from(atob(fileData.encryptedData), (c) => c.charCodeAt(0))
      const iv = Uint8Array.from(atob(fileData.iv), (c) => c.charCodeAt(0))

      const decryptedBuffer = await window.crypto.subtle.decrypt({ name: "AES-GCM", iv }, sessionKey, encryptedBytes)

      // Get file metadata
      let fileName = message.fileName || "download"
      let fileType = message.fileType || "application/octet-stream"

      if (fileData.encryptedMetadata && fileData.metadataIv) {
        try {
          const metaBytes = Uint8Array.from(atob(fileData.encryptedMetadata), (c) => c.charCodeAt(0))
          const metaIv = Uint8Array.from(atob(fileData.metadataIv), (c) => c.charCodeAt(0))
          const decryptedMeta = await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv: metaIv },
            sessionKey,
            metaBytes,
          )
          const metadata = JSON.parse(new TextDecoder().decode(decryptedMeta))
          fileName = metadata.name || fileName
          fileType = metadata.type || fileType
        } catch (e) {
          console.warn("Could not decrypt file metadata:", e)
        }
      }

      // Create download
      const blob = new Blob([decryptedBuffer], { type: fileType })
      const url = URL.createObjectURL(blob)
      const a = document.createElement("a")
      a.href = url
      a.download = fileName
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)

      addSecurityLog("FILE_DECRYPTED", `File decrypted and downloaded: ${fileName}`, true)
    } catch (err) {
      console.error("Failed to download file:", err)
      addSecurityLog(
        "FILE_DECRYPTION_FAILED",
        `Failed to decrypt file: ${err instanceof Error ? err.message : "Unknown error"}`,
        false,
      )
    }
  }

  const hasSessionKey =
    selectedUser && currentUser ? sessionKeys.has(getConversationId(currentUser.id, selectedUser.id)) : false

  if (!currentUser) {
    return (
      <div className="min-h-screen flex items-center justify-center p-4 bg-background relative overflow-hidden">
        {/* Animated grid background */}
        <div className="absolute inset-0 opacity-20">
          <div
            className="absolute inset-0"
            style={{
              backgroundImage: `linear-gradient(rgba(0,255,136,0.1) 1px, transparent 1px), linear-gradient(90deg, rgba(0,255,136,0.1) 1px, transparent 1px)`,
              backgroundSize: "50px 50px",
            }}
          />
        </div>

        {/* Floating elements */}
        <div className="absolute top-20 left-20 text-[120px] font-bold text-primary/5 select-none">V0</div>
        <div className="absolute bottom-20 right-20 text-[80px] font-bold text-primary/5 select-none rotate-12">ID</div>

        <div className="relative w-full max-w-md">
          {/* Terminal header */}
          <div className="border-2 border-primary bg-background">
            <div className="flex items-center gap-2 px-4 py-2 border-b-2 border-primary bg-primary/10">
              <Terminal className="w-4 h-4 text-primary" />
              <span className="text-xs text-primary uppercase tracking-widest">VØID_LINK TERMINAL v2.0.1</span>
              <div className="ml-auto flex gap-1">
                <div className="w-2 h-2 bg-primary" />
                <div className="w-2 h-2 bg-primary/50" />
                <div className="w-2 h-2 bg-primary/30" />
              </div>
            </div>

            <div className="p-8 space-y-8">
              {/* ASCII Art Logo */}
              <div className="text-center space-y-2">
                <pre className="text-primary text-xs leading-none font-mono flicker">
                  {`██╗   ██╗ ██████╗ ██╗██████╗ 
██║   ██║██╔═══██╗██║██╔══██╗
██║   ██║██║   ██║██║██║  ██║
╚██╗ ██╔╝██║   ██║██║██║  ██║
 ╚████╔╝ ╚██████╔╝██║██████╔╝
  ╚═══╝   ╚═════╝ ╚═╝╚═════╝ `}
                </pre>
                <p className="text-xs text-muted-foreground uppercase tracking-[0.3em]">[ ENCRYPTED COMMS PROTOCOL ]</p>
              </div>

              <Tabs value={authTab} onValueChange={(v) => setAuthTab(v as "login" | "register")}>
                <TabsList className="grid w-full grid-cols-2 bg-transparent gap-2 p-0 h-auto">
                  <TabsTrigger
                    value="login"
                    className="border-2 border-primary data-[state=active]:bg-primary data-[state=active]:text-background data-[state=inactive]:bg-transparent data-[state=inactive]:text-primary py-3 uppercase tracking-widest text-xs font-bold"
                  >
                    {">"} ACCESS
                  </TabsTrigger>
                  <TabsTrigger
                    value="register"
                    className="border-2 border-primary data-[state=active]:bg-primary data-[state=active]:text-background data-[state=inactive]:bg-transparent data-[state=inactive]:text-primary py-3 uppercase tracking-widest text-xs font-bold"
                  >
                    {">"} REGISTER
                  </TabsTrigger>
                </TabsList>
                <TabsContent value="login" className="mt-6">
                  <LoginForm onLogin={handleLogin} />
                </TabsContent>
                <TabsContent value="register" className="mt-6">
                  <RegisterForm onRegister={handleRegister} />
                </TabsContent>
              </Tabs>

              <div className="text-center space-y-1 pt-4 border-t-2 border-primary/30">
                <p className="text-[10px] text-primary/60 uppercase tracking-widest">
                  AES-256-GCM // ECDH P-256 // HKDF-SHA256
                </p>
                <p className="text-[10px] text-muted-foreground">NO LOGS • NO TRACES • ZERO KNOWLEDGE</p>
              </div>
            </div>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="border-b-2 border-primary bg-background sticky top-0 z-50">
        <div className="container mx-auto px-4 py-2 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2">
              <Skull className="w-6 h-6 text-primary flicker" />
              <span className="font-bold text-xl tracking-tighter text-primary">VØID</span>
            </div>
            <div className="hidden sm:flex items-center gap-2 px-3 py-1 border border-primary/30 text-xs text-primary/60">
              <Zap className="w-3 h-3" />
              <span className="uppercase tracking-widest">ENCRYPTED</span>
            </div>
          </div>

          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2 px-3 py-1 border border-primary text-primary">
              <Radio className="w-3 h-3 animate-pulse" />
              <span className="text-xs uppercase tracking-wider">{currentUser.username}</span>
            </div>
            <button
              onClick={handleLogout}
              className="flex items-center gap-2 px-3 py-1 border-2 border-destructive text-destructive hover:bg-destructive hover:text-background transition-colors text-xs uppercase tracking-widest"
            >
              <Power className="w-3 h-3" />
              <span className="hidden sm:inline">DISCONNECT</span>
            </button>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="container mx-auto p-4">
        <Tabs defaultValue="chat" className="space-y-4">
          <TabsList className="grid w-full grid-cols-2 lg:w-auto lg:inline-grid bg-transparent gap-2 p-0 h-auto">
            <TabsTrigger
              value="chat"
              className="border-2 border-primary data-[state=active]:bg-primary data-[state=active]:text-background data-[state=inactive]:bg-transparent data-[state=inactive]:text-primary py-2 px-6 uppercase tracking-widest text-xs font-bold gap-2"
            >
              <Terminal className="w-4 h-4" />
              <span>COMMS</span>
            </TabsTrigger>
            <TabsTrigger
              value="security"
              className="border-2 border-primary data-[state=active]:bg-primary data-[state=active]:text-background data-[state=inactive]:bg-transparent data-[state=inactive]:text-primary py-2 px-6 uppercase tracking-widest text-xs font-bold gap-2"
            >
              <Eye className="w-4 h-4" />
              <span>LOGS</span>
            </TabsTrigger>
          </TabsList>

          {/* Chat Tab */}
          <TabsContent value="chat" className="space-y-4">
            <div className="grid md:grid-cols-[300px_1fr] gap-4 h-[calc(100vh-180px)]">
              {/* User List */}
              <div className="border-2 border-primary overflow-hidden flex flex-col">
                <div className="px-4 py-3 border-b-2 border-primary bg-primary/5 flex items-center justify-between">
                  <span className="text-xs uppercase tracking-widest text-primary font-bold">NODES</span>
                  <div className="w-2 h-2 bg-primary animate-pulse" />
                </div>
                <div className="flex-1 overflow-auto p-2">
                  <UserList
                    currentUser={currentUser}
                    selectedUser={selectedUser}
                    onSelectUser={handleSelectUser}
                    keyExchangeStatus={keyExchangeStatus}
                    sessionToken={sessionToken}
                  />
                </div>
              </div>

              {/* Chat Area */}
              <div className="border-2 border-primary flex flex-col overflow-hidden">
                {selectedUser ? (
                  <>
                    {/* Chat Header */}
                    <div className="px-4 py-3 border-b-2 border-primary bg-primary/5 flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <div className="w-8 h-8 border-2 border-primary flex items-center justify-center bg-primary/10">
                          <span className="text-primary font-bold text-sm">
                            {selectedUser.username.charAt(0).toUpperCase()}
                          </span>
                        </div>
                        <div>
                          <span className="font-bold text-sm uppercase tracking-wider text-primary">
                            {selectedUser.username}
                          </span>
                          {hasSessionKey && (
                            <span className="block text-[10px] text-primary/60 uppercase tracking-widest flex items-center gap-1">
                              <EyeOff className="w-3 h-3" />
                              E2E ENCRYPTED
                            </span>
                          )}
                        </div>
                      </div>
                      {!hasSessionKey && (
                        <button
                          onClick={() => setKeyExchangeDialogOpen(true)}
                          className="flex items-center gap-2 px-3 py-1 border-2 border-accent text-accent hover:bg-accent hover:text-background transition-colors text-xs uppercase tracking-widest"
                        >
                          <Zap className="w-3 h-3" />
                          HANDSHAKE
                        </button>
                      )}
                    </div>

                    {/* Messages */}
                    <div className="flex-1 overflow-auto bg-background/50">
                      {hasSessionKey ? (
                        <MessageList
                          messages={messages}
                          currentUserId={currentUser.id}
                          onDownloadFile={handleDownloadFile}
                        />
                      ) : (
                        <div className="h-full flex items-center justify-center text-muted-foreground p-8">
                          <div className="text-center space-y-4 border-2 border-dashed border-primary/30 p-8">
                            <EyeOff className="w-12 h-12 mx-auto text-primary/30" />
                            <div>
                              <p className="text-xs uppercase tracking-widest text-primary/60">DERIVING KEY...</p>
                              <p className="text-[10px] text-muted-foreground mt-1">ECDH HANDSHAKE IN PROGRESS</p>
                            </div>
                          </div>
                        </div>
                      )}
                    </div>

                    {/* Message Input */}
                    {hasSessionKey && (
                      <div className="p-4 border-t-2 border-primary bg-primary/5">
                        <div className="flex gap-3">
                          <div className="flex-1">
                            <MessageInput onSend={handleSendMessage} disabled={!hasSessionKey} />
                          </div>
                          <FileUploadButton onUpload={handleSendFile} disabled={!hasSessionKey} />
                        </div>
                      </div>
                    )}
                  </>
                ) : (
                  <div className="flex-1 flex items-center justify-center text-muted-foreground">
                    <div className="text-center space-y-4 border-2 border-dashed border-primary/30 p-12">
                      <Terminal className="w-16 h-16 mx-auto text-primary/30" />
                      <div>
                        <p className="text-sm uppercase tracking-widest text-primary/60">SELECT NODE</p>
                        <p className="text-[10px] text-muted-foreground mt-1">CHOOSE TARGET FROM LIST</p>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </TabsContent>

          {/* Security Tab */}
          <TabsContent value="security">
            <SecurityLogs logs={securityLogs} />
          </TabsContent>
        </Tabs>
      </main>

      {/* Key Exchange Dialog */}
      <KeyExchangeDialog
        open={keyExchangeDialogOpen}
        onOpenChange={setKeyExchangeDialogOpen}
        state={keyExchangeState}
        peerUsername={selectedUser?.username || ""}
        onInitiate={handleInitiateKeyExchange}
      />
    </div>
  )
}
