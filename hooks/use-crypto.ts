// React hook for cryptographic operations

"use client"

import { useState, useCallback, useRef, useEffect } from "react"
import { generateECDHKeyPair, generateSigningKeyPair, exportPublicKey } from "@/lib/crypto/key-generation"
import { storePrivateKey, retrievePrivateKey } from "@/lib/crypto/key-storage"
import {
  initiateKeyExchange,
  respondToKeyExchange,
  completeKeyExchange,
  type KeyExchangeState,
} from "@/lib/crypto/key-exchange"
import { encryptMessage, decryptMessage } from "@/lib/crypto/encryption"
import { encryptFile, decryptFile } from "@/lib/crypto/file-encryption"
import { getReplayProtectionManager, type ReplayProtectionManager } from "@/lib/crypto/replay-protection"
import { getSecurityLogger } from "@/lib/security-logger"
import { storeSessionKey } from "@/lib/crypto/session-storage"
import type { KeyPair, EncryptedMessage, EncryptedFile, KeyExchangeMessage } from "@/lib/types"
import { importPublicKey } from "@/lib/crypto/key-generation"

interface CryptoState {
  ecdhKeyPair: KeyPair | null
  signingKeyPair: KeyPair | null
  sessionKeys: Map<string, CryptoKey>
  isInitialized: boolean
}

export function useCrypto(userId: string | null, password: string | null) {
  const [state, setState] = useState<CryptoState>({
    ecdhKeyPair: null,
    signingKeyPair: null,
    sessionKeys: new Map(),
    isInitialized: false,
  })

  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const replayProtection = useRef<ReplayProtectionManager>(getReplayProtectionManager())
  const securityLogger = useRef(getSecurityLogger())
  const keyExchangeStates = useRef<Map<string, KeyExchangeState>>(new Map())

  // Initialize cryptographic keys
  const initializeKeys = useCallback(async () => {
    if (!userId || !password) return

    setIsLoading(true)
    setError(null)

    try {
      // Try to retrieve existing keys
      const existingEcdhPrivate = await retrievePrivateKey(`${userId}_ecdh`, password)
      const existingSigningPrivate = await retrievePrivateKey(`${userId}_signing`, password)

      if (existingEcdhPrivate && existingSigningPrivate) {
        // Keys exist, import public keys from server
        console.log("[v0] Retrieved existing keys from storage")
        setState((prev) => ({
          ...prev,
          ecdhKeyPair: { privateKey: existingEcdhPrivate, publicKey: existingEcdhPrivate }, // Will fetch public from server
          signingKeyPair: { privateKey: existingSigningPrivate, publicKey: existingSigningPrivate },
          isInitialized: true,
        }))
      } else {
        // Generate new key pairs
        console.log("[v0] Generating new key pairs")
        const ecdhKeyPair = await generateECDHKeyPair()
        const signingKeyPair = await generateSigningKeyPair()

        // Store private keys securely
        await storePrivateKey(`${userId}_ecdh`, ecdhKeyPair.privateKey, password, "ECDH")
        await storePrivateKey(`${userId}_signing`, signingKeyPair.privateKey, password, "ECDSA")

        setState((prev) => ({
          ...prev,
          ecdhKeyPair,
          signingKeyPair,
          isInitialized: true,
        }))

        securityLogger.current.log("AUTH_SUCCESS", `Keys generated and stored for user ${userId}`, true, { userId })
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : "Failed to initialize keys"
      setError(message)
      securityLogger.current.log("AUTH_FAILURE", `Key initialization failed for user ${userId}: ${message}`, false, {
        userId,
      })
    } finally {
      setIsLoading(false)
    }
  }, [userId, password])

  // Export public keys for registration/sharing
  const getPublicKeys = useCallback(async () => {
    if (!state.ecdhKeyPair || !state.signingKeyPair) {
      throw new Error("Keys not initialized")
    }

    const publicKey = await exportPublicKey(state.ecdhKeyPair.publicKey)
    const signaturePublicKey = await exportPublicKey(state.signingKeyPair.publicKey)

    return { publicKey, signaturePublicKey }
  }, [state.ecdhKeyPair, state.signingKeyPair])

  // Start key exchange with another user
  const startKeyExchange = useCallback(
    async (receiverId: string, receiverSigningPublicKey: string): Promise<KeyExchangeMessage | null> => {
      if (!userId || !state.signingKeyPair) {
        setError("Not initialized")
        return null
      }

      try {
        const { state: kexState, message } = await initiateKeyExchange(
          userId,
          receiverId,
          state.signingKeyPair.privateKey,
        )

        // Store key exchange state
        keyExchangeStates.current.set(receiverId, kexState)

        securityLogger.current.logKeyExchange(userId, receiverId, true, "init")

        return message
      } catch (err) {
        const message = err instanceof Error ? err.message : "Key exchange failed"
        setError(message)
        securityLogger.current.logKeyExchange(userId, receiverId, false, "failure", message)
        return null
      }
    },
    [userId, state.signingKeyPair],
  )

  // Respond to key exchange from another user
  const handleKeyExchangeInit = useCallback(
    async (
      initMessage: KeyExchangeMessage,
      senderSigningPublicKey: string,
    ): Promise<{ response: KeyExchangeMessage; sessionKey: CryptoKey } | null> => {
      if (!userId || !state.signingKeyPair) {
        setError("Not initialized")
        return null
      }

      try {
        // Import sender's signing public key
        const peerSigningKey = await importPublicKey(senderSigningPublicKey, "ECDSA")

        const result = await respondToKeyExchange(initMessage, userId, state.signingKeyPair.privateKey, peerSigningKey)

        if (!result) {
          securityLogger.current.log(
            "AUTH_FAILURE",
            `Invalid signature in key exchange from ${initMessage.senderId}`,
            false,
            {},
          )
          return null
        }

        // Store key exchange state and session key
        keyExchangeStates.current.set(initMessage.senderId, result.state)

        // Store session key
        const conversationId = [userId, initMessage.senderId].sort().join(":")
        setState((prev) => {
          const newSessionKeys = new Map(prev.sessionKeys)
          newSessionKeys.set(conversationId, result.sessionKey)
          return { ...prev, sessionKeys: newSessionKeys }
        })

        await storeSessionKey(conversationId, result.sessionKey, userId)

        // Initialize replay protection for this conversation
        replayProtection.current.initializeConversation(conversationId)

        securityLogger.current.logKeyExchange(initMessage.senderId, userId, true, "complete")

        return { response: result.message, sessionKey: result.sessionKey }
      } catch (err) {
        const message = err instanceof Error ? err.message : "Key exchange response failed"
        setError(message)
        securityLogger.current.logKeyExchange(initMessage.senderId, userId, false, "failure", message)
        return null
      }
    },
    [userId, state.signingKeyPair],
  )

  // Complete key exchange (initiator side)
  const handleKeyExchangeResponse = useCallback(
    async (responseMessage: KeyExchangeMessage, senderSigningPublicKey: string): Promise<CryptoKey | null> => {
      if (!userId) {
        setError("Not initialized")
        return null
      }

      try {
        const kexState = keyExchangeStates.current.get(responseMessage.senderId)
        if (!kexState) {
          setError("No pending key exchange")
          return null
        }

        // Import peer's signing public key
        const peerSigningKey = await importPublicKey(senderSigningPublicKey, "ECDSA")

        const result = await completeKeyExchange(responseMessage, kexState, userId, peerSigningKey)

        if (!result) {
          securityLogger.current.log(
            "AUTH_FAILURE",
            `Invalid signature in key exchange response from ${responseMessage.senderId}`,
            false,
            {},
          )
          return null
        }

        // Store session key
        const conversationId = [userId, responseMessage.senderId].sort().join(":")
        setState((prev) => {
          const newSessionKeys = new Map(prev.sessionKeys)
          newSessionKeys.set(conversationId, result.sessionKey)
          return { ...prev, sessionKeys: newSessionKeys }
        })

        await storeSessionKey(conversationId, result.sessionKey, userId)

        // Initialize replay protection for this conversation
        replayProtection.current.initializeConversation(conversationId)

        // Update key exchange state
        keyExchangeStates.current.set(responseMessage.senderId, result.state)

        securityLogger.current.logKeyExchange(responseMessage.senderId, userId, true, "complete")

        return result.sessionKey
      } catch (err) {
        const message = err instanceof Error ? err.message : "Key exchange completion failed"
        setError(message)
        securityLogger.current.logKeyExchange(responseMessage.senderId, userId, false, "failure", message)
        return null
      }
    },
    [userId],
  )

  const setSessionKeyForUser = useCallback(
    async (peerId: string, sessionKey: CryptoKey) => {
      if (!userId) return

      const conversationId = [userId, peerId].sort().join(":")
      setState((prev) => {
        const newSessionKeys = new Map(prev.sessionKeys)
        newSessionKeys.set(conversationId, sessionKey)
        return { ...prev, sessionKeys: newSessionKeys }
      })

      await storeSessionKey(conversationId, sessionKey, userId)
      replayProtection.current.initializeConversation(conversationId)

      console.log("[v0] Session key set for conversation:", conversationId)
    },
    [userId],
  )

  // Encrypt a message
  const encryptMessageForUser = useCallback(
    async (plaintext: string, receiverId: string): Promise<EncryptedMessage | null> => {
      if (!userId || !state.signingKeyPair) {
        setError("Not initialized")
        return null
      }

      const conversationId = [userId, receiverId].sort().join(":")
      const sessionKey = state.sessionKeys.get(conversationId)

      if (!sessionKey) {
        setError("No session key for this conversation")
        return null
      }

      try {
        const sequenceNumber = replayProtection.current.getNextSequenceNumber(conversationId)

        const encrypted = await encryptMessage(
          plaintext,
          sessionKey,
          userId,
          receiverId,
          state.signingKeyPair.privateKey,
          sequenceNumber,
        )

        return encrypted
      } catch (err) {
        const message = err instanceof Error ? err.message : "Encryption failed"
        setError(message)
        return null
      }
    },
    [userId, state.signingKeyPair, state.sessionKeys],
  )

  // Decrypt a message
  const decryptMessageFromUser = useCallback(
    async (encryptedMessage: EncryptedMessage, senderSigningPublicKey: string): Promise<string | null> => {
      if (!userId) {
        setError("Not initialized")
        return null
      }

      const conversationId = [userId, encryptedMessage.senderId].sort().join(":")
      const sessionKey = state.sessionKeys.get(conversationId)

      if (!sessionKey) {
        setError("No session key for this conversation")
        securityLogger.current.logDecryptionFailure(userId, encryptedMessage.id, "No session key")
        return null
      }

      try {
        // Verify replay protection
        const replayCheck = replayProtection.current.verifyNotReplay(
          conversationId,
          encryptedMessage.nonce,
          encryptedMessage.timestamp,
          encryptedMessage.sequenceNumber,
        )

        if (!replayCheck.valid) {
          securityLogger.current.logReplayAttack(userId, replayCheck.reason || "Unknown", {
            messageId: encryptedMessage.id,
            senderId: encryptedMessage.senderId,
            sequenceNumber: encryptedMessage.sequenceNumber,
          })
          setError(`Replay attack detected: ${replayCheck.reason}`)
          return null
        }

        // Import sender's signing public key
        const senderKey = await importPublicKey(senderSigningPublicKey, "ECDSA")

        // Get expected sequence number (for additional validation)
        const expectedSeq = Math.max(0, encryptedMessage.sequenceNumber - 1)

        const result = await decryptMessage(encryptedMessage, sessionKey, senderKey, expectedSeq)

        if (!result) {
          securityLogger.current.logDecryptionFailure(
            userId,
            encryptedMessage.id,
            "Decryption or signature verification failed",
          )
          securityLogger.current.logInvalidSignature(encryptedMessage.senderId, userId, "MESSAGE")
          return null
        }

        return result
      } catch (err) {
        const message = err instanceof Error ? err.message : "Decryption failed"
        setError(message)
        securityLogger.current.logDecryptionFailure(userId, encryptedMessage.id, message)
        return null
      }
    },
    [userId, state.sessionKeys],
  )

  // Encrypt a file
  const encryptFileForUser = useCallback(
    async (file: File, receiverId: string): Promise<EncryptedFile | null> => {
      if (!userId || !state.signingKeyPair) {
        setError("Not initialized")
        return null
      }

      const conversationId = [userId, receiverId].sort().join(":")
      const sessionKey = state.sessionKeys.get(conversationId)

      if (!sessionKey) {
        setError("No session key for this conversation")
        return null
      }

      try {
        const encrypted = await encryptFile(file, sessionKey, userId, receiverId, state.signingKeyPair.privateKey)

        securityLogger.current.logFileOperation(userId, "upload", encrypted.id, true)

        return encrypted
      } catch (err) {
        const message = err instanceof Error ? err.message : "File encryption failed"
        setError(message)
        return null
      }
    },
    [userId, state.signingKeyPair, state.sessionKeys],
  )

  // Decrypt a file
  const decryptFileFromUser = useCallback(
    async (
      encryptedFile: EncryptedFile,
      senderSigningPublicKey: string,
    ): Promise<{ data: Blob; fileName: string } | null> => {
      if (!userId) {
        setError("Not initialized")
        return null
      }

      const conversationId = [userId, encryptedFile.senderId].sort().join(":")
      const sessionKey = state.sessionKeys.get(conversationId)

      if (!sessionKey) {
        setError("No session key for this conversation")
        return null
      }

      try {
        // Import sender's signing public key
        const senderKey = await importPublicKey(senderSigningPublicKey, "ECDSA")

        const result = await decryptFile(encryptedFile, sessionKey, senderKey)

        if (!result) {
          securityLogger.current.logFileOperation(userId, "download", encryptedFile.id, false)
          return null
        }

        securityLogger.current.logFileOperation(userId, "download", encryptedFile.id, true)

        return result
      } catch (err) {
        const message = err instanceof Error ? err.message : "File decryption failed"
        setError(message)
        securityLogger.current.logFileOperation(userId, "download", encryptedFile.id, false)
        return null
      }
    },
    [userId, state.sessionKeys],
  )

  // Get security logs
  const getSecurityLogs = useCallback(() => {
    return securityLogger.current.getLogs()
  }, [])

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      // Don't destroy shared replay protection manager
    }
  }, [])

  return {
    state,
    isLoading,
    error,
    initializeKeys,
    getPublicKeys,
    startKeyExchange,
    handleKeyExchangeInit,
    handleKeyExchangeResponse,
    setSessionKeyForUser,
    encryptMessageForUser,
    decryptMessageFromUser,
    encryptFileForUser,
    decryptFileFromUser,
    getSecurityLogs,
    clearError: () => setError(null),
  }
}
