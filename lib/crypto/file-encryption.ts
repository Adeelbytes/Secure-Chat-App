// E2E Encrypted File Sharing Implementation

import { CRYPTO_CONFIG } from "./constants"
import { arrayBufferToBase64, base64ToArrayBuffer, generateIV, generateFileId, getCurrentTimestamp } from "./utils"
import { signData, verifySignature } from "./signatures"
import type { EncryptedFile, EncryptedChunk } from "../types"

/**
 * Encrypt a file client-side before uploading
 * Splits file into chunks and encrypts each with AES-256-GCM
 */
export async function encryptFile(
  file: File,
  sessionKey: CryptoKey,
  senderId: string,
  receiverId: string,
  signingKey: CryptoKey,
): Promise<EncryptedFile> {
  const fileBuffer = await file.arrayBuffer()
  const chunks: EncryptedChunk[] = []

  // Split file into chunks and encrypt each
  const chunkSize = CRYPTO_CONFIG.FILE_CHUNK_SIZE
  const totalChunks = Math.ceil(fileBuffer.byteLength / chunkSize)

  for (let i = 0; i < totalChunks; i++) {
    const start = i * chunkSize
    const end = Math.min(start + chunkSize, fileBuffer.byteLength)
    const chunkData = fileBuffer.slice(start, end)

    // Generate fresh IV for each chunk
    const iv = generateIV()

    // Encrypt chunk
    const ciphertext = await crypto.subtle.encrypt(
      {
        name: CRYPTO_CONFIG.AES_GCM.name,
        iv: iv,
        tagLength: CRYPTO_CONFIG.AES_GCM.tagLength,
      },
      sessionKey,
      chunkData,
    )

    chunks.push({
      index: i,
      ciphertext: arrayBufferToBase64(ciphertext),
      iv: arrayBufferToBase64(iv.buffer),
      authTag: "", // Included in GCM ciphertext
    })
  }

  // Encrypt filename
  const fileNameIv = generateIV()
  const encryptedFileName = await crypto.subtle.encrypt(
    {
      name: CRYPTO_CONFIG.AES_GCM.name,
      iv: fileNameIv,
      tagLength: CRYPTO_CONFIG.AES_GCM.tagLength,
    },
    sessionKey,
    new TextEncoder().encode(file.name),
  )

  const timestamp = getCurrentTimestamp()

  // Create signature over file metadata
  const signatureData = new TextEncoder().encode(`${senderId}|${receiverId}|${file.size}|${totalChunks}|${timestamp}`)
  const signature = await signData(signatureData, signingKey)

  return {
    id: generateFileId(),
    senderId,
    receiverId,
    fileName: `${arrayBufferToBase64(encryptedFileName)}|${arrayBufferToBase64(fileNameIv.buffer)}`,
    fileSize: file.size,
    chunks,
    timestamp,
    signature,
  }
}

/**
 * Decrypt a file client-side after downloading
 */
export async function decryptFile(
  encryptedFile: EncryptedFile,
  sessionKey: CryptoKey,
  senderSigningKey: CryptoKey,
): Promise<{ data: Blob; fileName: string } | null> {
  // Verify signature
  const signatureData = new TextEncoder().encode(
    `${encryptedFile.senderId}|${encryptedFile.receiverId}|${encryptedFile.fileSize}|${encryptedFile.chunks.length}|${encryptedFile.timestamp}`,
  )

  const isValid = await verifySignature(signatureData, encryptedFile.signature, senderSigningKey)

  if (!isValid) {
    console.error("[v0] File decryption: Invalid signature")
    return null
  }

  try {
    // Decrypt filename
    const [encryptedNameB64, nameIvB64] = encryptedFile.fileName.split("|")
    const encryptedName = base64ToArrayBuffer(encryptedNameB64)
    const nameIv = new Uint8Array(base64ToArrayBuffer(nameIvB64))

    const decryptedNameBuffer = await crypto.subtle.decrypt(
      {
        name: CRYPTO_CONFIG.AES_GCM.name,
        iv: nameIv,
        tagLength: CRYPTO_CONFIG.AES_GCM.tagLength,
      },
      sessionKey,
      encryptedName,
    )

    const fileName = new TextDecoder().decode(decryptedNameBuffer)

    // Decrypt all chunks
    const decryptedChunks: ArrayBuffer[] = []

    // Sort chunks by index
    const sortedChunks = [...encryptedFile.chunks].sort((a, b) => a.index - b.index)

    for (const chunk of sortedChunks) {
      const ciphertext = base64ToArrayBuffer(chunk.ciphertext)
      const iv = new Uint8Array(base64ToArrayBuffer(chunk.iv))

      const decryptedChunk = await crypto.subtle.decrypt(
        {
          name: CRYPTO_CONFIG.AES_GCM.name,
          iv: iv,
          tagLength: CRYPTO_CONFIG.AES_GCM.tagLength,
        },
        sessionKey,
        ciphertext,
      )

      decryptedChunks.push(decryptedChunk)
    }

    // Combine chunks into single Blob
    const data = new Blob(decryptedChunks)

    return { data, fileName }
  } catch (error) {
    console.error("[v0] File decryption failed:", error)
    return null
  }
}

/**
 * Get file encryption progress callback
 */
export function createProgressCallback(onProgress: (progress: number) => void) {
  return (current: number, total: number) => {
    const progress = Math.round((current / total) * 100)
    onProgress(progress)
  }
}
