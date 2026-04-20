// Cryptographic constants and configurations

export const CRYPTO_CONFIG = {
  // RSA Configuration
  RSA: {
    name: "RSA-OAEP",
    modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: "SHA-256",
  },

  // ECDH Configuration for Key Exchange
  ECDH: {
    name: "ECDH",
    namedCurve: "P-256", // NIST curve as required
  },

  // ECDSA Configuration for Digital Signatures
  ECDSA: {
    name: "ECDSA",
    namedCurve: "P-256",
    hash: "SHA-256",
  },

  // AES-GCM Configuration for Symmetric Encryption
  AES_GCM: {
    name: "AES-GCM",
    length: 256, // AES-256-GCM as required
    tagLength: 128, // Authentication tag length in bits
  },

  // IV/Nonce sizes
  IV_LENGTH: 12, // 96 bits for AES-GCM
  NONCE_LENGTH: 16, // 128 bits for replay protection

  // Key derivation
  HKDF: {
    name: "HKDF",
    hash: "SHA-256",
    salt: new Uint8Array(32), // Will be generated per session
    info: new TextEncoder().encode("SecureMessaging-E2EE-v1"),
  },

  // Session key validity
  SESSION_KEY_VALIDITY_MS: 24 * 60 * 60 * 1000, // 24 hours

  // Replay protection window
  REPLAY_WINDOW_MS: 5 * 60 * 1000, // 5 minutes
  MAX_SEQUENCE_GAP: 100,

  // File chunk size for encrypted file sharing
  FILE_CHUNK_SIZE: 64 * 1024, // 64KB chunks
}

// Database collection names
export const COLLECTIONS = {
  USERS: "users",
  MESSAGES: "encrypted_messages",
  FILES: "encrypted_files",
  KEY_EXCHANGES: "key_exchanges",
  SECURITY_LOGS: "security_logs",
  SESSIONS: "sessions",
}
