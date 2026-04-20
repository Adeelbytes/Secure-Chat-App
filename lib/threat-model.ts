// STRIDE Threat Model for Secure Messaging System

import type { ThreatModel } from "./types"

/**
 * STRIDE Threat Model Analysis
 * S - Spoofing
 * T - Tampering
 * R - Repudiation
 * I - Information Disclosure
 * D - Denial of Service
 * E - Elevation of Privilege
 */
export const threatModel: ThreatModel[] = [
  // SPOOFING THREATS
  {
    threat: "User Identity Spoofing",
    category: "Spoofing",
    vulnerableComponent: "Authentication System",
    countermeasure: "Password hashing with bcrypt/argon2, session tokens, and digital signatures for all messages",
    implemented: true,
  },
  {
    threat: "Key Spoofing in Key Exchange",
    category: "Spoofing",
    vulnerableComponent: "Key Exchange Protocol",
    countermeasure: "Digital signatures (ECDSA) on all key exchange messages using long-term signing keys",
    implemented: true,
  },
  {
    threat: "Message Sender Spoofing",
    category: "Spoofing",
    vulnerableComponent: "Messaging System",
    countermeasure: "All messages are signed with sender's ECDSA private key; signature verified on receipt",
    implemented: true,
  },

  // TAMPERING THREATS
  {
    threat: "Message Content Tampering",
    category: "Tampering",
    vulnerableComponent: "Message Transmission",
    countermeasure: "AES-256-GCM provides authenticated encryption; any modification invalidates the auth tag",
    implemented: true,
  },
  {
    threat: "Key Exchange Message Tampering",
    category: "Tampering",
    vulnerableComponent: "Key Exchange Protocol",
    countermeasure:
      "ECDSA signatures cover all key exchange parameters; tampering detection via signature verification",
    implemented: true,
  },
  {
    threat: "File Chunk Tampering",
    category: "Tampering",
    vulnerableComponent: "File Sharing System",
    countermeasure: "Each chunk encrypted with AES-GCM; file metadata signed; tampered chunks fail decryption",
    implemented: true,
  },
  {
    threat: "Database Tampering",
    category: "Tampering",
    vulnerableComponent: "Server Storage",
    countermeasure: "Only encrypted data stored; any modification results in decryption failure; comprehensive logging",
    implemented: true,
  },

  // REPUDIATION THREATS
  {
    threat: "Message Sending Denial",
    category: "Repudiation",
    vulnerableComponent: "Messaging System",
    countermeasure: "All messages include digital signatures that prove sender authenticity; comprehensive audit logs",
    implemented: true,
  },
  {
    threat: "Key Exchange Denial",
    category: "Repudiation",
    vulnerableComponent: "Key Exchange Protocol",
    countermeasure: "Signed key exchange messages and key confirmation; all events logged with timestamps",
    implemented: true,
  },
  {
    threat: "Authentication Action Denial",
    category: "Repudiation",
    vulnerableComponent: "Authentication System",
    countermeasure: "Comprehensive logging of all auth attempts with timestamps, IP addresses, and outcomes",
    implemented: true,
  },

  // INFORMATION DISCLOSURE THREATS
  {
    threat: "Plaintext Message Exposure",
    category: "Information Disclosure",
    vulnerableComponent: "Message Storage/Transmission",
    countermeasure: "End-to-end encryption; server only sees ciphertext; keys never leave client devices",
    implemented: true,
  },
  {
    threat: "Private Key Exposure",
    category: "Information Disclosure",
    vulnerableComponent: "Key Storage",
    countermeasure: "Private keys encrypted with password-derived keys in IndexedDB; never transmitted",
    implemented: true,
  },
  {
    threat: "Session Key Exposure",
    category: "Information Disclosure",
    vulnerableComponent: "Key Exchange",
    countermeasure: "Ephemeral ECDH keys; forward secrecy; session keys derived using HKDF",
    implemented: true,
  },
  {
    threat: "Metadata Exposure",
    category: "Information Disclosure",
    vulnerableComponent: "Server Logs",
    countermeasure: "Minimal metadata collection; message content never logged; access controls on logs",
    implemented: true,
  },
  {
    threat: "Traffic Analysis",
    category: "Information Disclosure",
    vulnerableComponent: "Network Layer",
    countermeasure: "HTTPS/TLS for transport; message padding could be added for enhanced protection",
    implemented: true,
  },

  // DENIAL OF SERVICE THREATS
  {
    threat: "Message Replay Attack",
    category: "Denial of Service",
    vulnerableComponent: "Messaging System",
    countermeasure: "Nonces, timestamps, and sequence numbers; replay protection manager rejects duplicates",
    implemented: true,
  },
  {
    threat: "Key Exchange Replay",
    category: "Denial of Service",
    vulnerableComponent: "Key Exchange Protocol",
    countermeasure: "Timestamps, nonces, and signed ephemeral keys prevent replay of key exchange messages",
    implemented: true,
  },
  {
    threat: "Storage Exhaustion",
    category: "Denial of Service",
    vulnerableComponent: "Server Storage",
    countermeasure: "Rate limiting on uploads; file size limits; user quotas (implementation pending)",
    implemented: false,
  },
  {
    threat: "Computation Exhaustion",
    category: "Denial of Service",
    vulnerableComponent: "Key Exchange",
    countermeasure: "Rate limiting on key exchanges; ECC requires less computation than RSA",
    implemented: true,
  },

  // ELEVATION OF PRIVILEGE THREATS
  {
    threat: "Unauthorized Message Access",
    category: "Elevation of Privilege",
    vulnerableComponent: "Messaging System",
    countermeasure: "E2E encryption ensures only intended recipients can decrypt; no server access to plaintext",
    implemented: true,
  },
  {
    threat: "Admin Privilege Escalation",
    category: "Elevation of Privilege",
    vulnerableComponent: "Server",
    countermeasure: "E2E encryption means even server admins cannot read messages; zero-knowledge design",
    implemented: true,
  },
  {
    threat: "Session Hijacking",
    category: "Elevation of Privilege",
    vulnerableComponent: "Authentication",
    countermeasure: "Secure session tokens; session key binding to identity; re-authentication for sensitive ops",
    implemented: true,
  },
]

/**
 * MITM Attack Analysis
 */
export const mitmAnalysis = {
  attackDescription: `
    Man-in-the-Middle (MITM) Attack on Key Exchange:
    
    1. Without Signatures (Vulnerable):
       - Alice sends her public key to Bob
       - Attacker intercepts and replaces with their own public key
       - Bob sends his public key to Alice
       - Attacker intercepts and replaces with their own public key
       - Attacker now shares a secret with both Alice and Bob
       - Attacker can decrypt, read, and re-encrypt all messages
    
    2. With Digital Signatures (Protected):
       - Alice signs her public key with her long-term signing key
       - Attacker cannot forge Alice's signature
       - Bob verifies the signature using Alice's known public signing key
       - If verification fails, key exchange is rejected
       - Same protection applies in reverse direction
  `,

  prevention: [
    "All key exchange messages are signed with ECDSA",
    "Long-term signing keys are registered during account creation",
    "Signatures cover all parameters: sender ID, receiver ID, public key, timestamp, nonce",
    "Timestamp verification prevents delayed replay of captured messages",
    "Key confirmation step verifies both parties derived the same session key",
  ],

  demonstration: `
    The system includes an attack demonstration mode that shows:
    1. DH key exchange without signatures (vulnerable to MITM)
    2. DH key exchange with signatures (protected against MITM)
    3. Real-time logging of attack attempts and prevention
  `,
}

/**
 * Replay Attack Analysis
 */
export const replayAnalysis = {
  attackDescription: `
    Replay Attack Scenarios:
    
    1. Message Replay:
       - Attacker captures an encrypted message
       - Attacker re-sends the same message later
       - Without protection, receiver processes duplicate message
    
    2. Key Exchange Replay:
       - Attacker captures a key exchange initiation
       - Attacker replays it to establish old session key
       - Could allow decryption of messages with known key
    
    3. Authentication Replay:
       - Attacker captures authentication tokens
       - Attacker replays to gain unauthorized access
  `,

  prevention: [
    "Unique nonce in every message (tracked to prevent reuse)",
    "Timestamps with 5-minute validity window",
    "Sequence numbers with gap detection",
    "Multi-layer verification: nonce + timestamp + sequence",
    "Automatic cleanup of expired tracking data",
  ],

  demonstration: `
    The system includes replay attack demonstration that shows:
    1. Capture of legitimate message
    2. Attempted replay of captured message
    3. Detection and rejection by replay protection system
    4. Security logging of detected attack
  `,
}

/**
 * Get threat model summary statistics
 */
export function getThreatModelStats(): {
  total: number
  implemented: number
  pending: number
  byCategory: Record<string, { total: number; implemented: number }>
} {
  const stats = {
    total: threatModel.length,
    implemented: threatModel.filter((t) => t.implemented).length,
    pending: threatModel.filter((t) => !t.implemented).length,
    byCategory: {} as Record<string, { total: number; implemented: number }>,
  }

  threatModel.forEach((threat) => {
    if (!stats.byCategory[threat.category]) {
      stats.byCategory[threat.category] = { total: 0, implemented: 0 }
    }
    stats.byCategory[threat.category].total++
    if (threat.implemented) {
      stats.byCategory[threat.category].implemented++
    }
  })

  return stats
}
