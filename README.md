# VØID_LINK — End-to-End Encrypted Messaging System

**Zero-knowledge encrypted messaging protocol. No traces. No logs. No compromises.**

VØID_LINK is a full-stack, end-to-end encrypted (E2EE) chat application built with Next.js 16 and an Express/MongoDB backend. All cryptographic operations are performed client-side in the browser using the Web Crypto API. The server stores only ciphertext and never has access to plaintext messages, private keys, or session keys.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Tech Stack](#2-tech-stack)
3. [Cryptographic Design](#3-cryptographic-design)
4. [Key Exchange Protocol — SecureKEX v1](#4-key-exchange-protocol--securekex-v1)
5. [Replay Attack Protection](#5-replay-attack-protection)
6. [Key Storage](#6-key-storage)
7. [Encrypted File Sharing](#7-encrypted-file-sharing)
8. [Security Logging](#8-security-logging)
9. [STRIDE Threat Model](#9-stride-threat-model)
10. [API Reference](#10-api-reference)
11. [Database Schema](#11-database-schema)
12. [Project Structure](#12-project-structure)
13. [Environment Variables](#13-environment-variables)
14. [Getting Started](#14-getting-started)
15. [Testing & Demo Scripts](#15-testing--demo-scripts)

---

## 1. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                     Browser (Client)                            │
│                                                                 │
│  ┌──────────────┐   ┌─────────────────┐   ┌─────────────────┐  │
│  │  Next.js 16  │   │  Web Crypto API  │   │   IndexedDB     │  │
│  │  (App Router)│   │  (Encryption)    │   │  (Key Storage)  │  │
│  └──────┬───────┘   └────────┬────────┘   └────────┬────────┘  │
│         │                   │                      │            │
│         └───────────────────┴──────────────────────┘            │
│                             │                                   │
└─────────────────────────────┼───────────────────────────────────┘
                              │  HTTPS / WebSocket (TLS)
                              │  (Only ciphertext crosses the wire)
┌─────────────────────────────┼───────────────────────────────────┐
│                   Server (Node.js)                              │
│                             │                                   │
│  ┌──────────────────────────▼──────────────────────────────┐   │
│  │  Express.js + Socket.io                                 │   │
│  │  • JWT authentication                                   │   │
│  │  • PBKDF2 password hashing (SHA-512, 100k iterations)   │   │
│  │  • Nonce replay protection                              │   │
│  │  • Security audit logging                               │   │
│  └──────────────────────────┬──────────────────────────────┘   │
│                             │                                   │
│  ┌──────────────────────────▼──────────────────────────────┐   │
│  │  MongoDB                                                │   │
│  │  • Users (public keys only, hashed passwords)           │   │
│  │  • Messages (ciphertext only, never plaintext)          │   │
│  │  • Files (encrypted chunks only)                        │   │
│  │  • Key exchanges, Security logs                         │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

**Key design principle:** The server is zero-knowledge. It holds only encrypted data and public keys. Even a fully compromised server cannot read messages.

---

## 2. Tech Stack

### Frontend

| Technology | Version | Purpose |
|---|---|---|
| Next.js | 16.0.3 | React framework, App Router |
| React | 19.2.0 | UI library |
| TypeScript | ^5 | Type safety |
| Tailwind CSS | ^4.1.9 | Styling |
| shadcn/ui + Radix UI | latest | Accessible component primitives |
| Web Crypto API | (browser built-in) | All cryptographic operations |
| Socket.io-client | latest | Real-time messaging |
| Lucide React | ^0.454.0 | Icons |
| Zod | 3.25.76 | Schema validation |
| React Hook Form | latest | Form management |
| Vercel Analytics | latest | Usage analytics |
| Space Mono (Google Font) | — | Monospace UI font |

### Backend

| Technology | Version | Purpose |
|---|---|---|
| Express.js | ^4.18.2 | HTTP server |
| MongoDB + Mongoose | ^8.0.3 | Persistent storage |
| Socket.io | ^4.7.2 | Real-time WebSocket layer |
| jsonwebtoken | ^9.0.2 | JWT authentication |
| Node.js `crypto` | (built-in) | PBKDF2 password hashing, nonce generation |
| dotenv | ^16.3.1 | Environment configuration |
| cors | ^2.8.5 | Cross-origin request handling |

---

## 3. Cryptographic Design

All cryptographic operations use the **Web Crypto API** (`crypto.subtle`) in the browser. Keys are never transmitted in plaintext.

### Algorithm Configuration (`lib/crypto/constants.ts`)

| Algorithm | Parameters | Usage |
|---|---|---|
| **ECDH** | P-256 curve | Ephemeral key exchange |
| **ECDSA** | P-256 curve, SHA-256 | Digital signatures (authentication, non-repudiation) |
| **RSA-OAEP** | 2048-bit, SHA-256 | Alternative asymmetric encryption |
| **AES-GCM** | 256-bit key, 96-bit IV, 128-bit auth tag | Symmetric message/file encryption |
| **HKDF** | SHA-256 | Session key derivation from ECDH shared secret |
| **PBKDF2** | SHA-256, 100,000 iterations | Key derivation from user password (key storage) |

### Cryptographic Constants

| Constant | Value | Rationale |
|---|---|---|
| IV length | 96 bits (12 bytes) | NIST recommendation for AES-GCM |
| Nonce length | 128 bits (16 bytes) | Replay protection |
| Session key validity | 24 hours | Balance security vs usability |
| Replay window | 5 minutes | Reject timestamps outside this range |
| Max sequence gap | 100 | Tolerate minor reordering while blocking replays |
| File chunk size | 64 KB | Streaming-friendly encrypted file uploads |

### Message Encryption Flow

```
plaintext
    │
    ▼
[Generate fresh 96-bit IV]
[Generate 128-bit nonce]
[Get current timestamp + sequence number]
    │
    ▼
[Build AAD = {senderId, receiverId, nonce, timestamp, sequenceNumber}]
    │
    ▼
AES-256-GCM.encrypt(plaintext, sessionKey, IV, AAD)
    │
    ▼
[Sign: base64(ciphertext)|base64(IV)|nonce|timestamp|seqNum  →  ECDSA.sign(signingKey)]
    │
    ▼
EncryptedMessage { id, senderId, receiverId, ciphertext, iv,
                   nonce, timestamp, sequenceNumber, signature }
```

The **Associated Authenticated Data (AAD)** binds the ciphertext to its participants, nonce, timestamp, and sequence number. Any server-side modification of metadata causes GCM authentication tag verification to fail during decryption.

### Message Decryption Flow

```
EncryptedMessage
    │
    ├─▶ [Verify ECDSA signature]           → reject if invalid
    ├─▶ [Check timestamp within 5 min]     → reject if stale
    ├─▶ [Check sequence number]            → reject if replay
    │
    ▼
[Reconstruct AAD from metadata fields]
    │
    ▼
AES-256-GCM.decrypt(ciphertext, sessionKey, IV, AAD)
    │
    ▼
plaintext (or null if any verification step fails)
```

### Key Hierarchy

```
User Password
     │
     │ PBKDF2 (SHA-256, 100k iters, random 32-byte salt)
     ▼
Password-Derived Wrapping Key (AES-256-GCM)
     │
     │ AES-GCM encrypt
     ▼
Encrypted Private Keys (stored in IndexedDB)
  ├── ECDH Private Key   ─── ECDH Key Exchange
  └── ECDSA Private Key  ─── Digital Signatures

Long-term ECDH Private + Peer's Ephemeral ECDH Public
     │
     │ ECDH deriveBits (P-256) → 256-bit shared secret
     ▼
Shared Secret
     │
     │ HKDF (SHA-256, context-bound salt + info string)
     ▼
Session Key (AES-256-GCM, 256-bit)
     │
     │ AES-GCM encrypt/decrypt
     ▼
Message Ciphertext
```

---

## 4. Key Exchange Protocol — SecureKEX v1

Implemented in `lib/crypto/key-exchange.ts`. This is a custom authenticated ECDH protocol with 10 steps:

```
Alice                                          Bob
  │                                              │
  │ 1. Generate ephemeral ECDH key pair          │
  │ 2. Sign: senderId|receiverId|pubKey|ts|nonce │
  │──── KEY_EXCHANGE_INIT ──────────────────────▶│
  │    { ephemeralPublicKey, signature,          │
  │      timestamp, nonce }                      │
  │                                              │ 3. Verify receiver ID
  │                                              │ 4. Validate timestamp (≤5 min)
  │                                              │ 5. Verify Alice's ECDSA signature
  │                                              │    (prevents MITM key substitution)
  │                                              │ 6. Generate ephemeral ECDH key pair
  │                                              │ 7. Compute ECDH shared secret
  │                                              │ 8. Derive session key via HKDF
  │                                              │    info = "SecureMessaging-SessionKey-v1|nonce|sortedIds"
  │◀─── KEY_EXCHANGE_RESPONSE ──────────────────│
  │    { ephemeralPublicKey, signature,          │
  │      timestamp, nonce, originalNonce }        │
  │                                              │
  │ 9.  Verify Bob's ECDSA signature             │
  │     (includes Alice's original nonce)        │
  │ 10. Compute ECDH shared secret               │
  │     Derive session key via HKDF              │
  │     (same parameters → same key)             │
  │                                              │
  ├──── KEY_CONFIRMATION (HMAC) ───────────────▶ │
  │◀─── KEY_CONFIRMATION (HMAC) ─────────────── │
  │  Both verify HMAC(sessionKey, IDs + nonces)  │
```

**Security properties:**
- **Forward secrecy** — ephemeral ECDH keys; compromise of long-term keys does not expose past sessions.
- **MITM resistance** — ECDSA signatures bind the ephemeral public key to the sender's identity; an attacker cannot substitute keys without possessing the long-term signing key.
- **Replay resistance** — each message carries a fresh timestamp and nonce; Bob's response echoes Alice's nonce, binding the response to the specific init message.
- **Key confirmation** — HMAC over session key and both nonces proves both parties derived the identical session key.

### HKDF Key Derivation Context

```
info  = "SecureMessaging-SessionKey-v1|{nonce}|{sortedUserIds}"
salt  = SHA-256({nonce}|{sortedUserIds})
input = ECDH shared secret (256 bits)
output = AES-256-GCM key
```

User IDs are sorted before inclusion so both parties produce the same context string regardless of who initiated.

---

## 5. Replay Attack Protection

Implemented in `lib/crypto/replay-protection.ts` with three independent checks:

### Check 1 — Timestamp Validation
Every message carries a Unix millisecond timestamp. Messages with timestamps more than **5 minutes** from the current time are rejected.

### Check 2 — Nonce Deduplication
Every message carries a random 128-bit nonce. The `ReplayProtectionManager` maintains an in-memory `Map<nonce, timestamp>`. A seen nonce is immediately rejected. Expired entries are purged every 60 seconds.

### Check 3 — Sequence Number Validation
Per-conversation sequence numbers are tracked. A message is rejected if:
- Its sequence number has already been seen in this conversation.
- It falls more than `MAX_SEQUENCE_GAP` (100) behind the last seen sequence number.
- It is more than `MAX_SEQUENCE_GAP` ahead of the last seen number (guards against pre-positioning attacks).

All three checks must pass for a message to be accepted. Any failure is logged as a `REPLAY_ATTACK_DETECTED` security event.

**Server-side replay protection** (`server/index.js`) uses an additional in-memory nonce store with 5-minute TTL cleanup for key exchange messages.

---

## 6. Key Storage

Implemented in `lib/crypto/key-storage.ts`. Private keys never leave the browser unencrypted.

### Storage Mechanism

```
User Password
     │
     │ PBKDF2 (SHA-256, 100,000 iterations, 32-byte random salt)
     ▼
Wrapping Key (AES-256-GCM)
     │
     │ AES-256-GCM encrypt(privateKeyBytes, 96-bit IV)
     ▼
{ encryptedKey, iv, salt, keyType }  ──▶  IndexedDB ("SecureMessagingKeyStore")
```

- **Database name:** `SecureMessagingKeyStore` (IndexedDB)
- **Object store:** `keys` (keyed by a string ID)
- Key IDs follow the pattern `{userId}_ecdh` and `{userId}_signing`.
- Session keys per conversation are stored as `session_{conversationId}`.
- A different random salt and IV are generated each time a key is wrapped, so two writes of the same key produce different ciphertext.

Private keys are loaded on demand by decrypting with the user's password. The password itself is never persisted.

---

## 7. Encrypted File Sharing

Implemented in `lib/crypto/file-encryption.ts`.

### Encryption Process

1. Read the entire file into an `ArrayBuffer`.
2. Split into **64 KB chunks**.
3. For each chunk: generate a fresh 96-bit IV, encrypt with `AES-256-GCM` using the conversation session key.
4. Encrypt the filename separately with another fresh IV.
5. Encrypt a JSON metadata object (`{ name, type, size }`) with another IV.
6. Sign the assembled `EncryptedFile` object with the sender's ECDSA signing key.
7. Upload the complete `EncryptedFile` (all chunks, encrypted metadata) to the server.

### Decryption Process

1. Verify the sender's ECDSA signature on the `EncryptedFile`.
2. Decrypt file metadata to recover original name and MIME type.
3. Decrypt chunks in order and concatenate.
4. Return a `Blob` with the correct MIME type for download.

Each chunk has an independent IV and authentication tag, so chunk-level tampering is detected at decryption.

---

## 8. Security Logging

Implemented in `lib/security-logger.ts` (client-side) and `server/index.js` → MongoDB `SecurityLog` collection (server-side).

### Logged Security Events

| Event Type | Trigger |
|---|---|
| `AUTH_SUCCESS` / `AUTH_FAILURE` | Login, registration, key init |
| `KEY_EXCHANGE_INIT` / `KEY_EXCHANGE_COMPLETE` / `KEY_EXCHANGE_FAILURE` | Key exchange protocol steps |
| `MESSAGE_SENT` / `MESSAGE_DECRYPT_FAILURE` | Message send / decryption errors |
| `REPLAY_ATTACK_DETECTED` | Nonce, timestamp, or sequence number replay |
| `INVALID_SIGNATURE` | ECDSA verification failure |
| `MITM_ATTEMPT_DETECTED` | Key substitution detected |
| `FILE_UPLOAD` / `FILE_DOWNLOAD` | File transfer operations |

Client-side logs are stored in a capped in-memory array (max 10,000 entries). Server logs are persisted to MongoDB with timestamps and IP addresses. Both are exposed via the `/security-logs` component in the UI.

---

## 9. STRIDE Threat Model

Documented in `lib/threat-model.ts`. The STRIDE framework is applied to all major components.

| Category | Threat | Countermeasure | Status |
|---|---|---|---|
| **Spoofing** | User identity spoofing | PBKDF2 password hashing, JWT sessions, ECDSA message signatures | ✅ |
| **Spoofing** | Key spoofing in key exchange | ECDSA signatures on all key exchange messages | ✅ |
| **Spoofing** | Message sender spoofing | ECDSA signature on every encrypted message | ✅ |
| **Tampering** | Message content tampering | AES-256-GCM authenticated encryption; any modification invalidates the auth tag | ✅ |
| **Tampering** | Key exchange message tampering | ECDSA covers all parameters; tampering detected via signature failure | ✅ |
| **Tampering** | File chunk tampering | Each chunk independently authenticated by GCM | ✅ |
| **Tampering** | Database tampering | Only ciphertext stored; modification → decryption failure | ✅ |
| **Repudiation** | Message denial | Digital signatures prove sender identity; full audit logs | ✅ |
| **Repudiation** | Key exchange denial | Signed messages + key confirmation + event logs | ✅ |
| **Info Disclosure** | Plaintext message exposure | E2E encryption; server sees only ciphertext | ✅ |
| **Info Disclosure** | Private key exposure | Keys stored encrypted in IndexedDB; never transmitted | ✅ |
| **Info Disclosure** | Session key exposure | Ephemeral ECDH; forward secrecy; HKDF derivation | ✅ |
| **Info Disclosure** | Traffic analysis | HTTPS/TLS transport; message content not logged | ✅ |
| **DoS** | Message replay | Nonce + timestamp + sequence number triple check | ✅ |
| **DoS** | Key exchange replay | Timestamps, nonces, echoed nonces in response | ✅ |
| **DoS** | Storage exhaustion | Rate limiting / quotas (pending) | ⏳ |
| **DoS** | Computation exhaustion | Rate limiting on key exchange; ECC vs RSA efficiency | ✅ |
| **EoP** | Unauthorized message access | E2E encryption; no server-side decryption possible | ✅ |
| **EoP** | Admin privilege escalation | Zero-knowledge design; even server admin cannot read messages | ✅ |
| **EoP** | Session hijacking | Secure JWT tokens; session key bound to identity | ✅ |

---

## 10. API Reference

Base URL: `http://localhost:5000` (configurable via `NEXT_PUBLIC_BACKEND_URL`)

All authenticated endpoints require the header:
```
Authorization: Bearer <jwt_token>
```

### Authentication

#### `POST /api/auth/register`
Register a new user and upload public keys.

**Request body:**
```json
{
  "username": "string",
  "password": "string",
  "publicKey": "base64-encoded ECDH public key (SPKI)",
  "signaturePublicKey": "base64-encoded ECDSA public key (SPKI)"
}
```

**Response `201`:**
```json
{
  "user": { "id": "...", "username": "...", "publicKey": "...", "signaturePublicKey": "..." },
  "token": "jwt"
}
```

#### `POST /api/auth/login`
Authenticate with username and password.

**Request body:**
```json
{ "username": "string", "password": "string" }
```

**Response `200`:**
```json
{
  "user": { "id": "...", "username": "...", "publicKey": "...", "signaturePublicKey": "..." },
  "token": "jwt"
}
```

### Users

#### `GET /api/users` *(authenticated)*
List all users except the current user. Returns public keys.

#### `GET /api/users/:id` *(authenticated)*
Get a specific user's public keys by MongoDB ObjectId.

### Key Exchange

#### `POST /api/key-exchange` *(authenticated)*
Relay a key exchange message (INIT, RESPONSE, or CONFIRM) to the intended recipient.

**Request body:**
```json
{
  "receiverId": "string",
  "type": "INIT | RESPONSE | CONFIRM | KEY_EXCHANGE_AUTO",
  "publicKey": "base64 ephemeral ECDH public key",
  "signature": "base64 ECDSA signature",
  "nonce": "base64 nonce",
  "timestamp": 1234567890000
}
```

The server validates the timestamp (≤5 minutes) and checks nonce uniqueness before storing.

#### `GET /api/key-exchange/:userId` *(authenticated)*
Retrieve pending key exchange messages addressed to the authenticated user.

### Messages

#### `POST /api/messages` *(authenticated)*
Store an encrypted message. No plaintext is accepted; only ciphertext.

**Request body (EncryptedMessage):**
```json
{
  "receiverId": "string",
  "ciphertext": "base64",
  "iv": "base64",
  "nonce": "base64",
  "signature": "base64",
  "timestamp": 1234567890000,
  "sequenceNumber": 1,
  "isFile": false
}
```

#### `GET /api/messages/:userId` *(authenticated)*
Retrieve encrypted message history with a specific user.

### Files

#### `POST /api/files` *(authenticated)*
Upload an encrypted file (base64 encoded chunks stored in MongoDB).

#### `GET /api/files/:fileId` *(authenticated)*
Download an encrypted file by ID.

### Real-time (Socket.io)

The server exposes a Socket.io namespace on the same HTTP server. After authenticating via JWT, clients join a room identified by their user ID and receive real-time events:

| Event | Direction | Payload |
|---|---|---|
| `join` | client → server | `{ userId }` |
| `new_message` | server → client | `EncryptedMessage` |
| `key_exchange` | server → client | `KeyExchangeMessage` |
| `user_online` | server → client | `{ userId }` |
| `user_offline` | server → client | `{ userId }` |

---

## 11. Database Schema

### User
```
username          String (unique, indexed)
passwordHash      String (PBKDF2, SHA-512, 100k iters, base64)
salt              String (32 random bytes, base64)
publicKey         String (ECDH, SPKI, base64)
signaturePublicKey String (ECDSA, SPKI, base64)
createdAt         Date
```

### Message
```
senderId          ObjectId → User (indexed)
receiverId        ObjectId → User (indexed)
ciphertext        String (AES-256-GCM, base64)
iv                String (96-bit, base64)
nonce             String (128-bit, base64)
signature         String (ECDSA, base64)
timestamp         Number (milliseconds, indexed)
sequenceNumber    Number
isFile            Boolean
fileName          String
fileId            String
```
Compound index: `{ senderId, receiverId, timestamp -1 }`

### File
```
senderId          ObjectId → User
receiverId        ObjectId → User
fileName          String (encrypted or display name)
encryptedData     String (all chunks, base64)
iv                String (base64)
nonce             String (base64)
signature         String (ECDSA, base64)
timestamp         Number
fileSize          Number
```

### KeyExchange
```
senderId          ObjectId → User
receiverId        ObjectId → User
type              Enum: INIT | RESPONSE | CONFIRM | KEY_EXCHANGE_AUTO
publicKey         String (ephemeral ECDH, base64)
signature         String (ECDSA, base64)
nonce             String (base64)
timestamp         Number
processed         Boolean (indexed with receiverId)
```

### SecurityLog
```
eventType         Enum (see Section 8)
userId            ObjectId → User
targetUserId      ObjectId → User
ipAddress         String
userAgent         String
details           Mixed (JSON)
timestamp         Date (indexed)
```

---

## 12. Project Structure

```
Secure-Chat-App/
├── app/                         # Next.js App Router
│   ├── layout.tsx               # Root layout (Space Mono font, dark theme)
│   ├── page.tsx                 # Main chat page
│   ├── globals.css              # Global styles (scanlines/CRT effect)
│   └── api/                    # Next.js API routes (thin proxies to Express backend)
│       ├── auth/
│       │   ├── login/route.ts
│       │   └── register/route.ts
│       ├── messages/route.ts
│       ├── key-exchange/route.ts
│       ├── files/
│       └── users/
│
├── components/
│   ├── auth/
│   │   ├── login-form.tsx       # Login UI with form validation
│   │   └── register-form.tsx    # Registration UI, triggers key generation
│   ├── chat/
│   │   ├── message-list.tsx     # Renders decrypted messages in real-time
│   │   ├── message-input.tsx    # Encrypts and sends messages
│   │   ├── user-list.tsx        # Online user list with key exchange controls
│   │   ├── key-exchange-dialog.tsx  # Key exchange initiation UI
│   │   └── file-upload-button.tsx   # Encrypted file upload
│   ├── security/
│   │   └── security-logs.tsx   # Displays real-time security audit log
│   ├── ui/                     # shadcn/ui component library
│   └── theme-provider.tsx
│
├── hooks/
│   ├── use-crypto.ts            # Central React hook for all crypto operations
│   ├── use-mobile.ts            # Responsive layout detection
│   └── use-toast.ts             # Toast notification hook
│
├── lib/
│   ├── types.ts                 # Core TypeScript interfaces
│   ├── api-config.ts            # Backend URL configuration
│   ├── security-logger.ts       # Client-side security event logger
│   ├── threat-model.ts          # STRIDE threat model documentation
│   ├── utils.ts                 # General utilities
│   ├── db/
│   │   └── store.ts             # Client-side state store
│   └── crypto/
│       ├── constants.ts         # Algorithm parameters & configuration
│       ├── key-generation.ts    # ECDH, ECDSA, RSA key pair generation & import/export
│       ├── key-exchange.ts      # SecureKEX v1 protocol implementation
│       ├── key-storage.ts       # IndexedDB encrypted key persistence
│       ├── session-storage.ts   # Session key storage per conversation
│       ├── encryption.ts        # AES-256-GCM message encrypt/decrypt
│       ├── file-encryption.ts   # Chunked AES-256-GCM file encrypt/decrypt
│       ├── signatures.ts        # ECDSA sign/verify helpers
│       ├── replay-protection.ts # Nonce + timestamp + sequence validation
│       └── utils.ts             # IV/nonce generation, base64 helpers, SHA-256
│
├── server/
│   ├── index.js                 # Express + MongoDB + Socket.io server
│   └── package.json
│
├── scripts/                     # Standalone test and demo scripts
│   ├── crypto-verification.js   # Verifies all crypto primitives work correctly
│   ├── mitm-attack-demo.js      # Demonstrates MITM attack and ECDSA prevention
│   ├── replay-attack-demo.js    # Demonstrates replay attack and detection
│   ├── test-crypto-system.ts    # Full TypeScript crypto system test suite
│   ├── openssl-commands.sh      # OpenSSL commands for manual key inspection
│   └── package.json
│
├── public/                      # Static assets (icons, images)
├── styles/                      # Additional CSS
├── next.config.mjs              # Next.js configuration
├── tsconfig.json                # TypeScript configuration
└── package.json                 # Frontend dependencies
```

---

## 13. Environment Variables

### Frontend (`.env.local`)

| Variable | Default | Description |
|---|---|---|
| `NEXT_PUBLIC_BACKEND_URL` | `http://localhost:5000` | Express backend base URL |

### Backend (`server/.env`)

| Variable | Default | Description |
|---|---|---|
| `MONGODB_URI` | `mongodb://localhost:27017/secure_messaging` | MongoDB connection string |
| `JWT_SECRET` | *(insecure default — change in production)* | Secret for signing JWT tokens |
| `PORT` | `5000` | HTTP server port |

---

## 14. Getting Started

### Prerequisites

- Node.js ≥ 18
- MongoDB ≥ 6 (local install or [MongoDB Atlas](https://www.mongodb.com/atlas))
- npm or pnpm

### 1. Clone the repository

```bash
git clone https://github.com/Adeelbytes/Secure-Chat-App.git
cd Secure-Chat-App
```

### 2. Install frontend dependencies

```bash
npm install
# or
pnpm install
```

### 3. Configure the frontend

Create `.env.local` in the project root:
```env
NEXT_PUBLIC_BACKEND_URL=http://localhost:5000
```

### 4. Install and configure the backend

```bash
cd server
npm install
```

Create `server/.env`:
```env
MONGODB_URI=mongodb://localhost:27017/secure_messaging
JWT_SECRET=replace-with-a-strong-random-secret
PORT=5000
```

### 5. Start the backend

```bash
# In the server/ directory
npm start          # production
npm run dev        # development (nodemon auto-reload)
```

### 6. Start the frontend

```bash
# In the project root
npm run dev        # http://localhost:3000
```

### 7. Open in browser

Navigate to [http://localhost:3000](http://localhost:3000).

1. **Register** two accounts in separate browser tabs or profiles.
2. **Open the key exchange dialog** to establish a session key between the two users.
3. Once the key exchange completes, messages can be encrypted and sent end-to-end.

---

## 15. Testing & Demo Scripts

Located in the `scripts/` directory.

```bash
cd scripts
npm run all-tests    # run all three scripts in sequence
```

### `crypto-verification.js`
Verifies all cryptographic primitives in isolation:
- Key pair generation (ECDH, ECDSA)
- ECDH shared secret agreement
- AES-256-GCM encrypt / decrypt round-trip
- ECDSA sign / verify
- HKDF session key derivation

```bash
npm run verify
```

### `mitm-attack-demo.js`
Simulates a man-in-the-middle attack on an unauthenticated DH key exchange, then demonstrates how ECDSA signatures prevent it.

```bash
npm run mitm-demo
```

### `replay-attack-demo.js`
Captures an encrypted message, attempts to replay it, and demonstrates the three-layer detection system (nonce, timestamp, sequence number) rejecting the replay.

```bash
npm run replay-demo
```

### `test-crypto-system.ts`
Full TypeScript test suite for the key exchange protocol, including end-to-end message encryption/decryption with replay protection enabled.

### `openssl-commands.sh`
Helper OpenSSL commands for inspecting exported key material in PEM format.

---

## Security Considerations

- **Private keys never leave the browser.** They are stored encrypted in IndexedDB using AES-256-GCM, wrapped with a PBKDF2-derived key from the user's password.
- **The server is zero-knowledge.** MongoDB contains only ciphertext, base64-encoded IVs, nonces, signatures, and public keys. Server admins cannot read messages.
- **Forward secrecy** is achieved through ephemeral ECDH key pairs per session. Compromise of long-term signing keys does not expose past sessions.
- **Rate limiting and storage quotas** are not yet fully implemented and should be added before deploying publicly.
- **Nonce storage** is in-memory on the server. In a multi-instance deployment, replace `processedNonces` with a shared Redis store.
- **JWT secret** must be changed from the default before any production deployment.
- The `next.config.mjs` currently has `typescript.ignoreBuildErrors: true`; this should be set to `false` and all type errors resolved before production.
