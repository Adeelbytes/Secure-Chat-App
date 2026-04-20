# 🔐 Secure-Chat-App: End-to-End Encrypted Messaging

A state-of-the-art secure messaging platform featuring **Zero-Knowledge Architecture** and robust cryptographic protocols. Designed for modern information security standards, ensuring that privacy is maintained even if the server is compromised.

---

## 🚀 Key Features

*   **End-to-End Encryption (E2EE)**: Messages and files are encrypted using **AES-256-GCM** before leaving the sender's device.
*   **Secure Key Exchange**: Implements a custom **ECDH (Elliptic Curve Diffie-Hellman)** protocol combined with **ECDSA signatures** to prevent MITM attacks.
*   **Zero-Knowledge Server**: The backend acts as a blind relay; it never sees private keys or plaintext content.
*   **Replay Protection**: Every transaction is protected by nonces, sequence numbers, and strict timestamp validation.
*   **Cryptographic Audit Log**: Integrated security logger to track and visualize cryptographic events in real-time.
*   **Attack Demonstration Suite**: Built-in scripts to simulate and verify protection against MITM and Replay attacks.

---

## 🛠 Tech Stack

### Frontend & Client-Side Crypto
- **Framework**: Next.js 15 (App Router)
- **Styling**: Tailwind CSS + Shadcn UI
- **Cryptography**: Web Crypto API (SubtleCrypto)
- **Storage**: IndexedDB (for secure, persistent key storage)

### Backend & Infrastructure
- **Runtime**: Node.js / Express
- **Real-time**: Socket.io for instant message delivery
- **Database**: MongoDB (Metadata and encrypted blob storage)
- **Auth**: JWT-based session management

---

## 🏗 Project Structure

```text
├── app/                  # Next.js Application (Frontend)
├── components/           # UI & Feature Components
│   ├── chat/             # Messaging & File Upload
│   ├── auth/             # Secure Login/Register
│   └── security/         # Security Visualizations & Logs
├── lib/crypto/           # 🛡️ Core Cryptographic Engine
│   ├── encryption.ts     # AES-256-GCM Implementation
│   ├── key-exchange.ts   # ECDH + Signature Logic
│   ├── signatures.ts     # ECDSA Signing/Verification
│   └── replay-protection.ts # Nonce & Timestamp handling
├── server/               # 📦 Backend Relay Server
├── scripts/              # 🧪 Security Testing & Attack Demos
│   ├── mitm-attack-demo.js
│   ├── replay-attack-demo.js
│   └── crypto-verification.js
└── public/               # Static Assets
```

---

## 🔒 Cryptographic Architecture

### 1. Key Generation
The system uses **ECC (Elliptic Curve Cryptography)** for both identity and ephemeral operations.
- **Identity Keys**: P-256 ECDSA for long-term authentication.
- **Session Keys**: P-256 ECDH for perfect forward secrecy.

### 2. Message Encryption (AES-GCM)
We use AES-256 in Galois/Counter Mode to provide both **confidentiality** and **authenticity**.
- **96-bit Random IV**: Unique for every message.
- **AAD (Additional Authenticated Data)**: Includes sender/receiver IDs to bind the ciphertext to the context.

### 3. Protection Mechanisms
- **Anti-Replay**: Server-side nonce tracking prevents attackers from re-sending intercepted packets.
- **MITM Prevention**: All key exchange packets are digitally signed by the sender's private identity key.

---

## 🏁 Getting Started

### Prerequisites
- Node.js (v18.0.0+)
- MongoDB (running instance)
- npm or pnpm

### Installation & Setup

1. **Clone & Install Dependencies**
   ```bash
   git clone https://github.com/Adeelbytes/Secure-Chat-App.git
   cd Secure-Chat-App
   npm install
   ```

2. **Configure Environment**
   Create a `.env` file in the `server/` directory:
   ```env
   PORT=5000
   MONGODB_URI=your_mongodb_connection_string
   JWT_SECRET=your_super_secret_key
   ```

3. **Run the Application**
   ```bash
   # Start the Backend (Term 1)
   cd server
   npm start

   # Start the Frontend (Term 2)
   cd ..
   npm run dev
   ```

---

## 🧪 Security Demonstrations

This repository includes a suite of scripts to verify the security claims:

| Script | Purpose | Command |
| :--- | :--- | :--- |
| `mitm-attack-demo.js` | Simulates a Man-in-the-Middle attempting to swap keys. | `node scripts/mitm-attack-demo.js` |
| `replay-attack-demo.js` | Attempts to capture and replay a valid encrypted message. | `node scripts/replay-attack-demo.js` |
| `crypto-verification.js`| Validates the correctness of the AES and ECDH logic. | `node scripts/crypto-verification.js` |

---

## 📜 License & Academic Integrity

This project was developed for the **Information Security (BSSE)** course. 

- **License**: MIT
- **Note**: If you are a student, please ensure you follow your institution's academic integrity policies regarding code reuse.