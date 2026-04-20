/**
 * Cryptographic Operations Verification Script
 *
 * This script verifies that all cryptographic operations work correctly
 * using Node.js crypto module (equivalent to Web Crypto API).
 *
 * Run: node scripts/crypto-verification.js
 */

const crypto = require("crypto")

console.log("=".repeat(70))
console.log("CRYPTOGRAPHIC OPERATIONS VERIFICATION")
console.log("=".repeat(70))
console.log()

let testsPassed = 0
let testsFailed = 0

function test(name, fn) {
  try {
    fn()
    console.log(`[PASS] ${name}`)
    testsPassed++
  } catch (err) {
    console.log(`[FAIL] ${name}`)
    console.log(`       Error: ${err.message}`)
    testsFailed++
  }
}

// ============================================
// 1. ECC KEY GENERATION (P-256)
// ============================================

console.log("\n--- 1. ECC Key Generation (P-256/secp256r1) ---\n")

let ecdhKeyPair, ecdsaKeyPair

test("Generate ECDH key pair (P-256)", () => {
  const ecdh = crypto.createECDH("prime256v1")
  ecdh.generateKeys()
  ecdhKeyPair = {
    privateKey: ecdh.getPrivateKey(),
    publicKey: ecdh.getPublicKey(),
  }

  if (ecdhKeyPair.publicKey.length !== 65) {
    // Uncompressed point format
    throw new Error(`Unexpected public key length: ${ecdhKeyPair.publicKey.length}`)
  }
})

test("Generate ECDSA key pair (P-256)", () => {
  ecdsaKeyPair = crypto.generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
  })

  const publicKeyDer = ecdsaKeyPair.publicKey.export({ type: "spki", format: "der" })
  if (publicKeyDer.length < 50) {
    throw new Error("Public key too short")
  }
})

// ============================================
// 2. ECDH KEY EXCHANGE
// ============================================

console.log("\n--- 2. ECDH Key Exchange ---\n")

let aliceShared, bobShared

test("Perform ECDH key exchange", () => {
  // Alice's keys
  const aliceECDH = crypto.createECDH("prime256v1")
  aliceECDH.generateKeys()

  // Bob's keys
  const bobECDH = crypto.createECDH("prime256v1")
  bobECDH.generateKeys()

  // Compute shared secrets
  aliceShared = aliceECDH.computeSecret(bobECDH.getPublicKey())
  bobShared = bobECDH.computeSecret(aliceECDH.getPublicKey())

  if (!aliceShared.equals(bobShared)) {
    throw new Error("Shared secrets do not match!")
  }

  console.log(`       Shared secret length: ${aliceShared.length} bytes`)
  console.log(`       Shared secret (hex): ${aliceShared.toString("hex").substring(0, 32)}...`)
})

// ============================================
// 3. HKDF KEY DERIVATION
// ============================================

console.log("\n--- 3. HKDF Key Derivation ---\n")

let sessionKey

test("Derive session key using HKDF", () => {
  const sharedSecret = aliceShared
  const salt = Buffer.from("alice:bob")
  const info = Buffer.from("session-key-v1")

  // HKDF-Extract
  const prk = crypto.createHmac("sha256", salt).update(sharedSecret).digest()

  // HKDF-Expand
  const outputLength = 32 // 256 bits for AES-256
  const hashLen = 32
  const n = Math.ceil(outputLength / hashLen)

  let okm = Buffer.alloc(0)
  let t = Buffer.alloc(0)

  for (let i = 1; i <= n; i++) {
    const hmac = crypto.createHmac("sha256", prk)
    hmac.update(t)
    hmac.update(info)
    hmac.update(Buffer.from([i]))
    t = hmac.digest()
    okm = Buffer.concat([okm, t])
  }

  sessionKey = okm.slice(0, outputLength)

  if (sessionKey.length !== 32) {
    throw new Error(`Session key wrong length: ${sessionKey.length}`)
  }

  console.log(`       Session key length: ${sessionKey.length} bytes (256 bits)`)
  console.log(`       Session key (hex): ${sessionKey.toString("hex")}`)
})

// ============================================
// 4. AES-256-GCM ENCRYPTION
// ============================================

console.log("\n--- 4. AES-256-GCM Encryption ---\n")

let ciphertext, iv, authTag
const plaintext = "Hello, this is a secret message! 🔐"

test("Encrypt message with AES-256-GCM", () => {
  iv = crypto.randomBytes(12) // 96-bit IV for GCM

  const cipher = crypto.createCipheriv("aes-256-gcm", sessionKey, iv)

  // Add Associated Data (AAD)
  const aad = JSON.stringify({
    senderId: "alice",
    receiverId: "bob",
    timestamp: Date.now(),
  })
  cipher.setAAD(Buffer.from(aad))

  ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()])

  authTag = cipher.getAuthTag()

  console.log(`       Plaintext: "${plaintext}"`)
  console.log(`       Plaintext length: ${Buffer.from(plaintext).length} bytes`)
  console.log(`       Ciphertext length: ${ciphertext.length} bytes`)
  console.log(`       IV (hex): ${iv.toString("hex")}`)
  console.log(`       Auth tag (hex): ${authTag.toString("hex")}`)
})

test("Decrypt message with AES-256-GCM", () => {
  const decipher = crypto.createDecipheriv("aes-256-gcm", sessionKey, iv)

  // Same AAD must be provided
  const aad = JSON.stringify({
    senderId: "alice",
    receiverId: "bob",
    timestamp: Date.now(),
  })
  decipher.setAAD(Buffer.from(aad))
  decipher.setAuthTag(authTag)

  const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8")

  if (decrypted !== plaintext) {
    throw new Error(`Decryption mismatch: "${decrypted}" !== "${plaintext}"`)
  }

  console.log(`       Decrypted: "${decrypted}"`)
})

test("Detect tampered ciphertext", () => {
  // Tamper with ciphertext
  const tamperedCiphertext = Buffer.from(ciphertext)
  tamperedCiphertext[0] ^= 0xff

  const decipher = crypto.createDecipheriv("aes-256-gcm", sessionKey, iv)
  decipher.setAAD(Buffer.from("{}"))
  decipher.setAuthTag(authTag)

  let errorThrown = false
  try {
    decipher.update(tamperedCiphertext)
    decipher.final()
  } catch (err) {
    errorThrown = true
  }

  if (!errorThrown) {
    throw new Error("Tampered ciphertext was not detected!")
  }

  console.log("       Tampered ciphertext correctly rejected")
})

// ============================================
// 5. ECDSA DIGITAL SIGNATURES
// ============================================

console.log("\n--- 5. ECDSA Digital Signatures ---\n")

let signature
const messageToSign = "alice|bob|publickey123|1701234567890|nonce456"

test("Sign message with ECDSA", () => {
  signature = crypto.sign("sha256", Buffer.from(messageToSign), ecdsaKeyPair.privateKey)

  console.log(`       Message: "${messageToSign}"`)
  console.log(`       Signature length: ${signature.length} bytes`)
  console.log(`       Signature (hex): ${signature.toString("hex").substring(0, 64)}...`)
})

test("Verify valid signature", () => {
  const isValid = crypto.verify("sha256", Buffer.from(messageToSign), ecdsaKeyPair.publicKey, signature)

  if (!isValid) {
    throw new Error("Valid signature was rejected!")
  }

  console.log("       Signature verification: PASSED")
})

test("Reject tampered message", () => {
  const tamperedMessage = messageToSign.replace("alice", "mallory")

  const isValid = crypto.verify("sha256", Buffer.from(tamperedMessage), ecdsaKeyPair.publicKey, signature)

  if (isValid) {
    throw new Error("Tampered message was accepted!")
  }

  console.log("       Tampered message correctly rejected")
})

test("Reject forged signature", () => {
  // Create different key pair (attacker's key)
  const attackerKey = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" })
  const forgedSignature = crypto.sign("sha256", Buffer.from(messageToSign), attackerKey.privateKey)

  const isValid = crypto.verify(
    "sha256",
    Buffer.from(messageToSign),
    ecdsaKeyPair.publicKey, // Verify against legitimate key
    forgedSignature,
  )

  if (isValid) {
    throw new Error("Forged signature was accepted!")
  }

  console.log("       Forged signature correctly rejected")
})

// ============================================
// 6. PASSWORD HASHING (PBKDF2)
// ============================================

console.log("\n--- 6. Password Hashing (PBKDF2) ---\n")

let passwordHash, salt
const password = "SecurePassword123!"

test("Hash password with PBKDF2", () => {
  salt = crypto.randomBytes(32)

  passwordHash = crypto.pbkdf2Sync(
    password,
    salt,
    100000, // 100,000 iterations
    64, // 64-byte output (512 bits)
    "sha512",
  )

  console.log(`       Password: "${password}"`)
  console.log(`       Salt (hex): ${salt.toString("hex")}`)
  console.log(`       Hash length: ${passwordHash.length} bytes`)
  console.log(`       Iterations: 100,000`)
  console.log(`       Algorithm: SHA-512`)
})

test("Verify correct password", () => {
  const verifyHash = crypto.pbkdf2Sync(password, salt, 100000, 64, "sha512")

  if (!crypto.timingSafeEqual(passwordHash, verifyHash)) {
    throw new Error("Password verification failed!")
  }

  console.log("       Correct password verified")
})

test("Reject wrong password", () => {
  const wrongHash = crypto.pbkdf2Sync("WrongPassword", salt, 100000, 64, "sha512")

  const isEqual = crypto.timingSafeEqual(passwordHash, wrongHash)

  if (isEqual) {
    throw new Error("Wrong password was accepted!")
  }

  console.log("       Wrong password correctly rejected")
})

// ============================================
// 7. RANDOM NUMBER GENERATION
// ============================================

console.log("\n--- 7. Cryptographically Secure Random Numbers ---\n")

test("Generate random IV (12 bytes)", () => {
  const randomIV = crypto.randomBytes(12)
  console.log(`       Random IV: ${randomIV.toString("hex")}`)

  // Check uniqueness
  const anotherIV = crypto.randomBytes(12)
  if (randomIV.equals(anotherIV)) {
    throw new Error("Generated identical IVs!")
  }
})

test("Generate random nonce (16 bytes)", () => {
  const nonce = crypto.randomBytes(16)
  console.log(`       Random nonce: ${nonce.toString("hex")}`)
})

test("Generate random key (32 bytes)", () => {
  const key = crypto.randomBytes(32)
  console.log(`       Random key: ${key.toString("hex")}`)
})

// ============================================
// SUMMARY
// ============================================

console.log("\n" + "=".repeat(70))
console.log("VERIFICATION SUMMARY")
console.log("=".repeat(70))
console.log()
console.log(`Tests passed: ${testsPassed}`)
console.log(`Tests failed: ${testsFailed}`)
console.log()

if (testsFailed === 0) {
  console.log("All cryptographic operations verified successfully!")
  console.log()
  console.log("Verified operations:")
  console.log("  ✓ ECC P-256 key generation (ECDH + ECDSA)")
  console.log("  ✓ ECDH key exchange with shared secret derivation")
  console.log("  ✓ HKDF-SHA256 for session key derivation")
  console.log("  ✓ AES-256-GCM authenticated encryption")
  console.log("  ✓ AES-GCM tamper detection")
  console.log("  ✓ ECDSA digital signatures")
  console.log("  ✓ Signature verification and forgery detection")
  console.log("  ✓ PBKDF2-SHA512 password hashing")
  console.log("  ✓ Cryptographically secure random number generation")
} else {
  console.log("Some tests failed! Review the errors above.")
  process.exit(1)
}

console.log("=".repeat(70))
