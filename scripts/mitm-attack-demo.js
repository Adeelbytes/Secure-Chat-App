/**
 * MITM Attack Demonstration Script
 *
 * This script demonstrates how a Man-in-the-Middle attack would work
 * against a Diffie-Hellman key exchange WITHOUT digital signatures,
 * and how our system prevents it WITH digital signatures.
 *
 * Run: node scripts/mitm-attack-demo.js
 */

const crypto = require("crypto")

console.log("=".repeat(70))
console.log("MAN-IN-THE-MIDDLE (MITM) ATTACK DEMONSTRATION")
console.log("=".repeat(70))
console.log()

// ============================================
// PART 1: VULNERABLE DH WITHOUT SIGNATURES
// ============================================

console.log("SCENARIO 1: Diffie-Hellman WITHOUT Digital Signatures (VULNERABLE)")
console.log("-".repeat(70))
console.log()

// Generate key pairs for Alice, Bob, and Mallory (attacker)
const aliceECDH = crypto.createECDH("prime256v1")
aliceECDH.generateKeys()

const bobECDH = crypto.createECDH("prime256v1")
bobECDH.generateKeys()

const malloryECDH_alice = crypto.createECDH("prime256v1") // Key pair for Alice
malloryECDH_alice.generateKeys()

const malloryECDH_bob = crypto.createECDH("prime256v1") // Key pair for Bob
malloryECDH_bob.generateKeys()

console.log("1. Alice generates her ECDH key pair")
console.log(`   Alice Public Key: ${aliceECDH.getPublicKey("hex").substring(0, 40)}...`)
console.log()

console.log("2. Alice sends public key to Bob (through network)")
console.log("   [MALLORY INTERCEPTS THE MESSAGE]")
console.log()

console.log("3. Mallory replaces Alice's public key with her own")
console.log(`   Original (Alice):  ${aliceECDH.getPublicKey("hex").substring(0, 40)}...`)
console.log(`   Replaced (Mallory): ${malloryECDH_bob.getPublicKey("hex").substring(0, 40)}...`)
console.log()

console.log("4. Bob receives Mallory's key (thinking it's Alice's)")
console.log("   Bob computes shared secret with Mallory's key")

// Bob's "shared secret" is actually with Mallory
const bobSharedWithMallory = bobECDH.computeSecret(malloryECDH_bob.getPublicKey())
console.log(`   Bob's "shared secret": ${bobSharedWithMallory.toString("hex").substring(0, 40)}...`)
console.log()

console.log("5. Bob sends his public key to Alice (through network)")
console.log("   [MALLORY INTERCEPTS AGAIN]")
console.log()

console.log("6. Mallory replaces Bob's public key with her own")
console.log(`   Original (Bob):    ${bobECDH.getPublicKey("hex").substring(0, 40)}...`)
console.log(`   Replaced (Mallory): ${malloryECDH_alice.getPublicKey("hex").substring(0, 40)}...`)
console.log()

console.log("7. Alice receives Mallory's key (thinking it's Bob's)")
const aliceSharedWithMallory = aliceECDH.computeSecret(malloryECDH_alice.getPublicKey())
console.log(`   Alice's "shared secret": ${aliceSharedWithMallory.toString("hex").substring(0, 40)}...`)
console.log()

// Mallory can compute both shared secrets
const mallorySharedWithAlice = malloryECDH_alice.computeSecret(aliceECDH.getPublicKey())
const mallorySharedWithBob = malloryECDH_bob.computeSecret(bobECDH.getPublicKey())

console.log("8. ATTACK SUCCESS! Mallory knows both shared secrets:")
console.log(`   With Alice: ${mallorySharedWithAlice.toString("hex").substring(0, 40)}...`)
console.log(`   With Bob:   ${mallorySharedWithBob.toString("hex").substring(0, 40)}...`)
console.log()

console.log("9. Message flow with MITM:")
console.log("   Alice --[encrypted with mallory key]--> Mallory")
console.log("   Mallory decrypts, reads/modifies message")
console.log("   Mallory --[re-encrypted with bob key]--> Bob")
console.log()
console.log("   RESULT: Mallory can read and modify ALL messages!")
console.log()

// ============================================
// PART 2: SECURE ECDH WITH SIGNATURES
// ============================================

console.log("=".repeat(70))
console.log("SCENARIO 2: ECDH WITH Digital Signatures (SECURE - Our System)")
console.log("-".repeat(70))
console.log()

// Generate signing key pairs (long-term identity keys)
const aliceSign = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" })
const bobSign = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" })
const mallorySign = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" })

// Generate new ECDH keys for secure exchange
const aliceECDH2 = crypto.createECDH("prime256v1")
aliceECDH2.generateKeys()

const bobECDH2 = crypto.createECDH("prime256v1")
bobECDH2.generateKeys()

console.log("1. Alice and Bob have registered signing keys (public keys known to each other)")
console.log(
  `   Alice Signing Key: ${aliceSign.publicKey.export({ type: "spki", format: "der" }).toString("hex").substring(0, 40)}...`,
)
console.log(
  `   Bob Signing Key:   ${bobSign.publicKey.export({ type: "spki", format: "der" }).toString("hex").substring(0, 40)}...`,
)
console.log()

// Alice creates signed key exchange message
const timestamp = Date.now()
const nonce = crypto.randomBytes(16).toString("hex")
const aliceMessage = `INIT|alice|bob|${aliceECDH2.getPublicKey("hex")}|${timestamp}|${nonce}`

const aliceSignature = crypto.sign("sha256", Buffer.from(aliceMessage), aliceSign.privateKey)

console.log("2. Alice sends SIGNED key exchange INIT:")
console.log(`   Message: INIT|alice|bob|[publicKey]|${timestamp}|${nonce}`)
console.log(`   Signature: ${aliceSignature.toString("hex").substring(0, 40)}...`)
console.log()

console.log("3. [MALLORY INTERCEPTS] Attempts to replace public key")
const malloryFakeMessage = `INIT|alice|bob|${malloryECDH_bob.getPublicKey("hex")}|${timestamp}|${nonce}`

console.log("   Mallory cannot create valid signature without Alice's private signing key!")
console.log()

// Mallory tries to use Alice's signature with modified message
console.log("4. Mallory forwards modified message with ORIGINAL signature")
console.log()

console.log("5. Bob verifies signature:")
try {
  const isValid = crypto.verify(
    "sha256",
    Buffer.from(malloryFakeMessage), // Modified message
    aliceSign.publicKey,
    aliceSignature, // Original signature
  )

  if (isValid) {
    console.log("   VERIFICATION: PASSED (this should NOT happen!)")
  } else {
    console.log("   VERIFICATION: FAILED")
    console.log("   Reason: Signature does not match modified message content")
  }
} catch (err) {
  console.log("   VERIFICATION: FAILED")
  console.log(`   Error: ${err.message}`)
}
console.log()

console.log("6. Bob REJECTS the key exchange message")
console.log("   ATTACK PREVENTED!")
console.log()

// Show successful exchange
console.log("7. Legitimate key exchange (without MITM):")

// Alice's message verified successfully
const legitMessage = aliceMessage
const legitSignature = aliceSignature

const isLegitValid = crypto.verify("sha256", Buffer.from(legitMessage), aliceSign.publicKey, legitSignature)
console.log(`   Alice's signature verified: ${isLegitValid}`)

// Bob responds with signed message
const bobTimestamp = Date.now()
const bobNonce = crypto.randomBytes(16).toString("hex")
const bobMessage = `RESPONSE|bob|alice|${bobECDH2.getPublicKey("hex")}|${bobTimestamp}|${bobNonce}|${nonce}`
const bobSignature = crypto.sign("sha256", Buffer.from(bobMessage), bobSign.privateKey)

const isBobValid = crypto.verify("sha256", Buffer.from(bobMessage), bobSign.publicKey, bobSignature)
console.log(`   Bob's signature verified: ${isBobValid}`)
console.log()

// Both compute SAME shared secret
const aliceShared = aliceECDH2.computeSecret(bobECDH2.getPublicKey())
const bobShared = bobECDH2.computeSecret(aliceECDH2.getPublicKey())

console.log("8. Shared secrets computed:")
console.log(`   Alice's secret: ${aliceShared.toString("hex").substring(0, 40)}...`)
console.log(`   Bob's secret:   ${bobShared.toString("hex").substring(0, 40)}...`)
console.log(`   Match: ${aliceShared.equals(bobShared)}`)
console.log()

console.log("=".repeat(70))
console.log("SUMMARY")
console.log("=".repeat(70))
console.log()
console.log("Without Signatures:")
console.log("  - Attacker can replace public keys")
console.log("  - Attacker establishes separate keys with both parties")
console.log("  - All messages can be read and modified")
console.log()
console.log("With Signatures (Our System):")
console.log("  - Public keys are signed with long-term identity keys")
console.log("  - Any modification invalidates the signature")
console.log("  - Attacker cannot forge signatures without private key")
console.log("  - MITM attack is DETECTED and PREVENTED")
console.log()
console.log("Our implementation uses:")
console.log("  - ECDH P-256 for key exchange")
console.log("  - ECDSA P-256 for signatures")
console.log("  - Timestamps to prevent replay")
console.log("  - Nonces for uniqueness")
console.log("=".repeat(70))
