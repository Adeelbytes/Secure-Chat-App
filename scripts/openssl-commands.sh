#!/bin/bash
# OpenSSL Commands for Secure Messaging System Verification
# Run these commands to verify cryptographic operations outside the browser

echo "=================================================="
echo "OpenSSL Verification Commands for Secure Messaging"
echo "=================================================="

# ============================================
# 1. GENERATE ECC KEY PAIRS (P-256)
# ============================================

echo ""
echo "=== 1. Generating ECC Key Pairs (ECDH/ECDSA) ==="

# Generate private key for ECDH
openssl ecparam -name prime256v1 -genkey -noout -out ecdh_private.pem
echo "Generated: ecdh_private.pem"

# Extract public key
openssl ec -in ecdh_private.pem -pubout -out ecdh_public.pem
echo "Generated: ecdh_public.pem"

# Generate signing key pair (ECDSA)
openssl ecparam -name prime256v1 -genkey -noout -out ecdsa_private.pem
openssl ec -in ecdsa_private.pem -pubout -out ecdsa_public.pem
echo "Generated: ecdsa_private.pem, ecdsa_public.pem"

# View key details
echo ""
echo "=== Key Details ==="
openssl ec -in ecdh_private.pem -text -noout 2>/dev/null | head -20

# ============================================
# 2. ECDH KEY EXCHANGE SIMULATION
# ============================================

echo ""
echo "=== 2. Simulating ECDH Key Exchange ==="

# Generate Alice's key pair
openssl ecparam -name prime256v1 -genkey -noout -out alice_ecdh.pem
openssl ec -in alice_ecdh.pem -pubout -out alice_ecdh_pub.pem

# Generate Bob's key pair
openssl ecparam -name prime256v1 -genkey -noout -out bob_ecdh.pem
openssl ec -in bob_ecdh.pem -pubout -out bob_ecdh_pub.pem

echo "Alice's private key: alice_ecdh.pem"
echo "Alice's public key:  alice_ecdh_pub.pem"
echo "Bob's private key:   bob_ecdh.pem"
echo "Bob's public key:    bob_ecdh_pub.pem"

# Derive shared secret (Alice's side)
openssl pkeyutl -derive -inkey alice_ecdh.pem -peerkey bob_ecdh_pub.pem -out alice_shared.bin
echo "Alice's shared secret: alice_shared.bin"

# Derive shared secret (Bob's side)
openssl pkeyutl -derive -inkey bob_ecdh.pem -peerkey alice_ecdh_pub.pem -out bob_shared.bin
echo "Bob's shared secret:   bob_shared.bin"

# Compare shared secrets (should be identical!)
echo ""
echo "Verifying shared secrets match:"
echo "Alice's secret (hex): $(xxd -p alice_shared.bin | tr -d '\n')"
echo "Bob's secret (hex):   $(xxd -p bob_shared.bin | tr -d '\n')"

if diff alice_shared.bin bob_shared.bin > /dev/null; then
    echo "SUCCESS: Shared secrets match!"
else
    echo "ERROR: Shared secrets don't match!"
fi

# ============================================
# 3. KEY DERIVATION (HKDF)
# ============================================

echo ""
echo "=== 3. Key Derivation with HKDF ==="

# Note: OpenSSL 3.0+ supports HKDF
# For older versions, use: openssl kdf -keylen 32 -kdfopt digest:SHA256 ...

# Using OpenSSL 3.x HKDF
if openssl version | grep -q "OpenSSL 3"; then
    openssl kdf -keylen 32 -kdfopt digest:SHA256 \
        -kdfopt mode:EXTRACT_AND_EXPAND \
        -kdfopt key:$(xxd -p alice_shared.bin | tr -d '\n') \
        -kdfopt salt:$(echo -n "alice:bob" | xxd -p) \
        -kdfopt info:$(echo -n "session-key" | xxd -p) \
        -out session_key.bin \
        HKDF 2>/dev/null || echo "HKDF: Use the Node.js script for full HKDF support"
else
    echo "OpenSSL < 3.0 detected. HKDF available via Node.js script."
fi

# ============================================
# 4. AES-256-GCM ENCRYPTION
# ============================================

echo ""
echo "=== 4. AES-256-GCM Encryption Demo ==="

# Generate random key (256 bits) and IV (96 bits)
openssl rand -out aes_key.bin 32
openssl rand -out aes_iv.bin 12

echo "AES-256 Key: $(xxd -p aes_key.bin | tr -d '\n')"
echo "IV (96-bit): $(xxd -p aes_iv.bin | tr -d '\n')"

# Create test message
echo "Hello, this is a secret message!" > plaintext.txt
echo "Plaintext: $(cat plaintext.txt)"

# Encrypt with AES-256-GCM
openssl enc -aes-256-gcm \
    -K $(xxd -p aes_key.bin | tr -d '\n') \
    -iv $(xxd -p aes_iv.bin | tr -d '\n') \
    -in plaintext.txt \
    -out ciphertext.bin 2>/dev/null || {
    # Fallback for older OpenSSL without GCM support
    openssl enc -aes-256-cbc \
        -K $(xxd -p aes_key.bin | tr -d '\n') \
        -iv $(xxd -p aes_iv.bin | head -c 32 | tr -d '\n') \
        -in plaintext.txt \
        -out ciphertext.bin
    echo "Note: Using AES-CBC (GCM requires OpenSSL 3.0+)"
}

echo "Ciphertext (hex): $(xxd -p ciphertext.bin | tr -d '\n' | head -c 64)..."

# Decrypt
openssl enc -d -aes-256-gcm \
    -K $(xxd -p aes_key.bin | tr -d '\n') \
    -iv $(xxd -p aes_iv.bin | tr -d '\n') \
    -in ciphertext.bin \
    -out decrypted.txt 2>/dev/null || {
    openssl enc -d -aes-256-cbc \
        -K $(xxd -p aes_key.bin | tr -d '\n') \
        -iv $(xxd -p aes_iv.bin | head -c 32 | tr -d '\n') \
        -in ciphertext.bin \
        -out decrypted.txt
}

echo "Decrypted: $(cat decrypted.txt)"

# ============================================
# 5. ECDSA DIGITAL SIGNATURES
# ============================================

echo ""
echo "=== 5. ECDSA Digital Signatures ==="

# Create message to sign
echo "key-exchange|alice|bob|publickey123|1701234567890|nonce456" > message_to_sign.txt

# Sign with private key
openssl dgst -sha256 -sign ecdsa_private.pem -out signature.bin message_to_sign.txt
echo "Signature created: signature.bin"
echo "Signature (base64): $(base64 < signature.bin | tr -d '\n' | head -c 60)..."

# Verify with public key
echo ""
echo "Verifying signature..."
if openssl dgst -sha256 -verify ecdsa_public.pem -signature signature.bin message_to_sign.txt; then
    echo "SUCCESS: Signature is valid!"
else
    echo "ERROR: Signature verification failed!"
fi

# Test with tampered message
echo "key-exchange|alice|bob|ATTACKERKEY|1701234567890|nonce456" > tampered_message.txt
echo ""
echo "Verifying tampered message..."
if openssl dgst -sha256 -verify ecdsa_public.pem -signature signature.bin tampered_message.txt 2>/dev/null; then
    echo "ERROR: Tampered message accepted (this shouldn't happen!)"
else
    echo "SUCCESS: Tampered message rejected!"
fi

# ============================================
# 6. PASSWORD HASHING (PBKDF2)
# ============================================

echo ""
echo "=== 6. Password Hashing with PBKDF2 ==="

PASSWORD="SecurePassword123!"
SALT=$(openssl rand -hex 16)

echo "Password: $PASSWORD"
echo "Salt: $SALT"

# PBKDF2 with SHA-512, 100000 iterations, 64-byte output
HASH=$(echo -n "$PASSWORD" | openssl dgst -sha512 -mac HMAC -macopt hexkey:$SALT -iter 100000 2>/dev/null | cut -d' ' -f2)

# Alternative for older OpenSSL
if [ -z "$HASH" ]; then
    HASH=$(openssl kdf -keylen 64 -kdfopt digest:SHA512 \
        -kdfopt pass:$PASSWORD \
        -kdfopt salt:$(echo -n "$SALT" | xxd -p) \
        -kdfopt iter:100000 \
        PBKDF2 2>/dev/null | xxd -p | tr -d '\n')
fi

echo "Password Hash (PBKDF2): ${HASH:-Use Node.js script for full PBKDF2}"

# ============================================
# 7. CONVERT KEYS TO JWK FORMAT
# ============================================

echo ""
echo "=== 7. Converting Keys to JWK Format ==="

# This requires additional tools, showing structure instead
echo "Web Crypto API uses JWK format. Example structure:"
cat << 'EOF'
{
  "kty": "EC",
  "crv": "P-256",
  "x": "base64url-encoded-x-coordinate",
  "y": "base64url-encoded-y-coordinate",
  "d": "base64url-encoded-private-key (only in private key)"
}
EOF

# ============================================
# CLEANUP
# ============================================

echo ""
echo "=== Cleanup ==="
echo "Generated files:"
ls -la *.pem *.bin *.txt 2>/dev/null

echo ""
echo "To clean up generated files, run:"
echo "rm -f *.pem *.bin plaintext.txt decrypted.txt message_to_sign.txt tampered_message.txt"

echo ""
echo "=================================================="
echo "OpenSSL verification complete!"
echo "=================================================="
