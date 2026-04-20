"use client"

import type React from "react"
import { useState } from "react"
import { Input } from "@/components/ui/input"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Loader2, Terminal, Shield } from "lucide-react"

interface RegisterFormProps {
  onRegister: (user: { id: string; username: string; publicKey: string; signaturePublicKey: string }) => void
}

export function RegisterForm({ onRegister }: RegisterFormProps) {
  const [username, setUsername] = useState("")
  const [password, setPassword] = useState("")
  const [confirmPassword, setConfirmPassword] = useState("")
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [keyGenStatus, setKeyGenStatus] = useState<string | null>(null)

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)

    if (!username.trim()) {
      setError("IDENTITY REQUIRED")
      return
    }

    if (password !== confirmPassword) {
      setError("KEY MISMATCH")
      return
    }

    if (password.length < 8) {
      setError("KEY TOO SHORT [MIN 8]")
      return
    }

    setIsLoading(true)

    try {
      if (typeof window === "undefined" || !window.crypto?.subtle) {
        throw new Error("CRYPTO API UNAVAILABLE")
      }

      setKeyGenStatus("GENERATING ECDH P-256...")

      const ecdhKeyPair = await window.crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, [
        "deriveBits",
        "deriveKey",
      ])

      setKeyGenStatus("GENERATING ECDSA P-256...")

      const signingKeyPair = await window.crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
        "sign",
        "verify",
      ])

      setKeyGenStatus("EXPORTING PUBLIC KEYS...")

      const ecdhPublicKeySpki = await window.crypto.subtle.exportKey("spki", ecdhKeyPair.publicKey)
      const signingPublicKeySpki = await window.crypto.subtle.exportKey("spki", signingKeyPair.publicKey)

      const publicKey = btoa(String.fromCharCode(...new Uint8Array(ecdhPublicKeySpki)))
      const signaturePublicKey = btoa(String.fromCharCode(...new Uint8Array(signingPublicKeySpki)))

      setKeyGenStatus("ENCRYPTING PRIVATE KEYS...")

      await storeKeysForUser(username, ecdhKeyPair.privateKey, signingKeyPair.privateKey, password)

      setKeyGenStatus("REGISTERING NODE...")

      const response = await fetch("/api/auth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username: username.trim(),
          password,
          publicKey,
          signaturePublicKey,
        }),
      })

      let data: {
        success?: boolean
        error?: string
        user?: { id: string; username: string; publicKey: string; signaturePublicKey: string }
      }
      try {
        const text = await response.text()
        data = JSON.parse(text)
      } catch {
        throw new Error("CONNECTION FAILED")
      }

      if (!response.ok) {
        throw new Error(data.error || `REGISTRATION DENIED [${response.status}]`)
      }

      if (!data.user) {
        throw new Error("INVALID RESPONSE")
      }

      setKeyGenStatus("NODE REGISTERED!")
      onRegister(data.user)
    } catch (err) {
      setError(err instanceof Error ? err.message : "REGISTRATION FAILED")
    } finally {
      setIsLoading(false)
      setKeyGenStatus(null)
    }
  }

  return (
    <form onSubmit={handleRegister} className="space-y-4">
      <div className="space-y-2">
        <label htmlFor="username" className="text-[10px] uppercase tracking-widest text-primary/60 block">
          {">"} NODE IDENTITY
        </label>
        <Input
          id="username"
          type="text"
          placeholder="ENTER UNIQUE ID"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          disabled={isLoading}
          required
          className="bg-transparent border-2 border-primary/50 focus:border-primary text-primary placeholder:text-primary/30 uppercase tracking-wider text-sm"
        />
      </div>

      <div className="space-y-2">
        <label htmlFor="password" className="text-[10px] uppercase tracking-widest text-primary/60 block">
          {">"} ENCRYPTION KEY
        </label>
        <Input
          id="password"
          type="password"
          placeholder="MIN 8 CHARS"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          disabled={isLoading}
          required
          className="bg-transparent border-2 border-primary/50 focus:border-primary text-primary placeholder:text-primary/30 tracking-wider"
        />
        <p className="text-[9px] text-primary/40 uppercase tracking-wider">USED TO ENCRYPT LOCAL KEYS</p>
      </div>

      <div className="space-y-2">
        <label htmlFor="confirmPassword" className="text-[10px] uppercase tracking-widest text-primary/60 block">
          {">"} CONFIRM KEY
        </label>
        <Input
          id="confirmPassword"
          type="password"
          placeholder="REPEAT KEY"
          value={confirmPassword}
          onChange={(e) => setConfirmPassword(e.target.value)}
          disabled={isLoading}
          required
          className="bg-transparent border-2 border-primary/50 focus:border-primary text-primary placeholder:text-primary/30 tracking-wider"
        />
      </div>

      {error && (
        <Alert className="bg-destructive/10 border-2 border-destructive text-destructive">
          <AlertDescription className="text-xs uppercase tracking-wider font-bold">! {error}</AlertDescription>
        </Alert>
      )}

      {keyGenStatus && (
        <Alert className="bg-primary/10 border-2 border-primary text-primary">
          <Terminal className="h-4 w-4" />
          <AlertDescription className="text-xs uppercase tracking-wider font-mono">{keyGenStatus}</AlertDescription>
        </Alert>
      )}

      <button
        type="submit"
        className="w-full border-2 border-primary bg-primary text-background py-3 uppercase tracking-widest text-sm font-bold hover:bg-primary/90 transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2 neon-glow"
        disabled={isLoading}
      >
        {isLoading ? (
          <>
            <Loader2 className="h-4 w-4 animate-spin" />
            GENERATING KEYS...
          </>
        ) : (
          <>
            <Shield className="h-4 w-4" />
            CREATE NODE
          </>
        )}
      </button>
    </form>
  )
}

async function storeKeysForUser(
  username: string,
  ecdhPrivateKey: CryptoKey,
  ecdsaPrivateKey: CryptoKey,
  password: string,
): Promise<void> {
  const encoder = new TextEncoder()
  const passwordKey = await window.crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, [
    "deriveKey",
  ])

  const salt = window.crypto.getRandomValues(new Uint8Array(16))
  const derivedKey = await window.crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: 100000,
      hash: "SHA-256",
    },
    passwordKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  )

  const ecdhKeyData = await window.crypto.subtle.exportKey("pkcs8", ecdhPrivateKey)
  const iv1 = window.crypto.getRandomValues(new Uint8Array(12))
  const encryptedEcdh = await window.crypto.subtle.encrypt({ name: "AES-GCM", iv: iv1 }, derivedKey, ecdhKeyData)

  const ecdsaKeyData = await window.crypto.subtle.exportKey("pkcs8", ecdsaPrivateKey)
  const iv2 = window.crypto.getRandomValues(new Uint8Array(12))
  const encryptedEcdsa = await window.crypto.subtle.encrypt({ name: "AES-GCM", iv: iv2 }, derivedKey, ecdsaKeyData)

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

  const tx = db.transaction("keys", "readwrite")
  const store = tx.objectStore("keys")

  await new Promise<void>((resolve, reject) => {
    const request = store.put({
      id: username,
      salt: Array.from(salt),
      ecdhKey: {
        iv: Array.from(iv1),
        data: Array.from(new Uint8Array(encryptedEcdh)),
      },
      ecdsaKey: {
        iv: Array.from(iv2),
        data: Array.from(new Uint8Array(encryptedEcdsa)),
      },
    })
    request.onsuccess = () => resolve()
    request.onerror = () => reject(request.error)
  })

  db.close()
}
