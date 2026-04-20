"use client"

import type React from "react"
import { useState } from "react"
import { Input } from "@/components/ui/input"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Loader2, Zap } from "lucide-react"

interface LoginFormProps {
  onLogin: (
    user: { id: string; username: string; publicKey: string; signaturePublicKey: string },
    sessionToken: string,
    password: string,
  ) => void
}

export function LoginForm({ onLogin }: LoginFormProps) {
  const [username, setUsername] = useState("")
  const [password, setPassword] = useState("")
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    setIsLoading(true)

    try {
      if (!username.trim()) {
        throw new Error("IDENTITY REQUIRED")
      }
      if (!password) {
        throw new Error("KEY REQUIRED")
      }

      const response = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: username.trim(), password }),
      })

      let data: {
        success?: boolean
        error?: string
        user?: { id: string; username: string; publicKey: string; signaturePublicKey: string }
        token?: string
      }
      try {
        const text = await response.text()
        data = JSON.parse(text)
      } catch {
        throw new Error("CONNECTION FAILED")
      }

      if (!response.ok) {
        throw new Error(data.error || `ACCESS DENIED [${response.status}]`)
      }

      if (!data.user || !data.token) {
        throw new Error("INVALID RESPONSE")
      }

      onLogin(data.user, data.token, password)
    } catch (err) {
      setError(err instanceof Error ? err.message : "AUTHENTICATION FAILED")
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <form onSubmit={handleLogin} className="space-y-4">
      <div className="space-y-2">
        <label htmlFor="login-username" className="text-[10px] uppercase tracking-widest text-primary/60 block">
          {">"} IDENTITY
        </label>
        <Input
          id="login-username"
          type="text"
          placeholder="ENTER NODE ID"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          disabled={isLoading}
          required
          className="bg-transparent border-2 border-primary/50 focus:border-primary text-primary placeholder:text-primary/30 uppercase tracking-wider text-sm"
        />
      </div>

      <div className="space-y-2">
        <label htmlFor="login-password" className="text-[10px] uppercase tracking-widest text-primary/60 block">
          {">"} PRIVATE KEY
        </label>
        <Input
          id="login-password"
          type="password"
          placeholder="••••••••••••"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
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

      <button
        type="submit"
        className="w-full border-2 border-primary bg-primary text-background py-3 uppercase tracking-widest text-sm font-bold hover:bg-primary/90 transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2 neon-glow"
        disabled={isLoading}
      >
        {isLoading ? (
          <>
            <Loader2 className="h-4 w-4 animate-spin" />
            AUTHENTICATING...
          </>
        ) : (
          <>
            <Zap className="h-4 w-4" />
            CONNECT
          </>
        )}
      </button>
    </form>
  )
}
