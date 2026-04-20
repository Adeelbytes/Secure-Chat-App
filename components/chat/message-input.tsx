"use client"

import type React from "react"
import { useState } from "react"
import { Input } from "@/components/ui/input"
import { Send, Loader2, Terminal } from "lucide-react"

interface MessageInputProps {
  onSend: (message: string) => Promise<void>
  disabled?: boolean
}

export function MessageInput({ onSend, disabled }: MessageInputProps) {
  const [message, setMessage] = useState("")
  const [isSending, setIsSending] = useState(false)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!message.trim() || disabled || isSending) return

    setIsSending(true)
    try {
      await onSend(message.trim())
      setMessage("")
    } finally {
      setIsSending(false)
    }
  }

  return (
    <form onSubmit={handleSubmit} className="flex-1 flex items-center gap-3">
      <div className="flex-1 relative">
        <Terminal className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-primary/40" />
        <Input
          value={message}
          onChange={(e) => setMessage(e.target.value)}
          placeholder={disabled ? "HANDSHAKE REQUIRED..." : "ENTER MESSAGE..."}
          disabled={disabled || isSending}
          className="pl-10 bg-transparent border-2 border-primary/50 focus:border-primary text-foreground placeholder:text-primary/30 uppercase text-sm tracking-wider"
        />
      </div>

      <button
        type="submit"
        disabled={!message.trim() || disabled || isSending}
        className="w-12 h-12 border-2 border-primary bg-primary text-background flex items-center justify-center hover:bg-primary/90 transition-colors disabled:opacity-30 disabled:cursor-not-allowed neon-glow"
      >
        {isSending ? <Loader2 className="h-5 w-5 animate-spin" /> : <Send className="h-5 w-5" />}
      </button>
    </form>
  )
}
