"use client"

import { useState } from "react"
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Loader2, Zap, CheckCircle, AlertTriangle, Terminal } from "lucide-react"

interface KeyExchangeDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  peerUsername: string
  state: "idle" | "initiating" | "responding" | "complete" | "error"
  onInitiate: () => Promise<void>
}

export function KeyExchangeDialog({ open, onOpenChange, peerUsername, state, onInitiate }: KeyExchangeDialogProps) {
  const [error, setError] = useState<string | null>(null)

  const handleInitiate = async () => {
    setError(null)
    try {
      await onInitiate()
    } catch (err) {
      setError(err instanceof Error ? err.message : "HANDSHAKE FAILED")
    }
  }

  const status =
    state === "error" ? "error" : state === "responding" ? "waiting" : state === "complete" ? "complete" : state

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md border-2 border-primary bg-background">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-primary uppercase tracking-widest text-sm">
            <Zap className="h-4 w-4" />
            KEY EXCHANGE
          </DialogTitle>
          <DialogDescription className="text-xs text-muted-foreground uppercase tracking-wider">
            ESTABLISH SECURE CHANNEL WITH {peerUsername.toUpperCase()}
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-6 py-4">
          {/* Status display */}
          <div className="flex items-center justify-center py-8">
            {status === "idle" && (
              <div className="text-center space-y-4">
                <div className="w-16 h-16 border-2 border-primary/30 mx-auto flex items-center justify-center">
                  <Terminal className="h-8 w-8 text-primary/30" />
                </div>
                <div>
                  <p className="text-xs uppercase tracking-widest text-primary/60">READY</p>
                  <p className="text-[10px] text-muted-foreground uppercase tracking-wider mt-1">
                    ECDH P-256 + HKDF-SHA256
                  </p>
                </div>
              </div>
            )}

            {status === "initiating" && (
              <div className="text-center space-y-4">
                <div className="w-16 h-16 border-2 border-primary mx-auto flex items-center justify-center">
                  <Loader2 className="h-8 w-8 text-primary animate-spin" />
                </div>
                <div>
                  <p className="text-xs uppercase tracking-widest text-primary">COMPUTING...</p>
                  <p className="text-[10px] text-muted-foreground uppercase tracking-wider mt-1">
                    DERIVING SHARED SECRET
                  </p>
                </div>
              </div>
            )}

            {status === "waiting" && (
              <div className="text-center space-y-4">
                <div className="w-16 h-16 border-2 border-accent mx-auto flex items-center justify-center">
                  <Loader2 className="h-8 w-8 text-accent animate-spin" />
                </div>
                <div>
                  <p className="text-xs uppercase tracking-widest text-accent">WAITING...</p>
                  <p className="text-[10px] text-muted-foreground uppercase tracking-wider mt-1">
                    PEER RESPONSE PENDING
                  </p>
                </div>
              </div>
            )}

            {status === "complete" && (
              <div className="text-center space-y-4">
                <div className="w-16 h-16 border-2 border-primary bg-primary mx-auto flex items-center justify-center">
                  <CheckCircle className="h-8 w-8 text-background" />
                </div>
                <div>
                  <p className="text-xs uppercase tracking-widest text-primary font-bold">SECURE CHANNEL ESTABLISHED</p>
                  <p className="text-[10px] text-muted-foreground uppercase tracking-wider mt-1">AES-256-GCM ACTIVE</p>
                </div>
              </div>
            )}

            {status === "error" && (
              <div className="text-center space-y-4">
                <div className="w-16 h-16 border-2 border-destructive mx-auto flex items-center justify-center">
                  <AlertTriangle className="h-8 w-8 text-destructive" />
                </div>
                <div>
                  <p className="text-xs uppercase tracking-widest text-destructive font-bold">HANDSHAKE FAILED</p>
                  <p className="text-[10px] text-muted-foreground uppercase tracking-wider mt-1">RETRY REQUIRED</p>
                </div>
              </div>
            )}
          </div>

          {error && (
            <Alert className="bg-destructive/10 border-2 border-destructive">
              <AlertDescription className="text-xs uppercase tracking-wider text-destructive font-bold">
                ! {error}
              </AlertDescription>
            </Alert>
          )}

          <div className="flex justify-end gap-2">
            <button
              onClick={() => onOpenChange(false)}
              className="px-4 py-2 border-2 border-primary/50 text-primary/60 hover:border-primary hover:text-primary transition-colors text-xs uppercase tracking-widest"
            >
              {status === "complete" ? "CLOSE" : "CANCEL"}
            </button>

            {(status === "idle" || status === "error") && (
              <button
                onClick={handleInitiate}
                className="px-4 py-2 border-2 border-primary bg-primary text-background text-xs uppercase tracking-widest hover:bg-primary/90 transition-colors flex items-center gap-2 neon-glow"
              >
                <Zap className="h-3 w-3" />
                {status === "error" ? "RETRY" : "INITIATE"}
              </button>
            )}
          </div>
        </div>
      </DialogContent>
    </Dialog>
  )
}
