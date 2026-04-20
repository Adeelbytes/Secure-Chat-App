"use client"

import type React from "react"
import { useState } from "react"
import { ScrollArea } from "@/components/ui/scroll-area"
import {
  Terminal,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Zap,
  FileText,
  RefreshCw,
  Download,
  Send,
  Eye,
} from "lucide-react"
import type { LogEntry, SecurityEventType } from "@/lib/types"

interface SecurityLogsProps {
  logs: LogEntry[]
  onRefresh?: () => void
}

const eventTypeConfig: Record<SecurityEventType, { icon: React.ReactNode; color: string }> = {
  AUTH_ATTEMPT: { icon: <Zap className="h-3 w-3" />, color: "text-accent" },
  AUTH_SUCCESS: { icon: <CheckCircle className="h-3 w-3" />, color: "text-primary" },
  AUTH_FAILURE: { icon: <XCircle className="h-3 w-3" />, color: "text-destructive" },
  KEY_EXCHANGE_INIT: { icon: <Zap className="h-3 w-3" />, color: "text-accent" },
  KEY_EXCHANGE_COMPLETE: { icon: <CheckCircle className="h-3 w-3" />, color: "text-primary" },
  KEY_EXCHANGE_FAILURE: { icon: <XCircle className="h-3 w-3" />, color: "text-destructive" },
  MESSAGE_DECRYPT_FAILURE: { icon: <AlertTriangle className="h-3 w-3" />, color: "text-accent" },
  REPLAY_ATTACK_DETECTED: { icon: <AlertTriangle className="h-3 w-3" />, color: "text-destructive" },
  INVALID_SIGNATURE: { icon: <AlertTriangle className="h-3 w-3" />, color: "text-destructive" },
  MITM_ATTEMPT_DETECTED: { icon: <AlertTriangle className="h-3 w-3" />, color: "text-destructive" },
  FILE_UPLOAD: { icon: <FileText className="h-3 w-3" />, color: "text-accent" },
  FILE_DOWNLOAD: { icon: <FileText className="h-3 w-3" />, color: "text-accent" },
  METADATA_ACCESS: { icon: <Eye className="h-3 w-3" />, color: "text-muted-foreground" },
  MESSAGE_SENT: { icon: <Send className="h-3 w-3" />, color: "text-primary" },
  MESSAGE_SEND_FAILURE: { icon: <XCircle className="h-3 w-3" />, color: "text-destructive" },
  FILE_UPLOAD_FAILURE: { icon: <XCircle className="h-3 w-3" />, color: "text-destructive" },
  MESSAGE_FAILED: { icon: <XCircle className="h-3 w-3" />, color: "text-destructive" },
  FILE_ENCRYPTED: { icon: <CheckCircle className="h-3 w-3" />, color: "text-primary" },
  FILE_ENCRYPTION_FAILED: { icon: <XCircle className="h-3 w-3" />, color: "text-destructive" },
  FILE_DECRYPTION_FAILED: { icon: <XCircle className="h-3 w-3" />, color: "text-destructive" },
  FILE_DECRYPTED: { icon: <CheckCircle className="h-3 w-3" />, color: "text-primary" },
  MESSAGE_ENCRYPTED: { icon: <CheckCircle className="h-3 w-3" />, color: "text-primary" },
}

export function SecurityLogs({ logs, onRefresh }: SecurityLogsProps) {
  const [filter, setFilter] = useState<"all" | "security" | "auth" | "keys">("all")

  const filteredLogs = logs.filter((log) => {
    if (filter === "all") return true
    if (filter === "security") {
      return [
        "REPLAY_ATTACK_DETECTED",
        "INVALID_SIGNATURE",
        "MITM_ATTEMPT_DETECTED",
        "MESSAGE_DECRYPT_FAILURE",
      ].includes(log.eventType)
    }
    if (filter === "auth") {
      return ["AUTH_ATTEMPT", "AUTH_SUCCESS", "AUTH_FAILURE"].includes(log.eventType)
    }
    if (filter === "keys") {
      return ["KEY_EXCHANGE_INIT", "KEY_EXCHANGE_COMPLETE", "KEY_EXCHANGE_FAILURE"].includes(log.eventType)
    }
    return true
  })

  const exportLogs = () => {
    const data = JSON.stringify(logs, null, 2)
    const blob = new Blob([data], { type: "application/json" })
    const url = URL.createObjectURL(blob)
    const a = document.createElement("a")
    a.href = url
    a.download = `audit-${Date.now()}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="border-2 border-primary">
      <div className="flex items-center justify-between px-4 py-3 border-b-2 border-primary bg-primary/5">
        <div className="flex items-center gap-2">
          <Terminal className="h-4 w-4 text-primary" />
          <span className="text-xs uppercase tracking-widest text-primary font-bold">AUDIT LOG</span>
        </div>
        <div className="flex gap-2">
          {onRefresh && (
            <button
              onClick={onRefresh}
              className="px-3 py-1 border border-primary/50 text-primary text-[10px] uppercase tracking-widest hover:bg-primary/10 transition-colors flex items-center gap-1"
            >
              <RefreshCw className="h-3 w-3" />
              REFRESH
            </button>
          )}
          <button
            onClick={exportLogs}
            className="px-3 py-1 border border-primary/50 text-primary text-[10px] uppercase tracking-widest hover:bg-primary/10 transition-colors flex items-center gap-1"
          >
            <Download className="h-3 w-3" />
            EXPORT
          </button>
        </div>
      </div>

      <div className="p-4">
        <div className="flex gap-2 mb-4">
          {(["all", "security", "auth", "keys"] as const).map((f) => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={`px-3 py-1 border-2 text-[10px] uppercase tracking-widest transition-colors ${
                filter === f
                  ? "border-primary bg-primary text-background"
                  : "border-primary/30 text-primary/60 hover:border-primary hover:text-primary"
              }`}
            >
              {f}
            </button>
          ))}
        </div>

        <ScrollArea className="h-[400px]">
          <div className="space-y-1 font-mono">
            {filteredLogs.length === 0 ? (
              <p className="text-center text-muted-foreground py-8 text-[10px] uppercase tracking-widest">NO LOGS</p>
            ) : (
              filteredLogs.map((log) => {
                const config = eventTypeConfig[log.eventType]
                return (
                  <div
                    key={log.id}
                    className="flex items-start gap-3 p-2 border border-primary/10 hover:border-primary/30 transition-colors"
                  >
                    <span className={`${config.color} mt-0.5`}>{config.icon}</span>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span
                          className={`text-[10px] uppercase tracking-wider font-bold ${log.success ? "text-primary" : "text-destructive"}`}
                        >
                          {log.eventType.replace(/_/g, " ")}
                        </span>
                        <span className="text-[9px] text-muted-foreground">
                          {new Date(log.timestamp).toLocaleTimeString()}
                        </span>
                      </div>
                      <p className="text-[10px] text-muted-foreground truncate mt-0.5">{log.details}</p>
                    </div>
                  </div>
                )
              })
            )}
          </div>
        </ScrollArea>
      </div>
    </div>
  )
}
