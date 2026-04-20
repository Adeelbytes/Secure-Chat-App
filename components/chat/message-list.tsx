"use client"

import { useEffect, useRef, useState } from "react"
import { cn } from "@/lib/utils"
import { Terminal, AlertTriangle, FileIcon, Download, Loader2, CheckCircle2, Eye } from "lucide-react"
import { Progress } from "@/components/ui/progress"
import type { ChatMessage } from "@/lib/types"

interface MessageListProps {
  messages: ChatMessage[]
  currentUserId: string
  onDownloadFile?: (message: ChatMessage) => Promise<void>
}

function FileMessageContent({
  message,
  isOwn,
  onDownloadFile,
}: {
  message: ChatMessage
  isOwn: boolean
  onDownloadFile?: (message: ChatMessage) => Promise<void>
}) {
  const [downloadState, setDownloadState] = useState<"idle" | "downloading" | "decrypting" | "complete" | "error">(
    "idle",
  )
  const [progress, setProgress] = useState(0)

  const handleDownload = async () => {
    if (!message.fileId || !onDownloadFile) return

    setDownloadState("downloading")
    setProgress(0)

    const progressInterval = setInterval(() => {
      setProgress((prev) => {
        if (prev >= 50) {
          clearInterval(progressInterval)
          return 50
        }
        return prev + 10
      })
    }, 100)

    try {
      setDownloadState("decrypting")
      setProgress(70)

      await onDownloadFile(message)

      setProgress(100)
      setDownloadState("complete")

      setTimeout(() => {
        setDownloadState("idle")
        setProgress(0)
      }, 2000)
    } catch (error) {
      console.error("Download error:", error)
      setDownloadState("error")
      clearInterval(progressInterval)

      setTimeout(() => {
        setDownloadState("idle")
        setProgress(0)
      }, 3000)
    }
  }

  return (
    <div className="space-y-2">
      <div className="flex items-center gap-3">
        <div className="border-2 border-current p-2">
          <FileIcon className="h-6 w-6" />
        </div>
        <div className="flex-1 min-w-0">
          <p className="text-xs font-bold uppercase tracking-wider truncate">{message.fileName || "ENCRYPTED"}</p>
          <p className="text-[10px] opacity-60 uppercase tracking-widest">
            {message.fileSize ? `${(message.fileSize / 1024).toFixed(1)} KB` : "E2E"}
          </p>
        </div>
        {onDownloadFile && message.fileId && (
          <button
            onClick={handleDownload}
            disabled={downloadState !== "idle" && downloadState !== "error"}
            className="p-2 border-2 border-current hover:bg-current/10 transition-colors disabled:opacity-50"
          >
            {downloadState === "idle" && <Download className="h-4 w-4" />}
            {downloadState === "downloading" && <Loader2 className="h-4 w-4 animate-spin" />}
            {downloadState === "decrypting" && <Loader2 className="h-4 w-4 animate-spin" />}
            {downloadState === "complete" && <CheckCircle2 className="h-4 w-4" />}
            {downloadState === "error" && <AlertTriangle className="h-4 w-4" />}
          </button>
        )}
      </div>

      {(downloadState === "downloading" || downloadState === "decrypting") && (
        <div className="space-y-1">
          <Progress value={progress} className="h-1 bg-current/20" />
          <p className="text-[9px] uppercase tracking-widest opacity-60 text-center">
            {downloadState === "downloading" ? "FETCHING..." : "DECRYPTING..."}
          </p>
        </div>
      )}
    </div>
  )
}

export function MessageList({ messages, currentUserId, onDownloadFile }: MessageListProps) {
  const bottomRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" })
  }, [messages])

  if (messages.length === 0) {
    return (
      <div className="flex-1 flex items-center justify-center text-muted-foreground p-8">
        <div className="text-center space-y-4 border-2 border-dashed border-primary/30 p-8">
          <Terminal className="h-12 w-12 mx-auto text-primary/30" />
          <div>
            <p className="text-xs uppercase tracking-widest text-primary/60">CHANNEL EMPTY</p>
            <p className="text-[10px] text-muted-foreground mt-1">BEGIN TRANSMISSION</p>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="flex-1 overflow-y-auto p-4 space-y-3">
      {messages.map((message) => {
        const isOwn = message.senderId === currentUserId
        const displayContent = message.decryptedContent || message.content

        return (
          <div key={message.id} className={cn("flex", isOwn ? "justify-end" : "justify-start")}>
            <div
              className={cn(
                "max-w-[75%] border-2 px-4 py-3",
                isOwn ? "border-primary bg-primary text-background" : "border-primary/50 bg-background text-foreground",
                message.decryptionFailed && "border-destructive bg-destructive/10 text-destructive",
              )}
            >
              {message.decryptionFailed ? (
                <div className="flex items-center gap-2">
                  <AlertTriangle className="h-4 w-4" />
                  <span className="text-xs uppercase tracking-wider font-bold">DECRYPTION FAILED</span>
                </div>
              ) : message.isFile ? (
                <FileMessageContent message={message} isOwn={isOwn} onDownloadFile={onDownloadFile} />
              ) : (
                <p className="text-sm whitespace-pre-wrap font-mono">{displayContent || "[ENCRYPTED]"}</p>
              )}

              <div
                className={cn(
                  "flex items-center gap-2 mt-2 pt-2 border-t",
                  isOwn ? "border-background/20" : "border-primary/20",
                )}
              >
                <Eye className="h-3 w-3 opacity-40" />
                <span className="text-[9px] opacity-40 uppercase tracking-widest">
                  {new Date(message.timestamp).toLocaleTimeString()}
                </span>
              </div>
            </div>
          </div>
        )
      })}
      <div ref={bottomRef} />
    </div>
  )
}
