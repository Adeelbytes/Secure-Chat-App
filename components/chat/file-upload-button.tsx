"use client"

import type React from "react"
import { useRef, useState } from "react"
import { Paperclip, Loader2, X, FileIcon, Upload } from "lucide-react"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Progress } from "@/components/ui/progress"

interface FileUploadButtonProps {
  onUpload: (file: File) => Promise<void>
  disabled?: boolean
  maxSizeMB?: number
}

export function FileUploadButton({ onUpload, disabled, maxSizeMB = 10 }: FileUploadButtonProps) {
  const inputRef = useRef<HTMLInputElement>(null)
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [isUploading, setIsUploading] = useState(false)
  const [uploadProgress, setUploadProgress] = useState(0)
  const [error, setError] = useState<string | null>(null)
  const [showDialog, setShowDialog] = useState(false)

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return

    const maxBytes = maxSizeMB * 1024 * 1024
    if (file.size > maxBytes) {
      setError(`SIZE LIMIT: ${maxSizeMB}MB`)
      setShowDialog(true)
      return
    }

    setSelectedFile(file)
    setError(null)
    setShowDialog(true)

    if (inputRef.current) {
      inputRef.current.value = ""
    }
  }

  const handleUpload = async () => {
    if (!selectedFile) return

    setIsUploading(true)
    setUploadProgress(0)

    try {
      const progressInterval = setInterval(() => {
        setUploadProgress((prev) => {
          if (prev >= 90) {
            clearInterval(progressInterval)
            return 90
          }
          return prev + 10
        })
      }, 100)

      await onUpload(selectedFile)

      clearInterval(progressInterval)
      setUploadProgress(100)

      setTimeout(() => {
        setShowDialog(false)
        setSelectedFile(null)
        setUploadProgress(0)
      }, 500)
    } catch (err) {
      setError("ENCRYPTION FAILED")
      console.error("[v0] File upload error:", err)
    } finally {
      setIsUploading(false)
    }
  }

  const handleCancel = () => {
    setShowDialog(false)
    setSelectedFile(null)
    setError(null)
    setUploadProgress(0)
  }

  const formatFileSize = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`
  }

  return (
    <>
      <input
        ref={inputRef}
        type="file"
        className="hidden"
        onChange={handleFileSelect}
        disabled={disabled || isUploading}
      />

      <button
        type="button"
        onClick={() => inputRef.current?.click()}
        disabled={disabled || isUploading}
        title="ATTACH FILE"
        className="w-12 h-12 border-2 border-primary/50 flex items-center justify-center hover:border-primary hover:bg-primary/10 transition-colors disabled:opacity-30"
      >
        {isUploading ? (
          <Loader2 className="h-5 w-5 animate-spin text-primary" />
        ) : (
          <Paperclip className="h-5 w-5 text-primary" />
        )}
      </button>

      <Dialog open={showDialog} onOpenChange={(open) => !isUploading && !open && handleCancel()}>
        <DialogContent className="sm:max-w-md border-2 border-primary bg-background">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-primary uppercase tracking-widest text-sm">
              <Upload className="h-4 w-4" />
              ENCRYPT FILE
            </DialogTitle>
            <DialogDescription className="text-xs text-muted-foreground uppercase tracking-wider">
              E2E ENCRYPTION BEFORE TRANSMISSION
            </DialogDescription>
          </DialogHeader>

          {error ? (
            <div className="border-2 border-destructive bg-destructive/10 p-4 text-center">
              <p className="text-destructive text-xs uppercase tracking-widest font-bold">! {error}</p>
            </div>
          ) : selectedFile ? (
            <div className="space-y-4">
              <div className="flex items-center gap-4 border-2 border-primary/30 p-4">
                <div className="border-2 border-primary p-3">
                  <FileIcon className="h-6 w-6 text-primary" />
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm uppercase tracking-wider truncate text-foreground">{selectedFile.name}</p>
                  <p className="text-[10px] text-muted-foreground uppercase tracking-widest">
                    {formatFileSize(selectedFile.size)}
                  </p>
                </div>
                {!isUploading && (
                  <button onClick={handleCancel} className="p-2 hover:bg-primary/10 transition-colors">
                    <X className="h-4 w-4 text-muted-foreground" />
                  </button>
                )}
              </div>

              {isUploading && (
                <div className="space-y-2">
                  <div className="flex justify-between text-[10px] uppercase tracking-widest">
                    <span className="text-muted-foreground">
                      {uploadProgress < 90 ? "ENCRYPTING..." : "TRANSMITTING..."}
                    </span>
                    <span className="text-primary font-bold">{uploadProgress}%</span>
                  </div>
                  <Progress value={uploadProgress} className="h-1" />
                </div>
              )}
            </div>
          ) : null}

          <DialogFooter className="gap-2 sm:gap-2">
            <button
              onClick={handleCancel}
              disabled={isUploading}
              className="px-4 py-2 border-2 border-primary/50 text-primary/60 hover:border-primary hover:text-primary transition-colors text-xs uppercase tracking-widest disabled:opacity-50"
            >
              CANCEL
            </button>
            <button
              onClick={handleUpload}
              disabled={!selectedFile || isUploading || !!error}
              className="px-4 py-2 border-2 border-primary bg-primary text-background text-xs uppercase tracking-widest hover:bg-primary/90 transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
            >
              {isUploading ? (
                <>
                  <Loader2 className="h-3 w-3 animate-spin" />
                  ENCRYPTING...
                </>
              ) : (
                "TRANSMIT"
              )}
            </button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}
