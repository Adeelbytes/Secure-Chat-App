// Security Event Logging System

import type { SecurityEventType } from "./types"

interface LogEntry {
  id: string
  eventType: SecurityEventType
  userId?: string
  targetUserId?: string
  ipAddress: string
  timestamp: Date
  details: string
  success: boolean
  metadata?: Record<string, unknown>
}

/**
 * Security Logger for audit trail
 */
export class SecurityLogger {
  private logs: LogEntry[] = []
  private maxLogs = 10000

  /**
   * Log a security event
   */
  public log(
    eventType: SecurityEventType,
    details: string,
    success: boolean,
    options?: {
      userId?: string
      targetUserId?: string
      ipAddress?: string
      metadata?: Record<string, unknown>
    },
  ): void {
    const entry: LogEntry = {
      id: `log_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      eventType,
      userId: options?.userId,
      targetUserId: options?.targetUserId,
      ipAddress: options?.ipAddress || "unknown",
      timestamp: new Date(),
      details,
      success,
      metadata: options?.metadata,
    }

    this.logs.push(entry)

    // Trim old logs if needed
    if (this.logs.length > this.maxLogs) {
      this.logs = this.logs.slice(-this.maxLogs)
    }

    // Console output for demonstration
    const logLevel = success ? "info" : "warn"
    console[logLevel](`[SECURITY] [${eventType}] ${details}`, options?.metadata || "")
  }

  /**
   * Log authentication attempt
   */
  public logAuthAttempt(userId: string, success: boolean, ipAddress: string, reason?: string): void {
    this.log(
      success ? "AUTH_SUCCESS" : "AUTH_FAILURE",
      success
        ? `User ${userId} authenticated successfully`
        : `Authentication failed for user ${userId}: ${reason || "unknown reason"}`,
      success,
      { userId, ipAddress },
    )
  }

  /**
   * Log key exchange event
   */
  public logKeyExchange(
    userId: string,
    targetUserId: string,
    success: boolean,
    stage: "init" | "complete" | "failure",
    details?: string,
  ): void {
    const eventType: SecurityEventType =
      stage === "failure" ? "KEY_EXCHANGE_FAILURE" : stage === "init" ? "KEY_EXCHANGE_INIT" : "KEY_EXCHANGE_COMPLETE"

    this.log(
      eventType,
      `Key exchange ${stage} between ${userId} and ${targetUserId}${details ? `: ${details}` : ""}`,
      success,
      { userId, targetUserId },
    )
  }

  /**
   * Log replay attack detection
   */
  public logReplayAttack(userId: string, details: string, metadata?: Record<string, unknown>): void {
    this.log("REPLAY_ATTACK_DETECTED", `Replay attack detected for user ${userId}: ${details}`, false, {
      userId,
      metadata,
    })
  }

  /**
   * Log invalid signature detection
   */
  public logInvalidSignature(senderId: string, receiverId: string, messageType: string): void {
    this.log(
      "INVALID_SIGNATURE",
      `Invalid signature detected in ${messageType} from ${senderId} to ${receiverId}`,
      false,
      { userId: senderId, targetUserId: receiverId },
    )
  }

  /**
   * Log MITM attempt detection
   */
  public logMITMAttempt(userId: string, details: string): void {
    this.log("MITM_ATTEMPT_DETECTED", `Potential MITM attack detected for ${userId}: ${details}`, false, { userId })
  }

  /**
   * Log message decryption failure
   */
  public logDecryptionFailure(userId: string, messageId: string, reason: string): void {
    this.log(
      "MESSAGE_DECRYPT_FAILURE",
      `Message decryption failed for user ${userId}, message ${messageId}: ${reason}`,
      false,
      { userId, metadata: { messageId, reason } },
    )
  }

  /**
   * Log file operation
   */
  public logFileOperation(userId: string, operation: "upload" | "download", fileId: string, success: boolean): void {
    this.log(
      operation === "upload" ? "FILE_UPLOAD" : "FILE_DOWNLOAD",
      `User ${userId} ${operation}ed file ${fileId}`,
      success,
      { userId, metadata: { fileId } },
    )
  }

  /**
   * Get all logs
   */
  public getLogs(): LogEntry[] {
    return [...this.logs]
  }

  /**
   * Get logs by event type
   */
  public getLogsByType(eventType: SecurityEventType): LogEntry[] {
    return this.logs.filter((log) => log.eventType === eventType)
  }

  /**
   * Get logs by user
   */
  public getLogsByUser(userId: string): LogEntry[] {
    return this.logs.filter((log) => log.userId === userId || log.targetUserId === userId)
  }

  /**
   * Get failed security events
   */
  public getFailedEvents(): LogEntry[] {
    return this.logs.filter((log) => !log.success)
  }

  /**
   * Get logs within time range
   */
  public getLogsInRange(startTime: Date, endTime: Date): LogEntry[] {
    return this.logs.filter((log) => log.timestamp >= startTime && log.timestamp <= endTime)
  }

  /**
   * Export logs as JSON
   */
  public exportLogs(): string {
    return JSON.stringify(this.logs, null, 2)
  }

  /**
   * Clear all logs
   */
  public clearLogs(): void {
    this.logs = []
  }
}

// Singleton instance
let loggerInstance: SecurityLogger | null = null

export function getSecurityLogger(): SecurityLogger {
  if (!loggerInstance) {
    loggerInstance = new SecurityLogger()
  }
  return loggerInstance
}
