"use client"

import { useState, useEffect } from "react"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Radio, Zap, Eye, RefreshCw } from "lucide-react"
import { cn } from "@/lib/utils"

interface UserInfo {
  id: string
  username: string
  publicKey: string
  signaturePublicKey: string
}

interface UserListProps {
  currentUser: UserInfo
  selectedUser: UserInfo | null
  onSelectUser: (user: UserInfo) => void
  keyExchangeStatus: Map<string, "none" | "pending" | "complete">
  sessionToken: string | null
}

function getConversationId(userId1: string, userId2: string): string {
  return [userId1, userId2].sort().join(":")
}

export function UserList({ currentUser, selectedUser, onSelectUser, keyExchangeStatus, sessionToken }: UserListProps) {
  const [users, setUsers] = useState<UserInfo[]>([])
  const [isLoading, setIsLoading] = useState(true)

  const fetchUsers = async () => {
    setIsLoading(true)
    try {
      const response = await fetch("/api/users", {
        headers: sessionToken ? { Authorization: `Bearer ${sessionToken}` } : {},
      })
      const data = await response.json()
      setUsers(data.users.filter((u: UserInfo) => u.id !== currentUser.id))
    } catch (error) {
      console.error("Failed to fetch users:", error)
    } finally {
      setIsLoading(false)
    }
  }

  useEffect(() => {
    fetchUsers()
    const interval = setInterval(fetchUsers, 10000)
    return () => clearInterval(interval)
  }, [currentUser.id])

  const getStatusIndicator = (userId: string) => {
    const convId = getConversationId(currentUser.id, userId)
    const status = keyExchangeStatus.get(convId) || "none"

    switch (status) {
      case "complete":
        return (
          <span className="flex items-center gap-1 text-[9px] uppercase tracking-widest text-primary">
            <Eye className="w-3 h-3" />
            SECURE
          </span>
        )
      case "pending":
        return (
          <span className="flex items-center gap-1 text-[9px] uppercase tracking-widest text-accent">
            <Zap className="w-3 h-3 animate-pulse" />
            PENDING
          </span>
        )
      default:
        return (
          <span className="flex items-center gap-1 text-[9px] uppercase tracking-widest text-muted-foreground">
            <Radio className="w-3 h-3" />
            NO KEY
          </span>
        )
    }
  }

  return (
    <div className="w-full flex flex-col h-full">
      <div className="pb-3 flex items-center justify-between border-b border-primary/20 mb-3">
        <span className="text-[10px] uppercase tracking-widest text-muted-foreground">{users.length} ONLINE</span>
        <button onClick={fetchUsers} className="p-1 hover:bg-primary/10 transition-colors" disabled={isLoading}>
          <RefreshCw className={cn("h-3 w-3 text-primary", isLoading && "animate-spin")} />
        </button>
      </div>

      <ScrollArea className="flex-1">
        <div className="space-y-1">
          {users.length === 0 ? (
            <p className="text-[10px] text-muted-foreground text-center py-8 uppercase tracking-widest">
              NO NODES ONLINE
            </p>
          ) : (
            users.map((user) => (
              <button
                key={user.id}
                onClick={() => onSelectUser(user)}
                className={cn(
                  "w-full p-3 text-left transition-all duration-100 border-2",
                  selectedUser?.id === user.id
                    ? "border-primary bg-primary/10"
                    : "border-transparent hover:border-primary/30 hover:bg-primary/5",
                )}
              >
                <div className="flex items-center gap-3">
                  <div
                    className={cn(
                      "w-8 h-8 border-2 flex items-center justify-center text-sm font-bold",
                      selectedUser?.id === user.id
                        ? "border-primary text-primary bg-primary/20"
                        : "border-primary/30 text-primary/60",
                    )}
                  >
                    {user.username.charAt(0).toUpperCase()}
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm uppercase tracking-wider truncate text-foreground">{user.username}</p>
                    {getStatusIndicator(user.id)}
                  </div>
                </div>
              </button>
            ))
          )}
        </div>
      </ScrollArea>
    </div>
  )
}
