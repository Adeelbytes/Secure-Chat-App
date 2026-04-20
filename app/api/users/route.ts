// Users API - Proxy to backend MongoDB

import { type NextRequest, NextResponse } from "next/server"
import { BACKEND_API_URL } from "@/lib/api-config"

export async function GET(request: NextRequest) {
  try {
    const token = request.headers.get("authorization")?.replace("Bearer ", "")
    
    if (!token) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 })
    }

    const { searchParams } = new URL(request.url)
    const username = searchParams.get("username")
    const userId = searchParams.get("userId")

    let backendUrl = `${BACKEND_API_URL}/api/users`
    if (userId) {
      backendUrl = `${BACKEND_API_URL}/api/users/${userId}`
    }

    const response = await fetch(backendUrl, {
      headers: {
        "Authorization": `Bearer ${token}`,
      },
    })

    const data = await response.json()

    if (!response.ok) {
      return NextResponse.json(data, { status: response.status })
    }

    return NextResponse.json(data)
  } catch (error) {
    console.error("[API] Users proxy error:", error)
    return NextResponse.json({ error: "Failed to fetch users" }, { status: 500 })
  }
}
