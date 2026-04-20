// User Login API - Proxy to backend MongoDB

import { type NextRequest, NextResponse } from "next/server"
import { BACKEND_API_URL } from "@/lib/api-config"

export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    
    const { username, password } = body

    // Validation
    if (!username || !password) {
      return NextResponse.json({ error: "Missing username or password" }, { status: 400 })
    }

    // Proxy to backend
    const response = await fetch(`${BACKEND_API_URL}/api/auth/login`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ username, password }),
    })

    const data = await response.json()

    if (!response.ok) {
      return NextResponse.json(data, { status: response.status })
    }

    console.log(`[API] User logged in: ${username}`)

    return NextResponse.json(data)
  } catch (error) {
    console.error("[API] Login proxy error:", error)
    return NextResponse.json({ error: "Login failed" }, { status: 500 })
  }
}
