// User Registration API - Proxy to backend MongoDB

import { type NextRequest, NextResponse } from "next/server"
import { BACKEND_API_URL } from "@/lib/api-config"

export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    
    const { username, password, publicKey, signaturePublicKey } = body

    // Validation
    if (!username || !password || !publicKey || !signaturePublicKey) {
      return NextResponse.json({ error: "Missing required fields" }, { status: 400 })
    }

    if (typeof password !== "string" || password.length < 8) {
      return NextResponse.json({ error: "Password must be at least 8 characters" }, { status: 400 })
    }

    // Proxy to backend
    const response = await fetch(`${BACKEND_API_URL}/api/auth/register`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ username, password, publicKey, signaturePublicKey }),
    })

    const data = await response.json()

    if (!response.ok) {
      return NextResponse.json(data, { status: response.status })
    }

    console.log(`[API] User registered: ${username}`)

    return NextResponse.json(data)
  } catch (error) {
    console.error("[API] Registration proxy error:", error)
    return NextResponse.json({ error: "Registration failed" }, { status: 500 })
  }
}
