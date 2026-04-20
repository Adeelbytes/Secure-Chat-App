// Encrypted Messages API - Proxy to backend MongoDB

import { type NextRequest, NextResponse } from "next/server"
import { BACKEND_API_URL } from "@/lib/api-config"

export async function POST(request: NextRequest) {
  try {
    const token = request.headers.get("authorization")?.replace("Bearer ", "")
    
    if (!token) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 })
    }

    const body = await request.json()

    // Proxy to backend
    const response = await fetch(`${BACKEND_API_URL}/api/messages`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${token}`,
      },
      body: JSON.stringify(body),
    })

    const data = await response.json()

    if (!response.ok) {
      return NextResponse.json(data, { status: response.status })
    }

    return NextResponse.json(data)
  } catch (error) {
    console.error("[API] Message proxy error:", error)
    return NextResponse.json({ error: "Failed to send message" }, { status: 500 })
  }
}

export async function GET(request: NextRequest) {
  try {
    const token = request.headers.get("authorization")?.replace("Bearer ", "")
    
    if (!token) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 })
    }

    const { searchParams } = new URL(request.url)
    const partnerId = searchParams.get("partnerId")
    const since = searchParams.get("since")

    if (!partnerId) {
      return NextResponse.json({ error: "Partner ID required" }, { status: 400 })
    }

    let backendUrl = `${BACKEND_API_URL}/api/messages?partnerId=${partnerId}`
    if (since) {
      backendUrl += `&since=${since}`
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
    console.error("[API] Message retrieval proxy error:", error)
    return NextResponse.json({ error: "Failed to retrieve messages" }, { status: 500 })
  }
}
