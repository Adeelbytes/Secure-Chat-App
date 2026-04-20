// Key Exchange API - Proxy to backend MongoDB

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
    const response = await fetch(`${BACKEND_API_URL}/api/key-exchange`, {
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
    console.error("[API] Key exchange proxy error:", error)
    return NextResponse.json({ error: "Key exchange failed" }, { status: 500 })
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

    let backendUrl = `${BACKEND_API_URL}/api/key-exchange`
    if (partnerId) {
      backendUrl += `?partnerId=${partnerId}`
    }

    // Proxy to backend
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
    console.error("[API] Key exchange retrieval proxy error:", error)
    return NextResponse.json({ error: "Failed to retrieve key exchanges" }, { status: 500 })
  }
}
