// Encrypted File Storage API - Proxy to backend MongoDB

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
    const response = await fetch(`${BACKEND_API_URL}/api/files`, {
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
    console.error("[API] File upload proxy error:", error)
    return NextResponse.json({ error: "Failed to upload file" }, { status: 500 })
  }
}

export async function GET(request: NextRequest) {
  try {
    const token = request.headers.get("authorization")?.replace("Bearer ", "")
    
    if (!token) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 })
    }

    const { searchParams } = new URL(request.url)
    const fileId = searchParams.get("id") || searchParams.get("fileId")

    if (!fileId) {
      return NextResponse.json({ error: "File ID required" }, { status: 400 })
    }

    // Proxy to backend
    const response = await fetch(`${BACKEND_API_URL}/api/files/${fileId}`, {
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
    console.error("[API] File download proxy error:", error)
    return NextResponse.json({ error: "Failed to download file" }, { status: 500 })
  }
}
