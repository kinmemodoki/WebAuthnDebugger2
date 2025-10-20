import { NextRequest, NextResponse } from 'next/server';

export interface StoredCredential {
  username: string;
  id: string;
  rawId: string;
  pubKey: string;
  alg: number;
}

// In-memory storage (resets when server restarts)
let credentials: StoredCredential[] = [];

// GET - Retrieve all credentials
export async function GET() {
  return NextResponse.json(credentials);
}

// POST - Save a new credential
export async function POST(request: NextRequest) {
  try {
    const credential: StoredCredential = await request.json();

    // Check if credential already exists
    const exists = credentials.some(c => c.id === credential.id);

    if (!exists) {
      credentials.push(credential);
    }

    return NextResponse.json({ success: true, credential });
  } catch (error) {
    return NextResponse.json(
      { success: false, error: 'Failed to save credential' },
      { status: 500 }
    );
  }
}

// DELETE - Clear all credentials
export async function DELETE() {
  credentials = [];
  return NextResponse.json({ success: true });
}
