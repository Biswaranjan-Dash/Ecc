from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import json
import base64
import os
import asyncio
from typing import List
from datetime import datetime

app = FastAPI()

# Enable CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Store active WebSocket connections
active_connections: List[WebSocket] = []

# Generate ECC key pair for the server
private_key = ec.generate_private_key(ec.SECP256R1())
public_key = private_key.public_key()

# Serialize public key to share with clients
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

class EncryptedData(BaseModel):
    encrypted_data: str
    ephemeral_public_key: str
    iv: str

@app.get("/")
def read_root():
    return {"message": "Hello, FastAPI is running!"}

@app.get("/ping")
def ping():
    return {"status": "ok"}

@app.get("/public-key")
def get_public_key():
    """Endpoint to retrieve server's public key"""
    return {"public_key": public_key_pem.decode()}

async def broadcast_to_websockets(data: dict):
    """Broadcast data to all connected WebSocket clients"""
    if active_connections:
        disconnected = []
        for connection in active_connections:
            try:
                await connection.send_json(data)
            except Exception:
                disconnected.append(connection)
        
        # Remove disconnected clients
        for connection in disconnected:
            active_connections.remove(connection)

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for streaming decrypted data"""
    await websocket.accept()
    active_connections.append(websocket)
    
    try:
        # Send initial connection message
        await websocket.send_json({
            "type": "connection",
            "status": "connected",
            "message": "WebSocket connection established",
            "timestamp": datetime.now().isoformat()
        })
        
        # Keep connection alive
        while True:
            # Wait for any message from client (ping/pong)
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=1.0)
            except asyncio.TimeoutError:
                # Send periodic ping to keep connection alive
                await websocket.send_json({"type": "ping"})
            except WebSocketDisconnect:
                break
                
    except WebSocketDisconnect:
        pass
    finally:
        if websocket in active_connections:
            active_connections.remove(websocket)

@app.post("/ecc-decode")
async def ecc_decode(data: EncryptedData):
    """Decrypt data encrypted with ECC and broadcast to WebSocket clients"""
    try:
        print(data)
        # Decode the ephemeral public key from the client
        ephemeral_public_key_bytes = base64.b64decode(data.ephemeral_public_key)
        ephemeral_public_key = serialization.load_pem_public_key(ephemeral_public_key_bytes)
        
        # Perform ECDH to derive shared secret
        shared_secret = private_key.exchange(ec.ECDH(), ephemeral_public_key)
        
        # Derive AES key from shared secret using HKDF
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
        ).derive(shared_secret)
        
        # Decode encrypted data and IV
        encrypted_bytes = base64.b64decode(data.encrypted_data)
        iv = base64.b64decode(data.iv)
        
        # Decrypt the data
        cipher = Cipher(algorithms.AES(derived_key), modes.CFB(iv))
        decryptor = cipher.decryptor()
        decrypted_bytes = decryptor.update(encrypted_bytes) + decryptor.finalize()
        
        # Parse the JSON data
        decrypted_data = json.loads(decrypted_bytes.decode())
        
        # Prepare response with timestamp
        response_data = {
            "type": "health_data",
            "status": "success",
            "data": decrypted_data,
            "timestamp": datetime.now().isoformat(),
            "message": "Data successfully decrypted"
        }
        
        # Broadcast to all WebSocket clients
        await broadcast_to_websockets(response_data)
        
        return {
            "status": "success",
            "decrypted_data": decrypted_data,
            "message": "Data successfully decrypted and broadcasted"
        }
    except Exception as e:
        error_response = {
            "type": "error",
            "status": "error",
            "message": f"Decryption failed: {str(e)}",
            "timestamp": datetime.now().isoformat()
        }
        await broadcast_to_websockets(error_response)
        return error_response

@app.get("/ws/status")
def websocket_status():
    """Get the status of WebSocket connections"""
    return {
        "active_connections": len(active_connections),
        "status": "WebSocket server running"
    }