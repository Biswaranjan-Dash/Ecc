from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import json
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

# Serialize public key as uncompressed point (0x04 || X || Y) for ESP32
public_key_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.X962,
    format=serialization.PublicFormat.UncompressedPoint
)

# Also keep PEM format for Python clients
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

class EncryptedDataESP32(BaseModel):
    """ESP32 format: hex-encoded pubkey, iv, cipher, tag"""
    pubkey: str  # hex: 04||X||Y (65 bytes = 130 hex chars)
    iv: str      # hex: 12 bytes = 24 hex chars
    cipher: str  # hex: variable length
    tag: str     # hex: 16 bytes = 32 hex chars

class EncryptedData(BaseModel):
    """Python client format: base64 PEM"""
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
    """Endpoint to retrieve server's public key in both formats"""
    return {
        "public_key": public_key_pem.decode(),  # PEM for Python clients
        "public_key_hex": public_key_bytes.hex().upper()  # Hex for ESP32
    }

def hex_to_bytes(hex_str: str) -> bytes:
    """Convert hex string to bytes"""
    return bytes.fromhex(hex_str)

def derive_aes_key_sha256(shared_secret: bytes) -> bytes:
    """Derive AES key using SHA-256 (ESP32 method)"""
    digest = hashes.Hash(hashes.SHA256())
    digest.update(shared_secret)
    return digest.finalize()

@app.post("/receive-encrypted")
async def receive_encrypted_esp32(data: EncryptedDataESP32):
    """Decrypt data from ESP32 (AES-GCM, hex-encoded)"""
    try:
        # Decode hex strings to bytes
        client_pubkey_bytes = hex_to_bytes(data.pubkey)
        iv_bytes = hex_to_bytes(data.iv)
        cipher_bytes = hex_to_bytes(data.cipher)
        tag_bytes = hex_to_bytes(data.tag)
        
        # Validate public key format (must be 65 bytes: 0x04 || X || Y)
        if len(client_pubkey_bytes) != 65 or client_pubkey_bytes[0] != 0x04:
            raise ValueError("Invalid client public key format")
        
        # Load client's ephemeral public key
        client_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), 
            client_pubkey_bytes
        )
        
        # Perform ECDH to derive shared secret
        shared_secret = private_key.exchange(ec.ECDH(), client_public_key)
        
        # Derive AES key using SHA-256 (matching ESP32)
        aes_key = derive_aes_key_sha256(shared_secret)
        
        # Decrypt using AES-GCM
        aesgcm = AESGCM(aes_key)
        # Combine cipher and tag for decryption
        ciphertext_with_tag = cipher_bytes + tag_bytes
        decrypted_bytes = aesgcm.decrypt(iv_bytes, ciphertext_with_tag, None)
        
        # Parse the JSON data
        decrypted_data = json.loads(decrypted_bytes.decode('utf-8'))
        
        # Prepare response with timestamp
        response_data = {
            "type": "health_data",
            "status": "success",
            "data": decrypted_data,
            "timestamp": datetime.now().isoformat(),
            "message": "Data successfully decrypted (ESP32)"
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
    """Decrypt data encrypted with ECC (Python client - legacy CFB mode)"""
    try:
        # Import here to avoid issues if not needed
        import base64
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        
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