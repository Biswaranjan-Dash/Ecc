#!/usr/bin/env python3
"""Python client simulating ESP32 encryption (AES-GCM with hex encoding)"""

import requests
import json
import os
import random
import time
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Backend server URL
BACKEND_URL = "http://localhost:8000"

# Cache the server's public key
_cached_server_public_key = None
_cached_server_public_key_bytes = None

def get_server_public_key(force_refresh=False):
    """Retrieve the server's public key (cached after first retrieval)"""
    global _cached_server_public_key, _cached_server_public_key_bytes
    
    if _cached_server_public_key is not None and not force_refresh:
        return _cached_server_public_key, _cached_server_public_key_bytes
    
    response = requests.get(f"{BACKEND_URL}/public-key")
    if response.status_code == 200:
        data = response.json()
        # Get hex format for ESP32-style encryption
        public_key_hex = data["public_key_hex"]
        public_key_bytes = bytes.fromhex(public_key_hex)
        
        # Load as EC public key
        _cached_server_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), 
            public_key_bytes
        )
        _cached_server_public_key_bytes = public_key_bytes
        
        return _cached_server_public_key, _cached_server_public_key_bytes
    else:
        raise Exception("Failed to retrieve server public key")

def derive_aes_key_sha256(shared_secret: bytes) -> bytes:
    """Derive AES key using SHA-256 (ESP32 method)"""
    digest = hashes.Hash(hashes.SHA256())
    digest.update(shared_secret)
    return digest.finalize()

def encrypt_data_esp32(data: dict, server_public_key):
    """Encrypt data using ESP32 method (AES-GCM with SHA-256 key derivation)"""
    # Generate ephemeral key pair
    ephemeral_private_key = ec.generate_private_key(ec.SECP256R1())
    ephemeral_public_key = ephemeral_private_key.public_key()
    
    # Perform ECDH to derive shared secret
    shared_secret = ephemeral_private_key.exchange(ec.ECDH(), server_public_key)
    
    # Derive AES key using SHA-256 (ESP32 method)
    aes_key = derive_aes_key_sha256(shared_secret)
    
    # Convert data to JSON bytes
    data_bytes = json.dumps(data).encode('utf-8')
    
    # Generate random IV (12 bytes for GCM)
    iv = os.urandom(12)
    
    # Encrypt using AES-GCM
    aesgcm = AESGCM(aes_key)
    # GCM returns ciphertext with tag appended
    ciphertext_with_tag = aesgcm.encrypt(iv, data_bytes, None)
    
    # Split ciphertext and tag (last 16 bytes is tag)
    ciphertext = ciphertext_with_tag[:-16]
    tag = ciphertext_with_tag[-16:]
    
    # Export ephemeral public key as uncompressed point (0x04 || X || Y)
    ephemeral_public_key_bytes = ephemeral_public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    
    # Return in ESP32 format (all hex-encoded)
    return {
        "pubkey": ephemeral_public_key_bytes.hex().upper(),
        "iv": iv.hex().upper(),
        "cipher": ciphertext.hex().upper(),
        "tag": tag.hex().upper()
    }

def send_encrypted_data_esp32(data: dict, server_public_key):
    """Send encrypted health data to the backend server (ESP32 format)"""
    try:
        # Encrypt the data
        print(f"Encrypting data (ESP32 method): {data}")
        encrypted_payload = encrypt_data_esp32(data, server_public_key)
        print("✓ Data encrypted with AES-GCM")
        
        # Send encrypted data to the server
        response = requests.post(
            f"{BACKEND_URL}/receive-encrypted",
            json=encrypted_payload,
            headers={"Content-Type": "application/json"}
        )
        
        # Print response
        result = response.json()
        print(f"Server Response: {result['status']}")
        
        return result
    
    except requests.exceptions.ConnectionError:
        print("❌ Error: Could not connect to the server.")
        print("   Make sure the backend server is running at http://localhost:8000")
        return None
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        import traceback
        traceback.print_exc()
        return None

def generate_random_health_data():
    """Generate random health monitoring data (ESP32 format)"""
    return {
        "heart rate": random.randint(60, 100),  # heart rate
        "spo2": random.randint(95, 100)  # oxygen saturation
    }

if __name__ == "__main__":
    print("="*60)
    print("ESP32 Simulator - AES-GCM Encrypted Health Data Client")
    print("="*60)
    print("\nPress Ctrl+C to stop\n")
    
    # Retrieve server public key once at startup
    print("Retrieving server public key...")
    try:
        server_public_key, server_public_key_bytes = get_server_public_key()
        print(f"✓ Server public key retrieved (hex): {server_public_key_bytes.hex().upper()[:32]}...")
        print("✓ Key cached for reuse\n")
    except Exception as e:
        print(f"❌ Failed to get server public key: {e}")
        exit(1)
    
    transmission_count = 0
    
    try:
        while True:
            transmission_count += 1
            
            # Generate random health data
            health_data = generate_random_health_data()
            
            print(f"\n[Transmission #{transmission_count}] {health_data}")
            print("-" * 60)
            
            # Send encrypted data (reusing cached public key)
            send_encrypted_data_esp32(health_data, server_public_key)
            
            # Wait before next transmission
            time.sleep(2)  # 2 second delay between transmissions
            
    except KeyboardInterrupt:
        print("\n\n" + "="*60)
        print(f"Stopped! Total transmissions: {transmission_count}")
        print("="*60)
