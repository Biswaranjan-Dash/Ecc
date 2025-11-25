#!/usr/bin/env python3
"""Client to send encrypted health data using ECC to the backend server"""

import requests
import json
import base64
import os
import random
import time
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Backend server URL
BACKEND_URL = "http://localhost:8000"

# Cache the server's public key
_cached_server_public_key = None

def get_server_public_key(force_refresh=False):
    """Retrieve the server's public key (cached after first retrieval)"""
    global _cached_server_public_key
    
    if _cached_server_public_key is not None and not force_refresh:
        return _cached_server_public_key
    
    response = requests.get(f"{BACKEND_URL}/public-key")
    if response.status_code == 200:
        public_key_pem = response.json()["public_key"].encode()
        _cached_server_public_key = serialization.load_pem_public_key(public_key_pem)
        return _cached_server_public_key
    else:
        raise Exception("Failed to retrieve server public key")

def encrypt_data(data: dict, server_public_key):
    """Encrypt data using ECC (ECIES scheme)"""
    # Generate ephemeral key pair
    ephemeral_private_key = ec.generate_private_key(ec.SECP256R1())
    ephemeral_public_key = ephemeral_private_key.public_key()
    
    # Perform ECDH to derive shared secret
    shared_secret = ephemeral_private_key.exchange(ec.ECDH(), server_public_key)
    
    # Derive AES key from shared secret using HKDF
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
    ).derive(shared_secret)
    
    # Convert data to JSON bytes
    data_bytes = json.dumps(data).encode()
    
    # Generate random IV
    iv = os.urandom(16)
    
    # Encrypt the data using AES
    cipher = Cipher(algorithms.AES(derived_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    encrypted_bytes = encryptor.update(data_bytes) + encryptor.finalize()
    
    # Serialize ephemeral public key
    ephemeral_public_key_pem = ephemeral_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Return encrypted data components
    return {
        "encrypted_data": base64.b64encode(encrypted_bytes).decode(),
        "ephemeral_public_key": base64.b64encode(ephemeral_public_key_pem).decode(),
        "iv": base64.b64encode(iv).decode()
    }

def send_encrypted_data(data: dict, server_public_key):
    """Send encrypted health data to the backend server"""
    try:
        # Encrypt the data
        print(f"Encrypting data: {data}")
        encrypted_payload = encrypt_data(data, server_public_key)
        print("✓ Data encrypted")
        
        # Send encrypted data to the server
        response = requests.post(
            f"{BACKEND_URL}/ecc-decode",
            json=encrypted_payload,
            headers={"Content-Type": "application/json"}
        )
        
        # Print response
        print(f"Server Response: {response.json()['status']}")
        
        return response.json()
    
    except requests.exceptions.ConnectionError:
        print("❌ Error: Could not connect to the server.")
        print("   Make sure the backend server is running at http://localhost:8000")
        return None
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        return None

def generate_random_health_data():
    """Generate random health monitoring data"""
    return {
        "heart rate": random.randint(60, 100),
        "spo2": random.randint(95, 100)
    }

if __name__ == "__main__":
    print("="*60)
    print("ECC Encrypted Health Data Client - Continuous Mode")
    print("="*60)
    print("\nPress Ctrl+C to stop\n")
    
    # Retrieve server public key once at startup
    print("Retrieving server public key...")
    try:
        server_public_key = get_server_public_key()
        print("✓ Server public key retrieved and cached\n")
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
            send_encrypted_data(health_data, server_public_key)
            
            # Wait before next transmission
            time.sleep(1)  # 1 second delay between transmissions
            
    except KeyboardInterrupt:
        print("\n\n" + "="*60)
        print(f"Stopped! Total transmissions: {transmission_count}")
        print("="*60)