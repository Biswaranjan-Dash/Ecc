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

def get_server_public_key():
    """Retrieve the server's public key"""
    response = requests.get(f"{BACKEND_URL}/public-key")
    if response.status_code == 200:
        public_key_pem = response.json()["public_key"].encode()
        return serialization.load_pem_public_key(public_key_pem)
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

def send_encrypted_data(data: dict):
    """Send encrypted health data to the backend server"""
    try:
        # Get server's public key
        print("Retrieving server public key...")
        server_public_key = get_server_public_key()
        print("✓ Server public key retrieved")
        
        # Encrypt the data
        print(f"\nEncrypting data: {data}")
        encrypted_payload = encrypt_data(data, server_public_key)
        print("✓ Data encrypted successfully")
        
        # Send encrypted data to the server
        print("\nSending encrypted data to server...")
        response = requests.post(
            f"{BACKEND_URL}/ecc-decode",
            json=encrypted_payload,
            headers={"Content-Type": "application/json"}
        )
        
        # Print response
        print(f"\nServer Response (Status {response.status_code}):")
        print(json.dumps(response.json(), indent=2))
        
        return response.json()
    
    except requests.exceptions.ConnectionError:
        print("❌ Error: Could not connect to the server.")
        print("   Make sure the backend server is running at http://localhost:8000")
    except Exception as e:
        print(f"❌ Error: {str(e)}")

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
    
    transmission_count = 0
    
    try:
        while True:
            transmission_count += 1
            
            # Generate random health data
            health_data = generate_random_health_data()
            
            print(f"\n[Transmission #{transmission_count}]")
            print("-" * 60)
            
            # Send encrypted data
            send_encrypted_data(health_data)
            
            # Wait before next transmission
            time.sleep(2)  # 2 second delay between transmissions
            
    except KeyboardInterrupt:
        print("\n\n" + "="*60)
        print(f"Stopped! Total transmissions: {transmission_count}")
        print("="*60)