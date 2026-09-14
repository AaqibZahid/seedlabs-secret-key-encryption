#!/usr/bin/env python3
"""
Task 6.3: Local Oracle Server (reimplements Docker known_iv binary)
Listens on localhost:3000, mimics the SEED Labs encryption oracle.
- Generates random key + IV
- Encrypts "Yes" with AES-128-CBC, prints ciphertext + IV
- Loops: predicts next IV, encrypts user input, prints result
"""
import socket
import os
import sys
import struct
import random

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

KEY_SIZE = 16
BLOCK_SIZE = 16
HOST = '127.0.0.1'
PORT = 3000

def aes_encrypt(key, iv, plaintext):
    """AES-128-CBC encrypt with PKCS7 padding"""
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded) + encryptor.finalize()
    return ct

def hexlify(data):
    return data.hex()

def unhexlify(hexstr):
    return bytes.fromhex(hexstr)

def main():
    # Generate random key and IV
    key = os.urandom(KEY_SIZE)
    iv = os.urandom(BLOCK_SIZE)
    
    # Encrypt the secret message "Yes"
    secret = b'Yes'
    ctext1 = aes_encrypt(key, iv, secret)
    
    # Seed random with last 4 bytes of IV (mimics known_iv.cpp: srand(*reinterpret_cast<unsigned *>(&iv[8])))
    seed_val = struct.unpack('<I', iv[8:12])[0]
    random.seed(seed_val)
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(1)
    
    print(f"Oracle server listening on {HOST}:{PORT}")
    print(f"Secret: {secret.decode()}")
    print(f"Key: {hexlify(key)}")
    print(f"IV:  {hexlify(iv)}")
    print(f"Ciphertext: {hexlify(ctext1)}")
    print("-" * 50)
    
    while True:
        try:
            conn, addr = server.accept()
            print(f"Connection from {addr}")
            
            # Send initial info
            intro = (
                f"Bob's secret message is either \"Yes\" or \"No\", without quotations.\r\n"
                f"Bob's ciphertex: {hexlify(ctext1)}\r\n"
                f"The IV used    : {hexlify(iv)}\r\n"
            )
            conn.sendall(intro.encode())
            
            current_iv = iv
            while True:
                # Generate next IV using random (mimics known_iv.cpp)
                rand_val = random.getrandbits(32)
                next_iv = bytearray(current_iv)
                # Modify first 8 bytes by adding rand_val (as uint64)
                val = struct.unpack('<Q', bytes(next_iv[:8]))[0]
                val = (val + rand_val) & 0xFFFFFFFFFFFFFFFF
                next_iv[:8] = struct.pack('<Q', val)
                next_iv = bytes(next_iv)
                
                # Send next IV and prompt
                prompt = f"\r\nNext IV        : {hexlify(next_iv)}\r\nYour plaintext : "
                conn.sendall(prompt.encode())
                
                # Receive user input
                data = b''
                while b'\n' not in data and b'\r' not in data:
                    chunk = conn.recv(1024)
                    if not chunk:
                        break
                    data += chunk
                
                user_input = data.decode().strip()
                if not user_input:
                    break
                
                try:
                    plaintext = unhexlify(user_input)
                    ctext2 = aes_encrypt(key, next_iv, plaintext)
                    response = f"Your ciphertext: {hexlify(ctext2)}\r\n"
                    conn.sendall(response.encode())
                except Exception as e:
                    conn.sendall(f"Invalid hex string: {e}\r\n".encode())
                
                current_iv = next_iv
            
            conn.close()
        except KeyboardInterrupt:
            print("\nServer stopped.")
            break
        except Exception as e:
            print(f"Error: {e}")
    
    server.close()

if __name__ == '__main__':
    main()
