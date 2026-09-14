#!/usr/bin/env python3
"""
Task 7: Brute-Force Secret Key from Dictionary
Uses Python's cryptography library (EVP equivalent) to brute-force AES-128-CBC key.

Given:
  Plaintext:  "This is a top secret." (21 bytes)
  Ciphertext: 764aa26b55a4da654df6b19e4bce00f4ed05e09346fb0e762583cb7da2ac93a2 (hex)
  IV:         aabbccddeeff00998877665544332211 (hex)
  Key:        English word padded with '#' (0x23) to 16 bytes

Must use crypto library, not openssl CLI.
"""
import os
import time
from binascii import hexlify, unhexlify

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

LAB_DIR = os.path.join(os.path.dirname(__file__), '..', 'Labsetup', 'Files')
WORDS_FILE = os.path.join(LAB_DIR, 'words.txt')
OUT_DIR = os.path.join(os.path.dirname(__file__), 'task7_output')

def make_key(word):
    """Pad word with # (0x23) to 16 bytes"""
    key_bytes = word.encode('utf-8')
    if len(key_bytes) >= 16:
        return key_bytes[:16]
    return key_bytes + b'#' * (16 - len(key_bytes))

def aes_cbc_encrypt(key, iv, plaintext):
    """AES-128-CBC encrypt with PKCS7 padding"""
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    enc = cipher.encryptor()
    return enc.update(padded) + enc.finalize()

def aes_cbc_decrypt(key, iv, ciphertext):
    """AES-128-CBC decrypt"""
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    dec = cipher.decryptor()
    return dec.update(ciphertext) + dec.finalize()

def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    
    print("=" * 60)
    print("TASK 7: BRUTE-FORCE SECRET KEY FROM DICTIONARY")
    print("=" * 60)
    
    # Given values
    plaintext = b"This is a top secret."
    ciphertext_hex = "764aa26b55a4da654df6b19e4bce00f4ed05e09346fb0e762583cb7da2ac93a2"
    iv_hex = "aabbccddeeff00998877665544332211"
    
    ciphertext = unhexlify(ciphertext_hex)
    iv = unhexlify(iv_hex)
    
    print(f"\nGiven:")
    print(f"  Plaintext:  {plaintext.decode()}")
    print(f"  Ciphertext: {ciphertext_hex}")
    print(f"  IV:         {iv_hex}")
    print(f"  Key format: English word + '#' padding to 16 bytes")
    
    # Load dictionary
    print(f"\nLoading dictionary from {WORDS_FILE}...")
    with open(WORDS_FILE, 'r') as f:
        words = [line.strip() for line in f if line.strip()]
    print(f"  Loaded {len(words)} words")
    
    # Show example key derivation
    print(f"\nExample key derivations:")
    for w in ['security', 'hello', 'test', 'password']:
        k = make_key(w)
        print(f"  '{w}' -> {k.hex()} ({k})")
    
    # Brute-force
    print(f"\nBrute-forcing...")
    start = time.time()
    found = False
    
    for i, word in enumerate(words):
        key = make_key(word)
        
        # Try decrypting and check if result matches expected plaintext
        try:
            decrypted_padded = aes_cbc_decrypt(key, iv, ciphertext)
            # Remove PKCS7 padding
            unpadder = padding.PKCS7(128).unpadder()
            decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
            
            if decrypted == plaintext:
                elapsed = time.time() - start
                print(f"\n  *** KEY FOUND! ***")
                print(f"  Word: {word}")
                print(f"  Key (hex): {key.hex()}")
                print(f"  Key (ascii): {key.decode('ascii', errors='replace')}")
                print(f"  Attempt: {i + 1} / {len(words)}")
                print(f"  Time: {elapsed:.2f} seconds")
                found = True
                break
        except Exception:
            pass  # Invalid padding, skip
        
        if (i + 1) % 5000 == 0:
            elapsed = time.time() - start
            print(f"  ... checked {i + 1}/{len(words)} words ({elapsed:.1f}s)")
    
    elapsed = time.time() - start
    
    if not found:
        print(f"\n  Key not found after {len(words)} attempts ({elapsed:.1f}s)")
    else:
        # Verify
        key = make_key(word)
        print(f"\n  Verification:")
        print(f"  Encrypting '{plaintext.decode()}' with key '{word}'...")
        ct = aes_cbc_encrypt(key, iv, plaintext)
        print(f"  Result:   {ct.hex()}")
        print(f"  Expected: {ciphertext_hex}")
        print(f"  Match: {ct.hex() == ciphertext_hex}")
    
    # Save results
    with open(os.path.join(OUT_DIR, 'task7_results.txt'), 'w') as f:
        f.write("TASK 7: BRUTE-FORCE SECRET KEY FROM DICTIONARY\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"Plaintext:  {plaintext.decode()}\n")
        f.write(f"Ciphertext: {ciphertext_hex}\n")
        f.write(f"IV:         {iv_hex}\n\n")
        f.write(f"Dictionary: {WORDS_FILE} ({len(words)} words)\n")
        if found:
            f.write(f"Key word:   {word}\n")
            f.write(f"Key (hex):  {key.hex()}\n")
            f.write(f"Attempts:   {i + 1}\n")
            f.write(f"Time:       {elapsed:.2f} seconds\n")
        else:
            f.write("Key not found in dictionary\n")
    
    print(f"\nResults saved to task7_output/")

if __name__ == '__main__':
    main()
