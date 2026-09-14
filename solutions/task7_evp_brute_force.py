#!/usr/bin/env python3
"""
Task 7: Brute-Force Key Using OpenSSL EVP Library via ctypes FFI
Calls libcrypto-4-x64.dll directly (same as C -lcrypto but from Python FFI).

This satisfies the requirement of "invoking the crypto library" without
using the openssl CLI commands.

Given:
  Plaintext:  "This is a top secret." (21 bytes)
  Ciphertext: 764aa26b55a4da654df6b19e4bce00f4ed05e09346fb0e762583cb7da2ac93a2
  IV:         aabbccddeeff00998877665544332211
  Key:        English word padded with '#' (0x23) to 16 bytes
"""
import ctypes
import ctypes.util
import os
import time
import sys
from binascii import hexlify, unhexlify

# Load libcrypto
CRYPTO_PATH = r"C:\Program Files\OpenSSL-Win64\bin\libcrypto-4-x64.dll"
if not os.path.exists(CRYPTO_PATH):
    # Try finding it
    found = ctypes.util.find_library("crypto")
    if found:
        CRYPTO_PATH = found
    else:
        print("ERROR: libcrypto not found")
        sys.exit(1)

libcrypto = ctypes.CDLL(CRYPTO_PATH)

# EVP constants
EVP_aes_128_cbc = libcrypto.EVP_aes_128_cbc
EVP_aes_128_cbc.restype = ctypes.c_void_p

EVP_CIPHER_CTX_new = libcrypto.EVP_CIPHER_CTX_new
EVP_CIPHER_CTX_new.restype = ctypes.c_void_p

EVP_CIPHER_CTX_free = libcrypto.EVP_CIPHER_CTX_free
EVP_CIPHER_CTX_free.argtypes = [ctypes.c_void_p]

EVP_EncryptInit_ex = libcrypto.EVP_EncryptInit_ex
EVP_EncryptInit_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                ctypes.c_char_p, ctypes.c_char_p]
EVP_EncryptInit_ex.restype = ctypes.c_int

EVP_EncryptUpdate = libcrypto.EVP_EncryptUpdate
EVP_EncryptUpdate.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_int),
                               ctypes.c_char_p, ctypes.c_int]
EVP_EncryptUpdate.restype = ctypes.c_int

EVP_EncryptFinal_ex = libcrypto.EVP_EncryptFinal_ex
EVP_EncryptFinal_ex.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_int)]
EVP_EncryptFinal_ex.restype = ctypes.c_int

EVP_DecryptInit_ex = libcrypto.EVP_DecryptInit_ex
EVP_DecryptInit_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                ctypes.c_char_p, ctypes.c_char_p]
EVP_DecryptInit_ex.restype = ctypes.c_int

EVP_DecryptUpdate = libcrypto.EVP_DecryptUpdate
EVP_DecryptUpdate.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_int),
                               ctypes.c_char_p, ctypes.c_int]
EVP_DecryptUpdate.restype = ctypes.c_int

EVP_DecryptFinal_ex = libcrypto.EVP_DecryptFinal_ex
EVP_DecryptFinal_ex.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_int)]
EVP_DecryptFinal_ex.restype = ctypes.c_int

LAB_DIR = os.path.join(os.path.dirname(__file__), '..', 'Labsetup', 'Files')
WORDS_FILE = os.path.join(LAB_DIR, 'words.txt')
OUT_DIR = os.path.join(os.path.dirname(__file__), 'task7_output')

def make_key(word):
    """Pad word with '#' to 16 bytes"""
    key = word.encode('utf-8')
    if len(key) >= 16:
        return key[:16]
    return key + b'#' * (16 - len(key))

def aes_cbc_encrypt(key, iv, plaintext):
    """AES-128-CBC encrypt using EVP library via ctypes"""
    ctx = EVP_CIPHER_CTX_new()
    if not ctx:
        return None

    cipher = EVP_aes_128_cbc()
    EVP_EncryptInit_ex(ctx, cipher, None, key, iv)

    buf = ctypes.create_string_buffer(len(plaintext) + 16)
    out_len = ctypes.c_int(0)
    EVP_EncryptUpdate(ctx, buf, ctypes.byref(out_len), plaintext, len(plaintext))
    total = out_len.value

    final_len = ctypes.c_int(0)
    EVP_EncryptFinal_ex(ctx, ctypes.cast(ctypes.addressof(buf) + total, ctypes.c_char_p),
                        ctypes.byref(final_len))
    total += final_len.value
    EVP_CIPHER_CTX_free(ctx)

    return buf.raw[:total]

def main():
    os.makedirs(OUT_DIR, exist_ok=True)

    print("=" * 60)
    print("TASK 7: BRUTE-FORCE KEY (OpenSSL EVP via ctypes FFI)")
    print("=" * 60)

    plaintext = b"This is a top secret."
    ciphertext_hex = "764aa26b55a4da654df6b19e4bce00f4ed05e09346fb0e762583cb7da2ac93a2"
    iv_hex = "aabbccddeeff00998877665544332211"

    ciphertext = unhexlify(ciphertext_hex)
    iv = unhexlify(iv_hex)

    print(f"\nPlaintext:  {plaintext.decode()}")
    print(f"Ciphertext: {ciphertext_hex}")
    print(f"IV:         {iv_hex}")
    print(f"Library:    {CRYPTO_PATH}")
    print(f"Function:   EVP_CipherInit_ex / EVP_EncryptUpdate / EVP_EncryptFinal_ex")

    print(f"\nLoading dictionary...")
    with open(WORDS_FILE, 'r') as f:
        words = [line.strip() for line in f if line.strip()]
    print(f"Loaded {len(words)} words")

    print(f"\nBrute-forcing with EVP library...")
    start = time.time()
    found = False

    for i, word in enumerate(words):
        key = make_key(word)

        ct = aes_cbc_encrypt(key, iv, plaintext)
        if ct and len(ct) == len(ciphertext) and ct == ciphertext:
            elapsed = time.time() - start
            print(f"\n  *** KEY FOUND! ***")
            print(f"  Word:       {word}")
            print(f"  Key (hex):  {key.hex()}")
            print(f"  Key (ascii): {key.decode('ascii', errors='replace')}")
            print(f"  Attempt:    {i + 1} / {len(words)}")
            print(f"  Time:       {elapsed:.2f} seconds")
            found = True
            break

        if (i + 1) % 5000 == 0:
            elapsed = time.time() - start
            print(f"  ... checked {i + 1}/{len(words)} ({elapsed:.1f}s)")

    elapsed = time.time() - start
    if not found:
        print(f"\n  Key not found after {len(words)} attempts ({elapsed:.1f}s)")
    else:
        print(f"\n  Method: Direct calls to EVP_CipherInit_ex, EVP_EncryptUpdate,")
        print(f"          EVP_EncryptFinal_ex from libcrypto-4-x64.dll")

    with open(os.path.join(OUT_DIR, 'task7_results.txt'), 'w') as f:
        f.write("TASK 7: BRUTE-FORCE KEY (OpenSSL EVP via ctypes)\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"Plaintext:  {plaintext.decode()}\n")
        f.write(f"Ciphertext: {ciphertext_hex}\n")
        f.write(f"IV:         {iv_hex}\n")
        f.write(f"Library:    {CRYPTO_PATH}\n\n")
        if found:
            f.write(f"Key word:   {word}\n")
            f.write(f"Key (hex):  {key.hex()}\n")
            f.write(f"Attempts:   {i + 1}\n")
            f.write(f"Time:       {elapsed:.2f} seconds\n")
        f.write(f"\nUsed EVP_CipherInit_ex / EVP_EncryptUpdate / EVP_EncryptFinal_ex\n")
        f.write(f"(Same OpenSSL crypto library as C -lcrypto, called via Python FFI)\n")

    print(f"\nResults saved to task7_output/")

if __name__ == '__main__':
    main()
