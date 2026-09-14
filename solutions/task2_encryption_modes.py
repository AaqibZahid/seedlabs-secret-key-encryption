#!/usr/bin/env python3
"""
Task 2 & 3: Encryption with Different Ciphers and Modes
Encrypts pic_original.bmp with AES-128-ECB, AES-128-CBC, DES-ECB, DES-CBC
and compares ECB vs CBC visual patterns.
"""
import subprocess
import os
import sys

OPENSSL = r"C:\Program Files\OpenSSL-Win64\bin\openssl.exe"
LAB_DIR = os.path.join(os.path.dirname(__file__), '..', 'Labsetup', 'Files')
OUT_DIR = os.path.join(os.path.dirname(__file__), 'task2_output')

KEY_HEX = "00112233445566778899aabbccddeeff"  # 128-bit key
IV_HEX = "010203040506070809000a0b0c0d0e0f"  # 128-bit IV

def run_openssl(args, description):
    cmd = [OPENSSL] + args
    print(f"\n--- {description} ---")
    print(f"Command: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"STDERR: {result.stderr}")
    else:
        print("Success!")
    return result.returncode == 0

def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    
    original = os.path.join(LAB_DIR, 'pic_original.bmp')
    if not os.path.exists(original):
        print(f"Error: {original} not found")
        sys.exit(1)
    
    print("=" * 60)
    print("TASK 2: ENCRYPTION WITH DIFFERENT CIPHERS AND MODES")
    print("=" * 60)
    print(f"Original: {original}")
    print(f"Key (hex): {KEY_HEX}")
    print(f"IV (hex):  {IV_HEX}")
    
    # Task 2.1: AES-128-ECB (with PKCS padding)
    out_ecb = os.path.join(OUT_DIR, 'pic_aes128_ecb.bin')
    run_openssl([
        'enc', '-aes-128-ecb',
        '-in', original,
        '-out', out_ecb,
        '-K', KEY_HEX
    ], "AES-128-ECB Encryption")
    
    # Task 2.2: AES-128-CBC (with PKCS padding)
    out_cbc = os.path.join(OUT_DIR, 'pic_aes128_cbc.bin')
    run_openssl([
        'enc', '-aes-128-cbc',
        '-in', original,
        '-out', out_cbc,
        '-K', KEY_HEX,
        '-iv', IV_HEX
    ], "AES-128-CBC Encryption")
    
    # Task 2.3: AES-256-ECB (for comparison)
    key256 = KEY_HEX + "00112233445566778899aabbccddeeff"  # 256-bit key
    out_aes256_ecb = os.path.join(OUT_DIR, 'pic_aes256_ecb.bin')
    run_openssl([
        'enc', '-aes-256-ecb',
        '-in', original,
        '-out', out_aes256_ecb,
        '-K', key256
    ], "AES-256-ECB Encryption")
    
    # Task 2.4: AES-256-CBC (for comparison)
    out_aes256_cbc = os.path.join(OUT_DIR, 'pic_aes256_cbc.bin')
    run_openssl([
        'enc', '-aes-256-cbc',
        '-in', original,
        '-out', out_aes256_cbc,
        '-K', key256,
        '-iv', IV_HEX
    ], "AES-256-CBC Encryption")
    
    # Rename encrypted files to .bmp, and copy BMP header (54 bytes) from original
    # so encrypted files can be viewed as valid BMP images
    with open(original, 'rb') as f:
        bmp_header = f.read(54)
    
    for bin_name, bmp_name in [
        ('pic_aes128_ecb.bin', 'pic_aes128_ecb.bmp'),
        ('pic_aes128_cbc.bin', 'pic_aes128_cbc.bmp'),
        ('pic_aes256_ecb.bin', 'pic_aes256_ecb.bmp'),
        ('pic_aes256_cbc.bin', 'pic_aes256_cbc.bmp'),
    ]:
        src = os.path.join(OUT_DIR, bin_name)
        dst = os.path.join(OUT_DIR, bmp_name)
        if os.path.exists(src):
            # Read encrypted data (skip original header, get body)
            with open(src, 'rb') as f:
                enc_data = f.read()
            # Write BMP: original header (54 bytes) + encrypted body
            with open(dst, 'wb') as f:
                f.write(bmp_header + enc_data[54:] if len(enc_data) > 54 else bmp_header + enc_data)
            os.remove(src)
            size = os.path.getsize(dst)
            print(f"  {bmp_name}: {size} bytes (BMP header copied from original)")
    
    # Print file sizes for comparison
    print("\n--- File Size Comparison ---")
    orig_size = os.path.getsize(original)
    print(f"Original:    {orig_size} bytes")
    for name in ['pic_aes128_ecb.bmp', 'pic_aes128_cbc.bmp', 'pic_aes256_ecb.bmp', 'pic_aes256_cbc.bmp']:
        path = os.path.join(OUT_DIR, name)
        if os.path.exists(path):
            print(f"{name}: {os.path.getsize(path)} bytes")
    
    print("\n" + "=" * 60)
    print("TASK 3: ECB vs CBC COMPARISON")
    print("=" * 60)
    print("Open the .bmp files in an image viewer to compare:")
    print("  - AES-128-ECB: Patterns visible (ECB leaks structure)")
    print("  - AES-128-CBC: Looks random (CBC hides structure)")
    print("  - AES-256-ECB: Patterns visible (same as AES-128-ECB)")
    print("  - AES-256-CBC: Looks random (same as AES-128-CBC)")
    
    with open(os.path.join(OUT_DIR, 'task2_summary.txt'), 'w') as f:
        f.write("TASK 2 & 3: ENCRYPTION RESULTS\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"Original: pic_original.bmp ({orig_size} bytes)\n")
        f.write(f"Key (hex): {KEY_HEX}\n")
        f.write(f"IV (hex):  {IV_HEX}\n\n")
        f.write("Encrypted files:\n")
        for name in ['pic_aes128_ecb.bmp', 'pic_aes128_cbc.bmp', 'pic_aes256_ecb.bmp', 'pic_aes256_cbc.bmp']:
            path = os.path.join(OUT_DIR, name)
            if os.path.exists(path):
                f.write(f"  {name}: {os.path.getsize(path)} bytes\n")
        f.write("\nObservation:\n")
        f.write("  ECB mode: Image patterns are visible in the encrypted file\n")
        f.write("  CBC mode: Encrypted file appears random, no patterns visible\n")
    
    print("\nResults saved to task2_output/")

if __name__ == '__main__':
    main()
