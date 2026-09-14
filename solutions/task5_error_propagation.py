#!/usr/bin/env python3
"""
Task 5: Error Propagation - Corrupted Cipher Text
1. Create a text file >1000 bytes
2. Encrypt with AES-128 in ECB, CBC, CFB, OFB modes
3. Corrupt the 55th byte of the ciphertext
4. Decrypt and observe error propagation
"""
import subprocess
import os

OPENSSL = r"C:\Program Files\OpenSSL-Win64\bin\openssl.exe"
OUT_DIR = os.path.join(os.path.dirname(__file__), 'task5_output')
KEY_HEX = "00112233445566778899aabbccddeeff"
IV_HEX = "010203040506070809000a0b0c0d0e0f"

def openssl(args):
    cmd = [OPENSSL] + args
    result = subprocess.run(cmd, capture_output=True)
    return result.returncode == 0

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    
    print("=" * 60)
    print("TASK 5: ERROR PROPAGATION - CORRUPTED CIPHERTEXT")
    print("=" * 60)
    
    # Step 1: Create a test file >1000 bytes
    plaintext_file = os.path.join(OUT_DIR, 'plaintext.txt')
    # Create ~1050 bytes of repeating text
    text = "The quick brown fox jumps over the lazy dog. " * 23  # ~1058 bytes
    with open(plaintext_file, 'w') as f:
        f.write(text)
    
    plaintext_size = os.path.getsize(plaintext_file)
    print(f"\nOriginal plaintext: {plaintext_size} bytes")
    
    # Step 2: Encrypt with different modes
    modes = ['aes-128-ecb', 'aes-128-cbc', 'aes-128-cfb', 'aes-128-ofb']
    
    print(f"\nEncrypting with {len(modes)} modes...")
    
    for mode in modes:
        # Encrypt
        enc_file = os.path.join(OUT_DIR, f'encrypted_{mode}.enc')
        dec_clean = os.path.join(OUT_DIR, f'decrypted_{mode}_clean.txt')
        dec_corrupt = os.path.join(OUT_DIR, f'decrypted_{mode}_corrupt.txt')
        
        openssl(['enc', '-' + mode, '-e', '-in', plaintext_file, '-out', enc_file,
                 '-K', KEY_HEX, '-iv', IV_HEX])
        
        enc_size = os.path.getsize(enc_file)
        print(f"\n  {mode}: encrypted size = {enc_size} bytes")
        
        # Decrypt clean version
        openssl(['enc', '-' + mode, '-d', '-in', enc_file, '-out', dec_clean,
                 '-K', KEY_HEX, '-iv', IV_HEX])
        
        # Step 3: Corrupt the 55th byte (flip bits)
        with open(enc_file, 'rb') as f:
            enc_data = bytearray(f.read())
        
        byte_to_corrupt = 54  # 0-indexed = 55th byte
        original_byte = enc_data[byte_to_corrupt]
        enc_data[byte_to_corrupt] ^= 0xFF  # Flip all bits
        corrupted_byte = enc_data[byte_to_corrupt]
        
        print(f"  Corrupted byte 55: 0x{original_byte:02x} -> 0x{corrupted_byte:02x}")
        
        # Write corrupted file
        corrupt_file = os.path.join(OUT_DIR, f'corrupted_{mode}.enc')
        with open(corrupt_file, 'wb') as f:
            f.write(enc_data)
        
        # Step 4: Decrypt corrupted version
        openssl(['enc', '-' + mode, '-d', '-in', corrupt_file, '-out', dec_corrupt,
                 '-K', KEY_HEX, '-iv', IV_HEX])
        
        # Read and compare
        with open(dec_clean, 'rb') as f:
            clean_data = f.read()
        with open(dec_corrupt, 'rb') as f:
            corrupt_data = f.read()
        
        # Find first difference
        min_len = min(len(clean_data), len(corrupt_data))
        first_diff = -1
        for i in range(min_len):
            if clean_data[i] != corrupt_data[i]:
                first_diff = i
                break
        
        # Count total corrupted bytes
        diff_count = sum(1 for i in range(min_len) if clean_data[i] != corrupt_data[i])
        
        if mode == 'aes-128-ecb':
            analysis = "ECB: 1 block (16 bytes) corrupted. Each block independent."
        elif mode == 'aes-128-cbc':
            analysis = "CBC: 2 blocks (32 bytes) corrupted. Current block + next block (due to XOR chain)."
        elif mode == 'aes-128-cfb':
            analysis = "CFB: 17 bytes corrupted (1 block + 1 byte). Error propagates through shift register."
        elif mode == 'aes-128-ofb':
            analysis = "OFB: Only 1 byte corrupted. Errors don't propagate in OFB mode."
        
        print(f"  Corrupted bytes in plaintext: {diff_count}")
        if first_diff >= 0:
            print(f"  First corruption at byte: {first_diff + 1}")
        print(f"  Analysis: {analysis}")
    
    print("\n--- Summary ---")
    print("ECB:  Corruption confined to 1 block (16 bytes). No propagation between blocks.")
    print("CBC:  Corrupted byte affects current block AND next block (32 bytes total).")
    print("CFB:  Corrupted byte affects ~1 block + 1 byte (17 bytes).")
    print("OFB:  Only the single corrupted byte is affected. No error propagation.")
    
    print(f"\nResults saved to task5_output/")

if __name__ == '__main__':
    main()
