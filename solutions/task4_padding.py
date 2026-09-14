#!/usr/bin/env python3
"""
Task 4: Padding (PKCS#5)
1. Which modes use padding and which don't
2. Encrypt files of 5, 10, 16 bytes with AES-128-CBC, examine padding
"""
import subprocess
import os

OPENSSL = r"C:\Program Files\OpenSSL-Win64\bin\openssl.exe"
OUT_DIR = os.path.join(os.path.dirname(__file__), 'task4_output')
KEY_HEX = "00112233445566778899aabbccddeeff"
IV_HEX = "010203040506070809000a0b0c0d0e0f"

def openssl(args):
    cmd = [OPENSSL] + args
    result = subprocess.run(cmd, capture_output=True)
    return result.returncode == 0

def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    
    print("=" * 60)
    print("TASK 4: PADDING (PKCS#5)")
    print("=" * 60)
    
    # Part 1: Which modes pad?
    print("\n--- Part 1: Which Modes Use Padding? ---")
    modes = ['aes-128-ecb', 'aes-128-cbc', 'aes-128-cfb', 'aes-128-ofb']
    
    # Test with 5-byte file (not aligned to block size)
    test_file = os.path.join(OUT_DIR, 'test_5bytes.bin')
    with open(test_file, 'wb') as f:
        f.write(b'12345')  # 5 bytes
    
    print(f"\nTest file: 5 bytes (not block-aligned)")
    print(f"{'Mode':<20} {'Encrypted Size':<20} {'Pads?'}")
    print("-" * 55)
    
    for mode in modes:
        enc_file = os.path.join(OUT_DIR, f'test_5_{mode}.enc')
        openssl(['enc', '-' + mode, '-e', '-in', test_file, '-out', enc_file,
                 '-K', KEY_HEX, '-iv', IV_HEX])
        enc_size = os.path.getsize(enc_file)
        # ECB/CBC pad to next block (16), CFB/OFB don't pad (stream-like)
        pads = enc_size > 5
        print(f"{mode:<20} {enc_size:<20} {'Yes' if pads else 'No'}")
    
    # Part 2: Examine PKCS#5 padding
    print("\n--- Part 2: PKCS#5 Padding Analysis ---")
    
    for length, name in [(5, '5bytes'), (10, '10bytes'), (16, '16bytes')]:
        # Create test file
        test_file = os.path.join(OUT_DIR, f'test_{name}.bin')
        with open(test_file, 'wb') as f:
            f.write(bytes(range(length)))  # 0x00, 0x01, ... up to length bytes
        
        # Encrypt with CBC
        enc_file = os.path.join(OUT_DIR, f'test_{name}_cbc.enc')
        openssl(['enc', '-aes-128-cbc', '-e', '-in', test_file, '-out', enc_file,
                 '-K', KEY_HEX, '-iv', IV_HEX])
        
        # Decrypt with -nopad to see padding
        dec_file = os.path.join(OUT_DIR, f'test_{name}_nopad.bin')
        openssl(['enc', '-aes-128-cbc', '-d', '-nopad', '-in', enc_file, '-out', dec_file,
                 '-K', KEY_HEX, '-iv', IV_HEX])
        
        enc_size = os.path.getsize(enc_file)
        with open(dec_file, 'rb') as f:
            dec_data = f.read()
        
        print(f"\nOriginal size: {length} bytes")
        print(f"Encrypted size: {enc_size} bytes")
        print(f"Decrypted (nopad) size: {len(dec_data)} bytes")
        print(f"Original data:  {dec_data[:length].hex()}")
        print(f"Full decrypted: {dec_data.hex()}")
        
        # Show padding bytes
        padding = dec_data[length:]
        if padding:
            pad_val = padding[0]
            print(f"Padding bytes:  {padding.hex()}")
            print(f"Padding value:  0x{pad_val:02x} ({pad_val} bytes of 0x{pad_val:02x})")
        
        # Verify: 16-byte file should have 16 bytes of padding (0x10)
        if length == 16:
            expected_pad = bytes([0x10] * 16)
            print(f"Expected (full block = 16 bytes of 0x10): {expected_pad.hex()}")
            print(f"Actual padding matches: {padding == expected_pad}")
    
    print("\n--- Summary ---")
    print("PKCS#5 padding adds N bytes of value N, where N is the number of")
    print("bytes needed to reach the next block boundary.")
    print("If plaintext is already block-aligned, a full block of padding is added.")
    print("ECB and CBC use padding; CFB and OFB are stream-like and don't need padding.")
    
    # Save results
    with open(os.path.join(OUT_DIR, 'task4_summary.txt'), 'w') as f:
        f.write("TASK 4: PADDING (PKCS#5)\n")
        f.write("=" * 60 + "\n\n")
        f.write("Which modes pad:\n")
        f.write("  ECB, CBC: Yes (block cipher modes)\n")
        f.write("  CFB, OFB: No (stream cipher modes, no padding needed)\n\n")
        f.write("PKCS#5 padding:\n")
        f.write("  Adds N bytes of value 0xNN where N = bytes needed to reach block boundary\n")
        f.write("  If already aligned, adds full block of 16 bytes (0x10)\n")
    
    print(f"\nResults saved to task4_output/")

if __name__ == '__main__':
    main()
