#!/usr/bin/env python3
"""
Task 6.1: IV Experiment
Encrypt the same plaintext with:
1. Two different IVs
2. Same IV
Show why IV must be unique under the same key.
"""
import subprocess
import os

OPENSSL = r"C:\Program Files\OpenSSL-Win64\bin\openssl.exe"
OUT_DIR = os.path.join(os.path.dirname(__file__), 'task6_1_output')
KEY_HEX = "00112233445566778899aabbccddeeff"
IV1_HEX = "010203040506070809000a0b0c0d0e0f"
IV2_HEX = "0f0e0d0c0b0a09080706050403020100"

def openssl(args):
    cmd = [OPENSSL] + args
    result = subprocess.run(cmd, capture_output=True)
    return result.returncode == 0

def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    
    print("=" * 60)
    print("TASK 6.1: IV EXPERIMENT")
    print("=" * 60)
    
    # Create plaintext file
    plaintext_file = os.path.join(OUT_DIR, 'plaintext.txt')
    with open(plaintext_file, 'w') as f:
        f.write("This is a secret message that needs to be encrypted securely!")
    
    print(f"\nPlaintext: Same message for all encryptions")
    print(f"Key: {KEY_HEX}")
    print(f"IV1: {IV1_HEX}")
    print(f"IV2: {IV2_HEX}")
    
    # Part 1: Encrypt with two different IVs
    print("\n--- Part 1: Different IVs ---")
    
    enc_iv1 = os.path.join(OUT_DIR, 'enc_iv1.bin')
    enc_iv2 = os.path.join(OUT_DIR, 'enc_iv2.bin')
    
    openssl(['enc', '-aes-128-cbc', '-e', '-in', plaintext_file, '-out', enc_iv1,
             '-K', KEY_HEX, '-iv', IV1_HEX])
    openssl(['enc', '-aes-128-cbc', '-e', '-in', plaintext_file, '-out', enc_iv2,
             '-K', KEY_HEX, '-iv', IV2_HEX])
    
    with open(enc_iv1, 'rb') as f:
        c1 = f.read()
    with open(enc_iv2, 'rb') as f:
        c2 = f.read()
    
    print(f"Ciphertext with IV1: {c1.hex()}")
    print(f"Ciphertext with IV2: {c2.hex()}")
    print(f"Same ciphertext? {c1 == c2}")
    print(f"Observation: Different IVs produce different ciphertexts for same plaintext")
    
    # Part 2: Encrypt with same IV
    print("\n--- Part 2: Same IV ---")
    
    enc_same1 = os.path.join(OUT_DIR, 'enc_same1.bin')
    enc_same2 = os.path.join(OUT_DIR, 'enc_same2.bin')
    
    openssl(['enc', '-aes-128-cbc', '-e', '-in', plaintext_file, '-out', enc_same1,
             '-K', KEY_HEX, '-iv', IV1_HEX])
    openssl(['enc', '-aes-128-cbc', '-e', '-in', plaintext_file, '-out', enc_same2,
             '-K', KEY_HEX, '-iv', IV1_HEX])
    
    with open(enc_same1, 'rb') as f:
        c3 = f.read()
    with open(enc_same2, 'rb') as f:
        c4 = f.read()
    
    print(f"Ciphertext 1 (same IV): {c3.hex()}")
    print(f"Ciphertext 2 (same IV): {c4.hex()}")
    print(f"Same ciphertext? {c3 == c4}")
    print(f"Observation: Same IV produces identical ciphertext for same plaintext")
    
    # Part 3: Test with two different plaintexts, same IV
    print("\n--- Part 3: Different Plaintexts, Same IV ---")
    
    pt1_file = os.path.join(OUT_DIR, 'msg1.txt')
    pt2_file = os.path.join(OUT_DIR, 'msg2.txt')
    with open(pt1_file, 'w') as f:
        f.write("Message number one is here!")
    with open(pt2_file, 'w') as f:
        f.write("Message number two is here!")
    
    enc_msg1 = os.path.join(OUT_DIR, 'enc_msg1.bin')
    enc_msg2 = os.path.join(OUT_DIR, 'enc_msg2.bin')
    
    openssl(['enc', '-aes-128-cbc', '-e', '-in', pt1_file, '-out', enc_msg1,
             '-K', KEY_HEX, '-iv', IV1_HEX])
    openssl(['enc', '-aes-128-cbc', '-e', '-in', pt2_file, '-out', enc_msg2,
             '-K', KEY_HEX, '-iv', IV1_HEX])
    
    with open(enc_msg1, 'rb') as f:
        cm1 = f.read()
    with open(enc_msg2, 'rb') as f:
        cm2 = f.read()
    
    print(f"Msg1 ciphertext: {cm1.hex()}")
    print(f"Msg2 ciphertext: {cm2.hex()}")
    print(f"Same ciphertext? {cm1 == cm2}")
    print(f"Observation: Different plaintexts with same IV produce different ciphertexts")
    print(f"But the IV reuse pattern can leak information to an attacker")
    
    # Conclusion
    print("\n" + "=" * 60)
    print("CONCLUSION")
    print("=" * 60)
    print("IV must be unique under the same key because:")
    print("  1. Same IV + same plaintext = same ciphertext (identifiable pattern)")
    print("  2. Attacker can detect when same message is sent twice")
    print("  3. In some modes (like CFB), IV reuse can leak plaintext XOR relationships")
    print("  4. Random IVs prevent these attacks by ensuring uniqueness")
    
    with open(os.path.join(OUT_DIR, 'task6_1_summary.txt'), 'w') as f:
        f.write("TASK 6.1: IV EXPERIMENT\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"Key: {KEY_HEX}\n")
        f.write(f"IV1: {IV1_HEX}\n")
        f.write(f"IV2: {IV2_HEX}\n\n")
        f.write(f"Same plaintext, different IVs: {c1 == c2}\n")
        f.write(f"Same plaintext, same IV: {c3 == c4}\n\n")
        f.write("Conclusion: IV must be unique under the same key.\n")
        f.write("Reusing IV with same key produces identical ciphertext,\n")
        f.write("allowing attackers to detect message repetition and potentially\n")
        f.write("recover information through XOR analysis.\n")
    
    print(f"\nResults saved to task6_1_output/")

if __name__ == '__main__':
    main()
