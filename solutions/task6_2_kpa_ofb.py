#!/usr/bin/env python3
"""
Task 6.2: Known-Plaintext Attack on OFB Mode
Given P1, C1, C2 (same key+IV), recover P2 using: P2 = P1 XOR C1 XOR C2
"""
from binascii import hexlify, unhexlify

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def main():
    print("=" * 60)
    print("TASK 6.2: KNOWN-PLAINTEXT ATTACK ON OFB MODE")
    print("=" * 60)
    
    # Given information
    P1 = "This is a known message!"
    C1_hex = "a469b1c502c1cab966965e50425438e1bb1b5f9037a4c15913"
    C2_hex = "bf73bcd3509299d566c35b5d450337e1bb175f903fafc15913"
    
    print(f"\nGiven:")
    print(f"  P1 (plaintext 1):  {P1}")
    print(f"  C1 (ciphertext 1): {C1_hex}")
    print(f"  C2 (ciphertext 2): {C2_hex}")
    
    # Convert to bytes
    P1_bytes = P1.encode('utf-8')
    C1_bytes = unhexlify(C1_hex)
    C2_bytes = unhexlify(C2_hex)
    
    print(f"\n  P1 bytes: {hexlify(P1_bytes).decode()}")
    print(f"  C1 bytes: {C1_hex}")
    print(f"  C2 bytes: {C2_hex}")
    
    # In OFB mode with same key and IV:
    # C1 = P1 XOR keystream
    # C2 = P2 XOR keystream
    # Therefore: keystream = P1 XOR C1
    # And: P2 = keystream XOR C2 = P1 XOR C1 XOR C2
    
    keystream = xor_bytes(P1_bytes, C1_bytes)
    print(f"\nKeystream = P1 XOR C1:")
    print(f"  {hexlify(keystream).decode()}")
    
    P2_bytes = xor_bytes(keystream, C2_bytes)
    # Also: P2 = P1 XOR C1 XOR C2 directly
    P2_direct = xor_bytes(xor_bytes(P1_bytes, C1_bytes), C2_bytes)
    
    print(f"\nP2 = P1 XOR C1 XOR C2:")
    print(f"  Hex: {hexlify(P2_bytes).decode()}")
    try:
        P2_text = P2_bytes.decode('utf-8')
        print(f"  Text: {P2_text}")
    except:
        print(f"  (not valid UTF-8)")
    
    # Verify
    print(f"\nVerification:")
    print(f"  P2 (via keystream): {hexlify(P2_bytes).decode()}")
    print(f"  P2 (direct XOR):    {hexlify(P2_direct).decode()}")
    print(f"  Match: {P2_bytes == P2_direct}")
    
    # Also show the CFB answer
    print(f"\n--- CFB Mode Analysis ---")
    print("If OFB is replaced with CFB:")
    print("  CFB: C_i = E_k(C_{i-1}) XOR P_i (with C_0 = IV)")
    print("  With same IV: First block can be recovered (same as OFB)")
    print("  But subsequent blocks depend on previous ciphertext,")
    print("  so only the first block of P2 can be fully revealed.")
    
    # Save results
    with open('task6_2_kpa_results.txt', 'w') as f:
        f.write("TASK 6.2: KNOWN-PLAINTEXT ATTACK ON OFB MODE\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"P1: {P1}\n")
        f.write(f"C1: {C1_hex}\n")
        f.write(f"C2: {C2_hex}\n\n")
        f.write(f"Keystream (P1 XOR C1): {hexlify(keystream).decode()}\n")
        f.write(f"P2 (hex): {hexlify(P2_bytes).decode()}\n")
        try:
            f.write(f"P2 (text): {P2_bytes.decode('utf-8')}\n")
        except:
            f.write(f"P2 (text): (not valid UTF-8)\n")
        f.write(f"\nMethod: P2 = P1 XOR C1 XOR C2\n")
        f.write(f"In OFB mode, same key+IV produces same keystream.\n")
        f.write(f"Keystream = P1 XOR C1, then P2 = Keystream XOR C2\n")
    
    print("\nResults saved to task6_2_kpa_results.txt")

if __name__ == '__main__':
    main()
