#!/usr/bin/env python3
"""
Task 6.3: Chosen-Plaintext Attack on Predictable IV
Connects to the oracle server and determines if Bob's secret is "Yes" or "No".

Attack principle:
  In CBC mode: C1 = AES_K(IV XOR P1)
  If we know IV and IV_NEXT, we can construct:
    P2 = P1 XOR IV XOR IV_NEXT
  If C2[0:16] == C1[0:16], then P1 is correct.
"""
import socket
import time
from binascii import hexlify, unhexlify

HOST = '127.0.0.1'
PORT = 3000

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def connect_oracle():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    
    # Receive initial data
    data = b''
    while True:
        chunk = sock.recv(4096)
        data += chunk
        if b'Your plaintext : ' in data:
            break
        time.sleep(0.1)
    
    text = data.decode()
    print(text)
    
    # Parse the response
    lines = text.strip().split('\n')
    c1 = None
    iv_used = None
    next_iv = None
    
    for line in lines:
        line = line.strip()
        if "Bob's ciphertex:" in line:
            c1 = line.split(':')[-1].strip()
        elif 'The IV used' in line:
            iv_used = line.split(':')[-1].strip()
        elif 'Next IV' in line:
            next_iv = line.split(':')[-1].strip()
    
    return sock, c1, iv_used, next_iv

def send_plaintext(sock, plaintext_hex):
    """Send plaintext to oracle and receive ciphertext"""
    msg = plaintext_hex + '\n'
    sock.sendall(msg.encode())
    
    data = b''
    while b'Next IV' not in data and b'Your ciphertext' not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
        time.sleep(0.1)
    
    text = data.decode()
    print(text)
    
    # Parse response
    c2 = None
    next_iv = None
    for line in text.strip().split('\n'):
        line = line.strip()
        if 'Your ciphertext' in line:
            c2 = line.split(':')[-1].strip()
        elif 'Next IV' in line:
            next_iv = line.split(':')[-1].strip()
    
    return c2, next_iv

def main():
    print("=" * 60)
    print("TASK 6.3: CHOSEN-PLAINTEXT ATTACK ON PREDICTABLE IV")
    print("=" * 60)
    print()
    print("Attack Strategy:")
    print("  Bob's secret is either 'Yes' or 'No'")
    print("  In CBC: C1 = AES_K(IV XOR P1)")
    print("  We construct P2 = P1 XOR IV XOR IV_NEXT")
    print("  If C2[0:16] == C1[0:16], then P1 is correct")
    print()
    
    # Connect to oracle
    print("--- Connecting to Oracle ---")
    sock, c1_hex, iv_used_hex, next_iv_hex = connect_oracle()
    
    if not c1_hex or not iv_used_hex:
        print("Error: Could not parse oracle response")
        sock.close()
        return
    
    c1 = unhexlify(c1_hex)
    iv_used = unhexlify(iv_used_hex)
    
    print(f"\nParsed values:")
    print(f"  C1 (Bob's ciphertext): {c1_hex}")
    print(f"  IV used:               {iv_used_hex}")
    print(f"  Next IV:               {next_iv_hex}")
    
    # Test with "Yes" first
    print("\n--- Testing with 'Yes' ---")
    
    # PKCS7 pad "Yes" to 16 bytes
    # "Yes" = 59 65 73 (3 bytes), padding = 0d 0d 0d ... 0d (13 bytes of 0x0d)
    # Actually PKCS7: pad to 16 bytes: "Yes" + 13 bytes of 0x0d
    p_yes = b'Yes' + bytes([0x0d] * 13)  # 16 bytes
    print(f"  P_yes (padded): {hexlify(p_yes).decode()}")
    
    # Construct P2 = P_yes XOR IV_USED XOR IV_NEXT
    iv_next = unhexlify(next_iv_hex)
    p2_yes = xor_bytes(xor_bytes(p_yes, iv_used), iv_next)
    p2_yes_hex = hexlify(p2_yes).decode()
    print(f"  P2 (for Yes): {p2_yes_hex}")
    
    c2_hex, next_iv_hex = send_plaintext(sock, p2_yes_hex)
    if c2_hex:
        c2 = unhexlify(c2_hex)
        match_yes = c2[:16] == c1[:16]
        print(f"  C2[0:16]: {hexlify(c2[:16]).decode()}")
        print(f"  C1[0:16]: {hexlify(c1[:16]).decode()}")
        print(f"  Match: {match_yes}")
    
    # Test with "No" (optional, since "Yes" already matched)
    print("\n--- Testing with 'No' (verification) ---")
    p_no = b'No' + bytes([0x0e] * 14)  # 16 bytes (2 bytes + 14 padding)
    print(f"  P_no (padded): {hexlify(p_no).decode()}")
    
    if next_iv_hex:
        iv_next2 = unhexlify(next_iv_hex)
        p2_no = xor_bytes(xor_bytes(p_no, iv_used), iv_next2)
        p2_no_hex = hexlify(p2_no).decode()
        print(f"  P2 (for No): {p2_no_hex}")
        
        c2_hex2, _ = send_plaintext(sock, p2_no_hex)
        if c2_hex2:
            c2_2 = unhexlify(c2_hex2)
            match_no = c2_2[:16] == c1[:16]
            print(f"  C2[0:16]: {hexlify(c2_2[:16]).decode()}")
            print(f"  C1[0:16]: {hexlify(c1[:16]).decode()}")
            print(f"  Match: {match_no}")
    else:
        print("  (Skipped - 'Yes' already matched)")
        match_no = False
    
    # Conclusion
    print("\n" + "=" * 60)
    print("CONCLUSION")
    print("=" * 60)
    if match_yes:
        print("  Bob's secret message is: Yes")
    elif match_no:
        print("  Bob's secret message is: No")
    else:
        print("  Neither matched - attack needs refinement")
    
    sock.close()
    
    # Save results
    with open('task6_3_cpa_results.txt', 'w') as f:
        f.write("TASK 6.3: CHOSEN-PLAINTEXT ATTACK ON PREDICTABLE IV\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"Bob's ciphertext (C1): {c1_hex}\n")
        f.write(f"IV used: {iv_used_hex}\n\n")
        f.write(f"Attack method: P2 = P1 XOR IV_USED XOR IV_NEXT\n")
        f.write(f"If C2[0:16] == C1[0:16], then P1 is correct\n\n")
        if match_yes:
            f.write("Result: Bob's secret is 'Yes'\n")
        elif match_no:
            f.write("Result: Bob's secret is 'No'\n")
    
    print("\nResults saved to task6_3_cpa_results.txt")

if __name__ == '__main__':
    main()
