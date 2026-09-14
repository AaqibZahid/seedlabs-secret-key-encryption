# Secret-Key Encryption Lab (SEED Labs)

Hands-on lab exercises exploring symmetric encryption concepts: frequency analysis, AES modes (ECB/CBC/CFB/OFB), padding schemes, error propagation, IV security, and brute-force attacks.

Based on the [SEED Labs](https://seedsecuritylabs.org/Labs_20.04/Crypto/Crypto_Encryption/) Secret-Key Encryption lab by Prof. Wenliang Du, Syracuse University.

## What You'll Learn

- **Frequency analysis** — breaking monoalphabetic substitution ciphers
- **AES encryption modes** — ECB, CBC, CFB, OFB behavior and tradeoffs
- **ECB vs CBC** — why ECB leaks structure in images
- **PKCS#5 padding** — how block modes pad plaintext
- **Error propagation** — how bit errors spread across modes
- **IV security** — why IVs must never repeat under the same key
- **Known-plaintext attack** — recovering plaintext from OFB mode
- **Chosen-plaintext attack** — exploiting predictable IVs in CBC mode
- **Dictionary brute-force** — why English words make terrible keys

## Prerequisites

- Python 3.6+
- OpenSSL (`openssl` CLI)
- A C compiler (gcc) for Task 7 (optional — Python fallback included)

## Project Structure

```
.
├── Labsetup/
│   ├── Files/
│   │   ├── ciphertext.txt        # Task 1: encrypted text to decode
│   │   ├── pic_original.bmp      # Tasks 2-3: image for encryption
│   │   ├── words.txt             # Task 7: dictionary for brute-force
│   │   ├── freq.py               # Frequency analysis helper
│   │   └── sample_code.py        # Reference encryption code
│   ├── encryption_oracle/        # TCP oracle server for Task 6.3
│   │   ├── server.cpp
│   │   ├── evp-encrypt.hpp
│   │   ├── utils.hpp
│   │   └── Makefile
│   └── docker-compose.yml        # Docker setup (optional)
│
└── solutions/
    ├── task1_frequency_analysis.py    # Frequency analysis decryption
    ├── task2_encryption_modes.py      # AES-128/256 ECB/CBC encryption
    ├── task4_padding.py               # PKCS#5 padding analysis
    ├── task5_error_propagation.py     # Error propagation test
    ├── task6_1_iv_experiment.py       # IV reuse demonstration
    ├── task6_2_kpa_ofb.py            # Known-plaintext attack on OFB
    ├── task6_3_oracle_server.py       # Local oracle (Python replacement)
    ├── task6_3_cpa_attack.py         # Chosen-plaintext attack
    ├── task7_brute_force.py           # Brute-force dictionary attack
    ├── task7_evp_brute_force.py       # OpenSSL EVP brute-force (faster)
    └── task7_brute_force.c           # C implementation (reference)
```

## Running the Tasks

### Task 1 — Frequency Analysis
```bash
python solutions/task1_frequency_analysis.py
```

### Task 2 — AES Encryption
```bash
python solutions/task2_encryption_modes.py
```

### Task 4 — Padding Analysis
```bash
python solutions/task4_padding.py
```

### Task 5 — Error Propagation
```bash
python solutions/task5_error_propagation.py
```

### Task 6.1 — IV Experiment
```bash
python solutions/task6_1_iv_experiment.py
```

### Task 6.2 — Known-Plaintext Attack
```bash
python solutions/task6_2_kpa_ofb.py
```

### Task 6.3 — Chosen-Plaintext Attack

Start the oracle server, then run the attack:
```bash
# Terminal 1
python solutions/task6_3_oracle_server.py

# Terminal 2
python solutions/task6_3_cpa_attack.py
```

### Task 7 — Brute-Force Key
```bash
# Python (uses OpenSSL via ctypes)
python solutions/task7_evp_brute_force.py

# Or plain Python (slower)
python solutions/task7_brute_force.py
```

## Background

This lab covers the fundamentals of symmetric (secret-key) encryption using AES. You'll see firsthand why mode selection matters, how IV reuse breaks security, and why key quality is critical.

The original lab is designed for Ubuntu 20.04 with Docker. This implementation runs natively on Windows/Linux/macOS using Python and the OpenSSL CLI.

## References

- [SEED Labs — Secret-Key Encryption](https://seedsecuritylabs.org/Labs_20.04/Crypto/Crypto_Encryption/)
- *Computer & Internet Security: A Hands-on Approach* — Wenliang Du (2nd Ed.)
- [OpenSSL Documentation](https://www.openssl.org/docs/)

## License

Educational use. The SEED Labs materials are copyright Syracuse University.
