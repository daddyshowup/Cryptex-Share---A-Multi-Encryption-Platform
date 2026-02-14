# Cryptex Share: A Multi-Encryption Platform

# By Rohit Shrestha --<>

Cryptex Share is a Python-based **multi-encryption desktop platform** that supports **text and file encryption/decryption** using multiple cryptographic algorithms and modes. It also provides **hybrid encryption (RSA key wrapping)**, **hashing/HMAC utilities**, **digital signatures (RSA-PSS / ECDSA)**, a **recipient-based encrypted sharing store**, and **security monitoring/logging** for audit evidence.

> Designed for coursework demonstration and secure local-first cryptography workflows.

---

## Features

### Text Security
- Encrypt / Decrypt text with selectable algorithms/modes (e.g., AES modes, ChaCha20)
- Authenticated encryption support (AES-GCM includes tag verification)
- Output encoding using Base64 for portability

### File Security
- Encrypt / Decrypt files (supports password-based key derivation and key/IV mode)
- Hybrid file encryption: encrypt file with symmetric key + wrap key using RSA (OAEP)

### Integrity & Authenticity
- Hashing: SHA-256 / SHA-512 / SHA3-256
- HMAC: HMAC-SHA256 / HMAC-SHA512
- Digital signatures:
  - RSA-PSS + SHA-256
  - ECDSA (P-256) + SHA-256

### Secure Sharing (Local Store)
- Share encrypted files to registered recipients using a **share_id**
- Access counters + timestamps
- Optional **one-time access** (invalidates after first retrieval)

### Monitoring & Audit Evidence
- Security event logging to `security_logs.jsonl` (e.g., decrypt success/fail)
- User/operation tracking stored in SQLite (`encryption_suite.db`)

---

## Tech Stack
- **Python 3.x**
- **Tkinter/ttk** for GUI
- **cryptography** library for crypto primitives
- **SQLite** for user accounts & usage tracking
- **JSON / JSONL** for share store and security logs

---

## Project Structure (typical)

├── main.py / Cryptex_Share.py # (your single-file source code)
├── encryption_suite.db # auto-created (runtime)
├── shared_files.json # auto-created (runtime)
├── security_logs.jsonl # auto-created (runtime)
├── README.md


# Output Files (Generated)

 - encryption_suite.db: SQLite user store + operation counts
 - shared_files.json: recipient-based encrypted share store
 - security_logs.jsonl: append-only security log events

# How Sharing Works (High Level)

 - Sender encrypts a file (symmetric or hybrid)
 - Sender shares to a recipient (registered email/username)
 - A random share_id is generated and stored with encrypted payload + metadata
 - Recipient lists received shares and decrypts using correct credentials
 - If one-time is enabled, repeated access marks share corrupted and overwrites stored ciphertext

# Security Notes (Important)

 - AES-GCM provides integrity via authentication tag verification.
 - CBC/CTR modes do not provide integrity unless combined with HMAC/signatures.
 - Treat unknown encrypted containers as untrusted (future work: replace pickle container format).

# Future Improvements

 - SMTP delivery of encrypted output to any valid email (TLS)
 - Auto sign-on-share and verify-on-receive for authenticity
 - Sharing policies: expiry / revoke / download limits
 - Streaming encryption for large files + non-blocking GUI
 - Key management vault and safer key handling UX
 - Alert-based analytics from JSONL security logs
