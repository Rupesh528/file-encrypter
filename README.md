# Secure File Encrypter (In-Place)

TODO: Write a one-line summary describing what this project does.

---

## Project Overview

TODO:
Describe the purpose of this project.
Explain why you built it and what problem it solves.
Mention that this is a cybersecurity / cryptography learning project if relevant.

---

## Features

- In-place file encryption (original file is overwritten)
- In-place file decryption
- Password-based encryption
- Graphical user interface
- Supports all file types

TODO: Add or remove features as needed.

---

## Security Design

TODO:
Explain your security-related design decisions, such as:
- Why encryption is limited to individual files
- Why folder encryption is not supported
- Why user confirmation is required before encryption/decryption

---

## Cryptography Used

| Component        | Description            |
|------------------|------------------------|
| Encryption       | AES (Fernet)           |
| Key Derivation   | PBKDF2 (HMAC-SHA256)   |
| Salt             | Random per file        |
| Iterations       | 100,000                |

TODO: Update this table if algorithms or parameters change.

---

## Project Structure

