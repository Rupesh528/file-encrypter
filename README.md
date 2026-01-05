# Secure File Encrypter

This is a simple GUI-based file encryption tool written in Python.  
It allows you to encrypt and decrypt **individual files in place** using a password.


---

## What this project does

- Encrypts a file by **overwriting the original content**
- Decrypts the same file back using the correct password
- Works with any file type (text files, images, PDFs, zip files, etc.)
- Uses a minimal GUI so the focus stays on security, not UI complexity


---

## How encryption works here

- The user enters a password
- A strong encryption key is derived from the password using **PBKDF2**
- The file is encrypted using **AES (via Fernet)**
- A random salt is generated for every encryption
- The encrypted data replaces the original file content

If the password is wrong, the file cannot be decrypted.

---

## Features

- In-place file encryption (no encrypted copy)
- In-place file decryption
- Password-based protection
- AES symmetric encryption
- Simple Tkinter GUI
- Clean and modular code structure

---


---

## Installation

### Requirements
- Python 3.8 or higher
- pip

### Setup

```bash
git clone https://github.com/Rupesh528/file-encrypter.git
cd file-encrypter

python3 -m venv venv
source venv/bin/activate

pip install cryptography
```
- to run : python3 main.py
