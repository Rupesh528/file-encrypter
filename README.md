# Secure File Encrypter

This is a simple GUI-based file encryption tool written in Python.  
It allows you to encrypt and decrypt **individual files in place** using a password.

I built this project to understand how real-world file encryption works and to practice secure coding concepts used in cybersecurity.

---

## What this project does

- Encrypts a file by **overwriting the original content**
- Decrypts the same file back using the correct password
- Works with any file type (text files, images, PDFs, zip files, etc.)
- Uses a minimal GUI so the focus stays on security, not UI complexity

There is **no folder encryption** on purpose, to avoid accidental data loss or unsafe behavior.

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

