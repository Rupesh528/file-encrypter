"""
Secure File Encrypter / Decrypter (GUI)
--------------------------------------
Features:
- Encrypts the ORIGINAL file (in-place)
- Decrypts the ORIGINAL file (in-place)
- Works for ANY file type
- Password-based AES encryption (PBKDF2 + Fernet)
- File-only encryption (no folders)
- Modern Tkinter (ttk) UI
- Status bar + confirmations

Educational / defensive use only.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
import base64

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

# ================= CRYPTO HELPERS =================

def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derives a secure AES key from a password using PBKDF2.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

# ================= FILE OPERATIONS =================

def encrypt_file_inplace(filepath: str, password: str):
    """
    Encrypts the ORIGINAL file by overwriting its contents.
    """
    salt = os.urandom(16)
    key = derive_key(password, salt)
    fernet = Fernet(key)

    # Read original data
    with open(filepath, "rb") as f:
        original_data = f.read()

    # Encrypt data
    encrypted_data = fernet.encrypt(original_data)

    # Overwrite original file
    with open(filepath, "wb") as f:
        f.write(salt + encrypted_data)

def decrypt_file_inplace(filepath: str, password: str):
    """
    Decrypts the ORIGINAL encrypted file by overwriting its contents.
    """
    with open(filepath, "rb") as f:
        salt = f.read(16)
        encrypted_data = f.read()

    key = derive_key(password, salt)
    fernet = Fernet(key)

    # Decrypt data (raises error if password is wrong)
    decrypted_data = fernet.decrypt(encrypted_data)

    # Overwrite file with decrypted content
    with open(filepath, "wb") as f:
        f.write(decrypted_data)

# ================= GUI LOGIC =================

selected_file = None

def set_status(text: str):
    status_var.set(text)

def select_file():
    global selected_file
    selected_file = filedialog.askopenfilename()
    path_var.set(selected_file or "No file selected")
    set_status("File selected" if selected_file else "Ready")

def encrypt_action():
    password = password_entry.get()

    if not selected_file or not password:
        messagebox.showerror("Error", "Select a file and enter password")
        return

    if not messagebox.askyesno(
        "Confirm Encryption",
        f"This will ENCRYPT the original file:\n\n{selected_file}\n\nProceed?"
    ):
        return

    try:
        set_status("Encrypting...")
        encrypt_file_inplace(selected_file, password)
        messagebox.showinfo("Success", "File encrypted successfully")
        set_status("Encryption completed")
    except Exception as e:
        messagebox.showerror("Error", str(e))
        set_status("Error occurred")

def decrypt_action():
    password = password_entry.get()

    if not selected_file or not password:
        messagebox.showerror("Error", "Select a file and enter password")
        return

    if not messagebox.askyesno(
        "Confirm Decryption",
        f"This will DECRYPT the original file:\n\n{selected_file}\n\nProceed?"
    ):
        return

    try:
        set_status("Decrypting...")
        decrypt_file_inplace(selected_file, password)
        messagebox.showinfo("Success", "File decrypted successfully")
        set_status("Decryption completed")
    except Exception:
        messagebox.showerror(
            "Error",
            "Decryption failed.\nPossible reasons:\n- Wrong password\n- File is not encrypted"
        )
        set_status("Decryption failed")

def toggle_password():
    password_entry.config(show="" if show_password.get() else "*")

# ================= UI SETUP =================

root = tk.Tk()
root.title("Secure File Encrypter (In-Place)")
root.geometry("600x380")
root.resizable(False, False)

style = ttk.Style()
style.theme_use("clam")

# Title
ttk.Label(
    root,
    text="Secure File Encrypter",
    font=("Segoe UI", 18, "bold")
).pack(pady=12)

# Main container
card = ttk.Frame(root, padding=20)
card.pack(fill="x", padx=20)

# Selected file display
path_var = tk.StringVar(value="No file selected")
ttk.Label(card, textvariable=path_var, wraplength=560).pack(pady=8)

# File select button
ttk.Button(
    card,
    text="Select File",
    width=22,
    command=select_file
).pack(pady=8)

# Password section
ttk.Label(card, text="Password", font=("Segoe UI", 11)).pack(pady=(15, 5))

pwd_frame = ttk.Frame(card)
pwd_frame.pack()

password_entry = ttk.Entry(pwd_frame, width=32, show="*")
password_entry.grid(row=0, column=0, padx=5)

show_password = tk.BooleanVar()
ttk.Checkbutton(
    pwd_frame,
    text="Show",
    variable=show_password,
    command=toggle_password
).grid(row=0, column=1)

# Action buttons
action_frame = ttk.Frame(card)
action_frame.pack(pady=20)

ttk.Button(
    action_frame,
    text="Encrypt (Overwrite)",
    width=20,
    command=encrypt_action
).grid(row=0, column=0, padx=12)

ttk.Button(
    action_frame,
    text="Decrypt (Overwrite)",
    width=20,
    command=decrypt_action
).grid(row=0, column=1, padx=12)

# Status bar
status_var = tk.StringVar(value="Ready")
ttk.Label(
    root,
    textvariable=status_var,
    relief="sunken",
    anchor="w",
    padding=5
).pack(fill="x", side="bottom")

root.mainloop()
