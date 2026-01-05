

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from crypto import encrypt_file_inplace, decrypt_file_inplace


class FileEncrypterGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.filepath = None

        self.root.title("Secure File Encrypter")
        self.root.geometry("500x300")
        self.root.resizable(False, False)

        self._build_ui()

    def _build_ui(self):
        ttk.Label(
            self.root,
            text="Secure File Encrypter",
            font=("Segoe UI", 16, "bold")
        ).pack(pady=10)

        self.path_var = tk.StringVar(value="No file selected")
        ttk.Label(self.root, textvariable=self.path_var, wraplength=460)\
            .pack(pady=5)

        ttk.Button(
            self.root,
            text="Select File",
            command=self.select_file
        ).pack(pady=5)

        ttk.Label(self.root, text="Password").pack(pady=(10, 2))

        self.password = ttk.Entry(self.root, show="*", width=30)
        self.password.pack()

        self.show_pwd = tk.BooleanVar()
        ttk.Checkbutton(
            self.root,
            text="Show password",
            variable=self.show_pwd,
            command=self.toggle_password
        ).pack(pady=2)

        ttk.Button(
            self.root,
            text="Encrypt",
            command=self.encrypt
        ).pack(pady=5)

        ttk.Button(
            self.root,
            text="Decrypt",
            command=self.decrypt
        ).pack(pady=5)

        self.status = tk.StringVar(value="Ready")
        ttk.Label(
            self.root,
            textvariable=self.status,
            relief="sunken",
            anchor="w"
        ).pack(fill="x", side="bottom")

    def select_file(self):
        self.filepath = filedialog.askopenfilename()
        self.path_var.set(self.filepath or "No file selected")
        self.status.set("File selected" if self.filepath else "Ready")

    def encrypt(self):
        pwd = self.password.get()
        if not self._validate(pwd):
            return

        if not messagebox.askyesno("Confirm", "Encrypt the original file?"):
            return

        try:
            self.status.set("Encrypting...")
            encrypt_file_inplace(self.filepath, pwd)
            self.status.set("Encryption completed")
            messagebox.showinfo("Success", "File encrypted")
        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.status.set("Error")

    def decrypt(self):
        pwd = self.password.get()
        if not self._validate(pwd):
            return

        if not messagebox.askyesno("Confirm", "Decrypt the original file?"):
            return

        try:
            self.status.set("Decrypting...")
            decrypt_file_inplace(self.filepath, pwd)
            self.status.set("Decryption completed")
            messagebox.showinfo("Success", "File decrypted")
        except Exception:
            messagebox.showerror("Error", "Wrong password or file not encrypted")
            self.status.set("Failed")

    def toggle_password(self):
        self.password.config(show="" if self.show_pwd.get() else "*")

    def _validate(self, pwd: str) -> bool:
        if not self.filepath:
            messagebox.showerror("Error", "No file selected")
            return False
        if not pwd:
            messagebox.showerror("Error", "Password required")
            return False
        return True
