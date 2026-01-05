"""
gui.py
------
Handles the Tkinter GUI and user interactions.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from crypto import encrypt_file_inplace, decrypt_file_inplace


class FileEncrypterGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.selected_file = None

        self._setup_ui()

    def _setup_ui(self):
        self.root.title("Secure File Encrypter (In-Place)")
        self.root.geometry("600x380")
        self.root.resizable(False, False)

        style = ttk.Style()
        style.theme_use("clam")

        ttk.Label(
            self.root,
            text="Secure File Encrypter",
            font=("Segoe UI", 18, "bold")
        ).pack(pady=12)

        card = ttk.Frame(self.root, padding=20)
        card.pack(fill="x", padx=20)

        self.path_var = tk.StringVar(value="No file selected")
        ttk.Label(card, textvariable=self.path_var, wraplength=560).pack(pady=8)

        ttk.Button(
            card,
            text="Select File",
            width=22,
            command=self.select_file
        ).pack(pady=8)

        ttk.Label(card, text="Password", font=("Segoe UI", 11)).pack(pady=(15, 5))

        pwd_frame = ttk.Frame(card)
        pwd_frame.pack()

        self.password_entry = ttk.Entry(pwd_frame, width=32, show="*")
        self.password_entry.grid(row=0, column=0, padx=5)

        self.show_password = tk.BooleanVar()
        ttk.Checkbutton(
            pwd_frame,
            text="Show",
            variable=self.show_password,
            command=self.toggle_password
        ).grid(row=0, column=1)

        action_frame = ttk.Frame(card)
        action_frame.pack(pady=20)

        ttk.Button(
            action_frame,
            text="Encrypt (Overwrite)",
            width=20,
            command=self.encrypt_action
        ).grid(row=0, column=0, padx=12)

        ttk.Button(
            action_frame,
            text="Decrypt (Overwrite)",
            width=20,
            command=self.decrypt_action
        ).grid(row=0, column=1, padx=12)

        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(
            self.root,
            textvariable=self.status_var,
            relief="sunken",
            anchor="w",
            padding=5
        ).pack(fill="x", side="bottom")

    def set_status(self, text: str):
        self.status_var.set(text)

    def select_file(self):
        self.selected_file = filedialog.askopenfilename()
        self.path_var.set(self.selected_file or "No file selected")
        self.set_status("File selected" if self.selected_file else "Ready")

    def encrypt_action(self):
        password = self.password_entry.get()

        if not self.selected_file or not password:
            messagebox.showerror("Error", "Select a file and enter password")
            return

        if not messagebox.askyesno(
            "Confirm Encryption",
            f"This will ENCRYPT the original file:\n\n{self.selected_file}\n\nProceed?"
        ):
            return

        try:
            self.set_status("Encrypting...")
            encrypt_file_inplace(self.selected_file, password)
            messagebox.showinfo("Success", "File encrypted successfully")
            self.set_status("Encryption completed")
        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.set_status("Error occurred")

    def decrypt_action(self):
        password = self.password_entry.get()

        if not self.selected_file or not password:
            messagebox.showerror("Error", "Select a file and enter password")
            return

        if not messagebox.askyesno(
            "Confirm Decryption",
            f"This will DECRYPT the original file:\n\n{self.selected_file}\n\nProceed?"
        ):
            return

        try:
            self.set_status("Decrypting...")
            decrypt_file_inplace(self.selected_file, password)
            messagebox.showinfo("Success", "File decrypted successfully")
            self.set_status("Decryption completed")
        except Exception:
            messagebox.showerror(
                "Error",
                "Decryption failed.\nWrong password or file not encrypted."
            )
            self.set_status("Decryption failed")

    def toggle_password(self):
        self.password_entry.config(
            show="" if self.show_password.get() else "*"
        )
