"""
main.py
-------
Application entry point.
"""

import tkinter as tk
from gui import FileEncrypterGUI


def main():
    root = tk.Tk()
    FileEncrypterGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
