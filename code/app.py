import os
import ctypes
import tkinter as tk
from tkinter import messagebox

SANITIZER_PATH = r"C:\Users\sanya\Desktop\SIH-WannaBeNerdsRepo\sanitizer.exe"

def run_windows_code():
    try:
        # Request elevation (UAC popup will appear)
        ret = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", SANITIZER_PATH, None, os.path.dirname(SANITIZER_PATH), 1
        )
        if ret <= 32:
            messagebox.showerror(
                "Error",
                "Failed to launch sanitizer.exe with admin rights."
            )
            return

        messagebox.showinfo(
            "Sanitizer",
            "Sanitizer launched with Administrator rights.\n"
            "Follow the console window to complete the process."
        )

    except Exception as e:
        messagebox.showerror("Error", f"Failed to run sanitizer.exe\n{e}")

# GUI window for testing
root = tk.Tk()
root.withdraw()  # hide empty main window
run_windows_code()
