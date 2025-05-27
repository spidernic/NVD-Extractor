import os
import sys
import subprocess
import tkinter as tk
from tkinter import ttk, messagebox


def run_extraction():
    days = int(days_var.get())
    attack_vector = attack_var.get()
    severity = severity_var.get()
    output_fmt = format_var.get()

    env = os.environ.copy()
    env["CVE_AGE_DAYS"] = str(days)
    env["ATTACK_VECTOR"] = attack_vector
    env["SEVERITY"] = severity
    env["OUTPUT_FORMAT"] = output_fmt

    script_path = os.path.join(os.path.dirname(__file__), "nvd_extraction_v1.py")
    subprocess.run([sys.executable, script_path], env=env)
    messagebox.showinfo("NVD Extractor", "Extraction completed successfully!")


root = tk.Tk()
root.title("NVD Extractor")

# Age selection
tk.Label(root, text="CVE Age (days)").grid(row=0, column=0, sticky="w")
days_var = tk.IntVar(value=360)
spin = tk.Spinbox(root, from_=0, to=360, textvariable=days_var, width=10)
spin.grid(row=0, column=1, padx=5, pady=5)

# Attack vector
tk.Label(root, text="Attack Vector").grid(row=1, column=0, sticky="w")
attack_var = tk.StringVar(value="NETWORK")
attack_options = ["NETWORK", "ADJACENT_NETWORK", "LOCAL", "PHYSICAL"]
attack_menu = ttk.OptionMenu(root, attack_var, attack_var.get(), *attack_options)
attack_menu.grid(row=1, column=1, padx=5, pady=5)

# Severity
tk.Label(root, text="Severity").grid(row=2, column=0, sticky="w")
severity_var = tk.StringVar(value="CRITICAL")
severity_options = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
severity_menu = ttk.OptionMenu(root, severity_var, severity_var.get(), *severity_options)
severity_menu.grid(row=2, column=1, padx=5, pady=5)

# Output format
tk.Label(root, text="Output Format").grid(row=3, column=0, sticky="w")
format_var = tk.StringVar(value="both")
format_options = ["csv", "json", "both"]
format_menu = ttk.OptionMenu(root, format_var, format_var.get(), *format_options)
format_menu.grid(row=3, column=1, padx=5, pady=5)

# Run button
run_btn = tk.Button(root, text="Run Extraction", command=run_extraction)
run_btn.grid(row=4, column=0, columnspan=2, pady=10)

root.mainloop()
