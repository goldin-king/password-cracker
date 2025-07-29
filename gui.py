import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from cracker import crack_hash, guess_hash_algorithm
import os

def browse_wordlist():
    path = filedialog.askopenfilename(title="Select Wordlist File")
    wordlist_entry.delete(0, tk.END)
    wordlist_entry.insert(0, path)

def browse_hash_file():
    path = filedialog.askopenfilename(title="Select Hash File (optional)")
    hash_entry.delete(0, tk.END)
    hash_entry.insert(0, path)

def start_crack():
    hash_input = hash_entry.get().strip()
    wordlist = wordlist_entry.get().strip()
    algo = algo_entry.get().strip().lower()
    use_brute = brute_var.get()

    if not wordlist:
        messagebox.showerror("Missing", "Please select a wordlist.")
        return

    output_box.config(state='normal')
    output_box.delete(1.0, tk.END)

    hashes = []
    if os.path.isfile(hash_input):
        with open(hash_input) as f:
            hashes = [line.strip() for line in f if line.strip()]
    else:
        hashes = [hash_input]

    for h in hashes:
        hash_algo = algo or guess_hash_algorithm(h)
        output_box.insert(tk.END, f"\nCracking hash: {h} ({hash_algo})...\n")
        result = crack_hash(h, wordlist, hash_algo, brute_force=use_brute)
        if result:
            output_box.insert(tk.END, f"[+] Found: {result}\n")
        else:
            output_box.insert(tk.END, "[-] Not found\n")

    output_box.config(state='disabled')

# --- GUI Setup ---
root = tk.Tk()
root.title("Password Cracker GUI")

style = ttk.Style()
style.theme_use('clam')  # or try: 'alt', 'vista', 'xpnative'

main_frame = ttk.Frame(root, padding="10")
main_frame.grid(row=0, column=0)

ttk.Label(main_frame, text="Hash or file:").grid(row=0, column=0, sticky="e")
hash_entry = ttk.Entry(main_frame, width=50)
hash_entry.grid(row=0, column=1, padx=5, pady=5)
ttk.Button(main_frame, text="Browse", command=browse_hash_file).grid(row=0, column=2)

ttk.Label(main_frame, text="Wordlist:").grid(row=1, column=0, sticky="e")
wordlist_entry = ttk.Entry(main_frame, width=50)
wordlist_entry.grid(row=1, column=1, padx=5, pady=5)
ttk.Button(main_frame, text="Browse", command=browse_wordlist).grid(row=1, column=2)

ttk.Label(main_frame, text="Algorithm (optional):").grid(row=2, column=0, sticky="e")
algo_entry = ttk.Entry(main_frame, width=30)
algo_entry.grid(row=2, column=1, sticky="w", padx=5)

brute_var = tk.BooleanVar()
ttk.Checkbutton(main_frame, text="Enable brute-force fallback", variable=brute_var).grid(row=3, column=1, sticky="w", pady=5)

ttk.Button(main_frame, text="Start Cracking", command=start_crack).grid(row=4, column=1, pady=10)

output_box = tk.Text(main_frame, height=15, width=70, state='disabled', bg="#111", fg="#0f0", font=("Consolas", 10))
output_box.grid(row=5, column=0, columnspan=3, padx=10, pady=10)

root.mainloop()
