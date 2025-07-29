import tkinter as tk
from tkinter import filedialog, messagebox
from cracker import crack_hash, guess_hash_algorithm

def browse_wordlist():
    path = filedialog.askopenfilename(title="Select Wordlist File")
    wordlist_entry.delete(0, tk.END)
    wordlist_entry.insert(0, path)

def start_crack():
    hash_input = hash_entry.get().strip()
    wordlist = wordlist_entry.get().strip()
    algo = algo_entry.get().strip().lower() or guess_hash_algorithm(hash_input)

    if not hash_input or not wordlist:
        messagebox.showerror("Error", "Hash and wordlist are required.")
        return

    result = crack_hash(hash_input, wordlist, algo)
    if result:
        output_box.config(state='normal')
        output_box.insert(tk.END, f"\n[+] Cracked password: {result}")
        output_box.config(state='disabled')
    else:
        output_box.config(state='normal')
        output_box.insert(tk.END, "\n[-] Password not found.")
        output_box.config(state='disabled')

# --- GUI Setup ---
window = tk.Tk()
window.title("Password Cracker GUI")

tk.Label(window, text="Hash to crack:").grid(row=0, column=0, sticky="e")
hash_entry = tk.Entry(window, width=50)
hash_entry.grid(row=0, column=1, padx=5, pady=5)

tk.Label(window, text="Wordlist path:").grid(row=1, column=0, sticky="e")
wordlist_entry = tk.Entry(window, width=50)
wordlist_entry.grid(row=1, column=1, padx=5, pady=5)
tk.Button(window, text="Browse", command=browse_wordlist).grid(row=1, column=2, padx=5)

tk.Label(window, text="Algorithm (optional):").grid(row=2, column=0, sticky="e")
algo_entry = tk.Entry(window, width=20)
algo_entry.grid(row=2, column=1, sticky="w", padx=5)

tk.Button(window, text="Crack Password", command=start_crack, bg="green", fg="white").grid(row=3, column=1, pady=10)

output_box = tk.Text(window, height=10, width=60, state='disabled', bg="black", fg="lime")
output_box.grid(row=4, column=0, columnspan=3, padx=10, pady=5)

window.mainloop()
