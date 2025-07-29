# cracker.py

import hashlib
import time
from tqdm import tqdm
import bcrypt
import argparse
import itertools
import string
import threading
import queue
from colorama import Fore, Style

# Guess algorithm based on hash format
def guess_hash_algorithm(hash_str):
    if hash_str.startswith("$2a$") or hash_str.startswith("$2b$"):
        return "bcrypt"
    elif hash_str.startswith("$argon2"):
        return "argon2"
    elif len(hash_str) == 32:
        return "md5"
    elif len(hash_str) == 40:
        return "sha1"
    elif len(hash_str) == 64:
        return "sha256"
    elif len(hash_str) == 128:
        return "sha512"
    else:
        return "unknown"

# Hash a word using the specified algorithm
def hash_word(word, algorithm, original_hash=None):
    word_bytes = word.encode()

    try:
        if algorithm == "md5":
            return hashlib.md5(word_bytes).hexdigest()
        elif algorithm == "sha1":
            return hashlib.sha1(word_bytes).hexdigest()
        elif algorithm == "sha256":
            return hashlib.sha256(word_bytes).hexdigest()
        elif algorithm == "sha512":
            return hashlib.sha512(word_bytes).hexdigest()
        elif algorithm == "sha3_256":
            return hashlib.sha3_256(word_bytes).hexdigest()
        elif algorithm == "sha3_512":
            return hashlib.sha3_512(word_bytes).hexdigest()
        elif algorithm == "ntlm":
            return hashlib.new('md4', word_bytes.decode('utf-8').encode('utf-16le')).hexdigest()
        elif algorithm == "bcrypt":
            return bcrypt.checkpw(word_bytes, original_hash.encode())
        else:
            return None
    except Exception as e:
        print(Fore.RED + f"[!] Error hashing word: {word} ({e})" + Style.RESET_ALL)
        return None

def load_wordlist(path):
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            return [line.strip() for line in f]
    except FileNotFoundError:
        print(Fore.RED + f"[!] Wordlist file '{path}' not found." + Style.RESET_ALL)
        return []

# Brute-force engine (multi-threaded)
def brute_force_crack(target_hash, algorithm, max_len=4, charset=string.ascii_lowercase + string.digits, threads=4):
    print(Fore.CYAN + "[*] Brute-force enabled. Attempting character combinations..." + Style.RESET_ALL)
    found = threading.Event()
    result = [None]
    q = queue.Queue()

    def worker():
        while not found.is_set():
            try:
                guess = q.get_nowait()
            except queue.Empty:
                return
            if algorithm == "bcrypt":
                if hash_word(guess, algorithm, target_hash):
                    result[0] = guess
                    found.set()
            else:
                hashed = hash_word(guess, algorithm)
                if hashed == target_hash.lower():
                    result[0] = guess
                    found.set()

    # Generate all combinations
    for length in range(1, max_len + 1):
        for combo in itertools.product(charset, repeat=length):
            q.put(''.join(combo))

    threads_list = []
    for _ in range(threads):
        t = threading.Thread(target=worker)
        t.start()
        threads_list.append(t)

    for t in threads_list:
        t.join()

    return result[0]

# Crack a single hash
def crack_hash(target_hash, wordlist_path, forced_algorithm=None, brute_force=False):
    algorithm = forced_algorithm or guess_hash_algorithm(target_hash)

    if algorithm == "unknown":
        print(Fore.YELLOW + "[!] Unknown or unsupported hash type. Try using --algo to force one." + Style.RESET_ALL)
        return None

    print(Fore.CYAN + f"[*] Cracking using {algorithm.upper()}..." + Style.RESET_ALL)
    wordlist = load_wordlist(wordlist_path)

    for word in wordlist:
        try:
            if algorithm == "bcrypt":
                if hash_word(word, algorithm, target_hash):
                    print(Fore.GREEN + f"[+] Password found: {word}" + Style.RESET_ALL)
                    return word
            else:
                hashed = hash_word(word, algorithm)
                if hashed == target_hash.lower():
                    print(Fore.GREEN + f"[+] Password found: {word}" + Style.RESET_ALL)
                    return word
        except Exception as e:
            print(Fore.RED + f"[!] Error testing word '{word}': {e}" + Style.RESET_ALL)

    if brute_force:
        brute = brute_force_crack(target_hash, algorithm)
        if brute:
            print(Fore.GREEN + f"[+] Password found (brute-force): {brute}" + Style.RESET_ALL)
            return brute

    print(Fore.RED + "[-] Password not found." + Style.RESET_ALL)
    return None

# Crack multiple hashes from a file
def batch_crack(hash_file_path, wordlist_path, forced_algorithm=None, brute_force=False):
    try:
        with open(hash_file_path, 'r', encoding='utf-8') as f:
            hashes = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(Fore.RED + f"[!] Could not read hash file: {e}" + Style.RESET_ALL)
        return

    for h in hashes:
        print(Style.BRIGHT + f"\n[>] Cracking hash: {h}" + Style.RESET_ALL)
        crack_hash(h, wordlist_path, forced_algorithm, brute_force)

# CLI entrypoint
def main():
    parser = argparse.ArgumentParser(description="Smart Password Hash Cracker")
    parser.add_argument("hash", help="Hash or path to file containing hashes (batch mode)")
    parser.add_argument("wordlist", help="Path to wordlist file")
    parser.add_argument("--algo", help="Force hash algorithm (e.g., md5, sha256, ntlm, bcrypt)")
    parser.add_argument("--brute", action="store_true", help="Enable brute-force fallback")
    parser.add_argument("--batch", action="store_true", help="Indicate the hash input is a file of hashes")

    args = parser.parse_args()

    if args.batch:
        batch_crack(args.hash, args.wordlist, args.algo, args.brute)
    else:
        crack_hash(args.hash, args.wordlist, args.algo, args.brute)

if __name__ == "__main__":
    main()
