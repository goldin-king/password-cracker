# cracker.py
import hashlib
import bcrypt
import argparse
from colorama import Fore, Style

def guess_hash_algorithm(hash_str):
    if hash_str.startswith("$2a$") or hash_str.startswith("$2b$"):
        return "bcrypt"
    elif hash_str.startswith("$argon2"):
        return "argon2"
    elif len(hash_str) == 32:
        return "md5"  # or NTLM, will try both
    elif len(hash_str) == 40:
        return "sha1"
    elif len(hash_str) == 64:
        return "sha256"
    elif len(hash_str) == 128:
        return "sha512"
    else:
        return "unknown"

def hash_word(word, algorithm, original_hash=None):
    word_bytes = word.encode()

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

def load_wordlist(path):
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            return [line.strip() for line in f]
    except FileNotFoundError:
        print(Fore.RED + f"[!] Wordlist file '{path}' not found." + Style.RESET_ALL)
        return []

def crack_hash(target_hash, wordlist_path, forced_algorithm=None):
    algorithm = forced_algorithm or guess_hash_algorithm(target_hash)

    if algorithm == "unknown":
        print(Fore.YELLOW + "[!] Unknown or unsupported hash type. Try using --algo to force one." + Style.RESET_ALL)
        return

    print(Fore.CYAN + f"[*] Cracking using {algorithm.upper()}..." + Style.RESET_ALL)
    wordlist = load_wordlist(wordlist_path)

    for word in wordlist:
        try:
            if algorithm == "bcrypt":
                if hash_word(word, algorithm, target_hash):
                    print(Fore.GREEN + f"[+] Password found: {word}" + Style.RESET_ALL)
                    return word
            else:
                hashed = hash_word(word, algorithm, target_hash)
                if hashed == target_hash.lower():
                    print(Fore.GREEN + f"[+] Password found: {word}" + Style.RESET_ALL)
                    return word
        except Exception as e:
            print(Fore.RED + f"[!] Error testing word '{word}': {e}" + Style.RESET_ALL)

    print(Fore.RED + "[-] Password not found." + Style.RESET_ALL)
    return None

def main():
    parser = argparse.ArgumentParser(description="Smart Password Hash Cracker")
    parser.add_argument("hash", help="The hash value to crack")
    parser.add_argument("wordlist", help="Path to wordlist file")
    parser.add_argument("--algo", help="Force a specific hash algorithm (e.g., md5, sha1, sha256, sha512, sha3_256, sha3_512, ntlm, bcrypt)")

    args = parser.parse_args()

    crack_hash(args.hash, args.wordlist, args.algo)

if __name__ == "__main__":
    main()
