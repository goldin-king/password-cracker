# 🔐 Password Cracker (CLI + GUI)

A powerful, extensible password hash cracker with CLI and GUI support. Built for ethical security auditing, penetration testing, and training in controlled environments.

---

## 🚀 Features

- ✅ Supports multiple hash algorithms: `MD5`, `SHA-1`, `SHA-256`, `SHA-512`, `SHA-3`, `NTLM`, `bcrypt`
- ✅ Wordlist + Brute-force mode (multi-threaded)
- ✅ GUI (Tkinter + ttk widgets)
- ✅ CLI support using `argparse`
- ✅ Batch mode: crack multiple hashes from a file
- ✅ Progress bars & time tracking with `tqdm`
- ✅ Easy to extend and customize

---

## 📦 Installation

```bash
git clone https://github.com/yourusername/password-cracker.git
cd password-cracker
pip install -r requirements.txt

    Note: Use Python 3.6+

🧰 Usage
🔧 CLI Mode

python3 cracker.py <hash> <wordlist> --algo <algorithm> [--brute]

Examples:

python3 cracker.py 5ebe2294ecd0e0f08eab7690d2a6ee69 wordlist.txt --algo md5
python3 cracker.py hashes.txt wordlist.txt --batch --brute

🖥 GUI Mode

python3 gui.py

    Select hash type

    Provide a wordlist

    Toggle brute-force mode

    Get real-time results and progress

🔍 Supported Algorithms
Algorithm	Notes
MD5	Fast, weak
SHA-1	Weak (deprecated)
SHA-256	Stronger than SHA-1
SHA-512	High-entropy
SHA3-256/512	Modern cryptographic family
NTLM	Used in legacy Windows systems
bcrypt	Slow, secure (salted)
🧪 Ethical Use Only

This tool is intended for educational and ethical testing purposes only.

Do not use it without explicit permission or on systems you do not own.
📄 License

MIT License
🤝 Contributing

Contributions are welcome! Open issues or pull requests for improvements, bug fixes, or new features.
🧠 Credits

Developed by [Your Name]
Tested on Kali Linux, Ubuntu, and Windows (Python 3)
💡 Sample Wordlist

A simple example:

123456
password
admin
letmein
secret
qwerty

Use larger lists like SecLists for real testing.
