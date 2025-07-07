# CIPHERLOCK
# 🔐 CIPHERLOCKS v5 – Secure File Encryption Tool

**CIPHERLOCKS v5** is a robust file encryption/decryption application designed for security-conscious users. It features a sleek GUI, high-grade encryption, secure memory handling, and unique protections like device-bound transfer restrictions and auto-destruction on repeated access failure.

It is available open-source and in complied .exe version.
---

## 🧰 Features

- **AES-GCM Encryption**: Utilizes authenticated encryption to ensure confidentiality and integrity.
- **System-bound Transfers**: Encrypted files can be locked to a specific device using a unique system ID.
- **Randomized Filenames**: Optionally obfuscate output files with randomized names.
- **Auto Destruction**: Files can be set to self-destruct after a configurable number of failed decryption attempts.
- **Metadata Protection**: Metadata is encrypted and authenticated to avoid tampering.
- **Secure Delete**: Optionally overwrite and remove the original file after encryption.
- **User-Friendly GUI**: Built with `Tkinter` and `ttkthemes` for a modern dark-mode interface.
- **Clipboard Support**: Quickly copy system ID via GUI for secure transfers.

---

## 🔐 Security Features

- **Scrypt Key Derivation**: Passwords are strengthened using the Scrypt KDF, protecting against brute-force attacks.
- **Memory Sanitization**: Sensitive data like passwords and keys are wiped from memory after use.
- **Secure Randomness**: Uses `os.urandom` and `SystemRandom` for cryptographically secure generation of salts, nonces, and filenames.
- **File Hiding**: Automatically hides system ID file on supported platforms.
- **GCM Mode**: Ensures both encryption and verification using AES in Galois/Counter Mode.

---

## 🚀 Installation

The fastest way to launch that is to download or copy repository and launch CIPHERLOCK.exe file. Additionally, you can use open-source version:


1. Clone or download this repository (git clone https://github.com/vertosolutions/CIPHERLOCK)
2. Install dependencies:

pip install -r requirements.txt

Done!

Enjoy you secure file. Made with love by Verto Solutions

DO NOT REPRODUCE WITHOUT PERMISSION. THIS IS AN INTELLCTUAL PROPERTY OF https://github.com/vertosolutions
