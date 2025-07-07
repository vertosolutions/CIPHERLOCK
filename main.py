import os
import random
import string
import uuid
import platform
import json
import hashlib
import pyperclip
from tkinter import Tk, Label, Entry, Button, filedialog, Checkbutton, IntVar, messagebox
from tkinter.simpledialog import askstring
from tkinter import ttk
from ttkthemes import ThemedTk
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

# ======================
# SECURITY CORE
# ======================

def secure_wipe(data):
    """Securely wipe sensitive data from memory"""
    if isinstance(data, (bytearray, bytes)):
        try:
            if isinstance(data, bytes):
                data = bytearray(data)
            for i in range(len(data)):
                data[i] = 0
        except TypeError:
            pass
    return None

class SecureByteArray(bytearray):
    """Self-wiping bytearray for sensitive data"""
    def __del__(self):
        secure_wipe(self)

# ======================
# HELPER FUNCTIONS
# ======================

def hide_file(filepath):
    """OS-appropriate file hiding"""
    if platform.system() == 'Windows':
        os.system(f'attrib +h "{filepath}"')
    else:
        base = os.path.basename(filepath)
        os.rename(filepath, os.path.join(os.path.dirname(filepath), f'.{base}'))

def get_system_id():
    """Get system fingerprint with secure storage"""
    system_id_file = 'system_id.txt'
    if os.path.exists(system_id_file):
        with open(system_id_file, 'r') as f:
            return f.read().strip()
    system_id = str(uuid.getnode())
    with open(system_id_file, 'w') as f:
        f.write(system_id)
    hide_file(system_id_file)
    return system_id

def derive_key(password, salt, system_id=None):
    """Secure key derivation with memory protection"""
    if isinstance(password, str):
        password = SecureByteArray(password.encode('utf-8'))
    
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
        backend=default_backend()
    )
    key = SecureByteArray(kdf.derive(password + (system_id or '').encode()))
    secure_wipe(password)
    return key

def generate_random_string(length=64):
    """Cryptographically secure random generation"""
    return ''.join(random.SystemRandom().choices(
        string.ascii_letters + string.digits + string.punctuation,
        k=length
    ))

def generate_random_filename():
    """Unpredictable filename generation"""
    return ''.join(random.SystemRandom().choices(
        string.ascii_letters + string.digits, 
        k=12
    ))

# ======================
# CRYPTO OPERATIONS
# ======================

def encrypt_metadata(data, key):
    """Authenticated encryption for metadata"""
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce),
                   backend=default_backend())
    encryptor = cipher.encryptor()
    
    json_data = json.dumps(data).encode()
    ciphertext = encryptor.update(json_data) + encryptor.finalize()
    return nonce + ciphertext + encryptor.tag

def decrypt_metadata(encrypted_data, key):
    """Verified metadata decryption"""
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:-16]
    tag = encrypted_data[-16:]
    
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag),
                   backend=default_backend())
    decryptor = cipher.decryptor()
    
    json_data = decryptor.update(ciphertext) + decryptor.finalize()
    return json.loads(json_data.decode())

# ======================
# MAIN FUNCTIONALITY
# ======================

def encrypt_file(file_path, password, max_attempts, generate_random=False,
                delete_original=False, transfer_file=False):
    """Secure encryption pipeline"""
    plaintext = key = part1 = part2 = None
    try:
        password = SecureByteArray(password.encode()) if isinstance(password, str) else password
        
        salt = os.urandom(16)
        nonce = os.urandom(12)
        random_str = generate_random_string()
        part1 = SecureByteArray(random_str[:32].encode())
        part2 = SecureByteArray(random_str[32:].encode())

        system_id = None
        if transfer_file:
            system_id = askstring("System ID", "Enter target system ID:",
                                initialvalue=get_system_id())
            if not system_id:
                raise ValueError("System ID required for transfer files")

        with open(file_path, 'rb') as f:
            plaintext = SecureByteArray(f.read())

        key = derive_key(password, salt, system_id)
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce),
                       backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        tag = encryptor.tag

        if generate_random:
            rand_name = generate_random_filename()
            enc_file = f"{rand_name}.enc"
            info_file = f"{rand_name}.info"
        else:
            base = os.path.basename(file_path)
            enc_file = f"{base}.enc"
            info_file = f"{base}.info"

        metadata = {
            'original_name': os.path.basename(file_path),
            'transfer': transfer_file,
            'system_id': system_id,
            'part2': bytes(part2).decode('utf-8'),
            'checksum': hashlib.sha256(bytes(part1) + bytes(part2)).hexdigest()
        }
        encrypted_metadata = encrypt_metadata(metadata, key)

        with open(info_file, 'wb') as f:
            f.write(encrypted_metadata)

        attempts_bytes = max_attempts.to_bytes(4, 'big', signed=True)
        with open(enc_file, 'wb') as f:
            f.write(salt)
            f.write(nonce)
            f.write(attempts_bytes)
            f.write(part1)
            f.write(ciphertext)
            f.write(tag)

        if delete_original:
            with open(file_path, 'wb') as f:
                f.write(os.urandom(os.path.getsize(file_path)))
            os.remove(file_path)

        messagebox.showinfo("Success", f"Encrypted:\n{enc_file}")
    except Exception as e:
        messagebox.showerror("Error", f"Encryption failed: {str(e)}")
    finally:
        for var in [plaintext, key, password, part1, part2]:
            if var is not None:
                secure_wipe(var)

def decrypt_file(encrypted_path, password):
    """Secure decryption pipeline"""
    plaintext = key = part1 = part2 = None
    metadata = system_id = info_file = None
    password_bytes = None
    
    try:
        if not encrypted_path.endswith('.enc'):
            raise ValueError("Invalid encrypted file")

        with open(encrypted_path, 'rb') as f:
            salt = f.read(16)
            nonce = f.read(12)
            attempts_bytes = f.read(4)
            max_attempts = int.from_bytes(attempts_bytes, 'big', signed=True)
            part1 = SecureByteArray(f.read(32))
            
            # Fixed tag reading logic
            remaining_data = f.read()
            ciphertext = remaining_data[:-16]
            tag = remaining_data[-16:]

        if max_attempts == 0:
            os.remove(encrypted_path)
            info_file = encrypted_path[:-4] + '.info'
            if os.path.exists(info_file):
                os.remove(info_file)
            raise PermissionError("Maximum attempts reached")

        info_file = encrypted_path[:-4] + '.info'
        if not os.path.exists(info_file):
            raise FileNotFoundError("Missing info file")

        with open(info_file, 'rb') as f:
            encrypted_metadata = f.read()

        password_bytes = SecureByteArray(password.encode()) if isinstance(password, str) else password

        try:
            key = derive_key(password_bytes, salt)
            metadata = decrypt_metadata(encrypted_metadata, key)
        except (InvalidTag, ValueError):
            metadata = None

        if not metadata:
            raise ValueError("Decryption failed")

        part2 = SecureByteArray(metadata['part2'].encode('utf-8'))
        checksum = hashlib.sha256(bytes(part1) + bytes(part2)).hexdigest()
        if checksum != metadata['checksum']:
            if metadata.get('transfer', False):
                system_id = askstring("System ID", "Enter System ID:")
                if not system_id:
                    raise ValueError("System ID required")
                key = derive_key(password_bytes, salt, system_id)
                metadata = decrypt_metadata(encrypted_metadata, key)
                checksum = hashlib.sha256(bytes(part1) + bytes(part2)).hexdigest()
                if checksum != metadata['checksum']:
                    raise ValueError("Security check failed")
            else:
                raise ValueError("Security check failed")

        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag),
                       backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = SecureByteArray(decryptor.update(ciphertext) + decryptor.finalize())

        orig_name = os.path.join(os.path.dirname(encrypted_path),
                                metadata['original_name'])
        with open(orig_name, 'wb') as f:
            f.write(plaintext)

        os.remove(encrypted_path)
        os.remove(info_file)
        messagebox.showinfo("Success", f"Decrypted:\n{orig_name}")

    except Exception as e:
        try:
            if max_attempts > 0:
                max_attempts -= 1
                with open(encrypted_path, 'r+b') as f:
                    f.seek(28)  # Update attempts counter position
                    f.write(max_attempts.to_bytes(4, 'big', signed=True))
                if max_attempts == 0:
                    os.remove(encrypted_path)
                    if os.path.exists(info_file):
                        os.remove(info_file)
                    msg = "Files destroyed - max attempts"
                else:
                    msg = f"{str(e)}\nAttempts left: {max_attempts}"
            else:
                msg = "Files destroyed - max attempts"
        except Exception as update_error:
            msg = f"{str(e)} [Update failed: {update_error}]"
        
        messagebox.showerror("Error", msg)
    finally:
        for var in [plaintext, key, password_bytes, part1, part2]:
            if var is not None:
                secure_wipe(var)

# ======================
# GUI IMPLEMENTATION
# ======================

class EncryptionApp:
    def __init__(self):
        self.root = ThemedTk(theme="black")
        self.root.title("Verto Solutions CIPHERLOCKS v5")
        self.style = ttk.Style()
        self.configure_styles()
        self.create_widgets()
        self.root.configure(bg="#2b2b2b")

    def configure_styles(self):
        self.style.configure("TLabel", background="#2b2b2b", foreground="white")
        self.style.configure("TEntry", fieldbackground="#3c3c3c")
        self.style.configure("TButton", background="#1a73e8", foreground="white")
        self.style.configure("TCheckbutton", background="#2b2b2b", foreground="white")

    def create_widgets(self):
        # File Selection
        ttk.Label(self.root, text="File Path:").grid(row=0, column=0, padx=10, pady=10)
        self.file_entry = ttk.Entry(self.root, width=50)
        self.file_entry.grid(row=0, column=1, padx=10, pady=10)
        ttk.Button(self.root, text="Browse", command=self.browse_file).grid(row=0, column=2)

        # Encryption Options
        self.random_var = IntVar()
        self.delete_var = IntVar()
        self.transfer_var = IntVar()
        self.attempts_var = IntVar()

        ttk.Checkbutton(self.root, text="Random Filename", variable=self.random_var).grid(row=1, column=0)
        ttk.Checkbutton(self.root, text="Secure Delete", variable=self.delete_var).grid(row=2, column=0)
        ttk.Checkbutton(self.root, text="Transfer File", variable=self.transfer_var).grid(row=1, column=1)
        ttk.Checkbutton(self.root, text="Enable Attempt Limit", variable=self.attempts_var).grid(row=3, column=0)

        self.attempts_entry = ttk.Entry(self.root, width=5)
        self.attempts_entry.grid(row=3, column=1, sticky='w')

        # Action Buttons
        ttk.Button(self.root, text="Encrypt", command=self.encrypt_action).grid(row=4, column=0, pady=15)
        ttk.Button(self.root, text="Decrypt", command=self.decrypt_action).grid(row=4, column=2, pady=15)

        # System ID
        self.sys_id_label = ttk.Label(
            self.root, 
            text=f"System ID: {get_system_id()}", 
            cursor="hand2",
            font=('Arial', 10, 'underline')
        )
        self.sys_id_label.grid(row=5, column=1, pady=10)
        self.sys_id_label.bind("<Button-1>", self.copy_system_id)

    def copy_system_id(self, event):
        pyperclip.copy(get_system_id())
        messagebox.showinfo("Copied", "System ID copied to clipboard!")

    def browse_file(self):
        path = filedialog.askopenfilename()
        if path:
            self.file_entry.delete(0, 'end')
            self.file_entry.insert(0, path)

    def encrypt_action(self):
        path = self.file_entry.get()
        if not path:
            messagebox.showerror("Error", "Select a file first")
            return

        password = askstring("Password", "Enter encryption password:", show='*')
        if not password:
            return

        try:
            attempts = int(self.attempts_entry.get()) if self.attempts_var.get() else -1
        except ValueError:
            messagebox.showerror("Error", "Invalid attempt limit")
            return

        encrypt_file(
            path, password, attempts,
            generate_random=self.random_var.get(),
            delete_original=self.delete_var.get(),
            transfer_file=self.transfer_var.get()
        )

    def decrypt_action(self):
        path = self.file_entry.get()
        if not path:
            messagebox.showerror("Error", "Select a file first")
            return
        if not path.endswith('.enc'):
            messagebox.showerror("Error", "Select .enc file")
            return

        password = askstring("Password", "Enter decryption password:", show='*')
        if not password:
            return

        decrypt_file(path, password)

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    app = EncryptionApp()
    app.run()
