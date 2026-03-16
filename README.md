# Cipherlocks

Cipherlocks is a professional-grade desktop encryption suite with a PySide6 GUI, hardened crypto workflow, and LAN-bound key-share support for anti-espionage file protection.

## What changed

- Migrated GUI from Tkinter to **PySide6** for a modern cross-platform desktop experience.
- Refactored from one script into dedicated modules for security, crypto, GUI, identity, and LAN services.
- Replaced system-bound transfer mode with **LAN-bound decryption policy**.
- Added **GitHub Actions** matrix build for Windows, macOS, and Linux, including a Linux AppImage artifact.

## Project structure

- `main.py`: desktop entry point.
- `cipherlock/gui.py`: PySide6 user interface.
- `cipherlock/crypto.py`: encryption/decryption engine and key derivation.
- `cipherlock/network_client.py`: client integration with LAN key-share service.
- `cipherlock/lan_server.py`: internal key-share service (Tang/Clevis-inspired share provider).
- `cipherlock/security.py`: secure wiping and secure delete helpers.
- `cipherlock/system_identity.py`: stable local system identity generation.
- `.github/workflows/build.yml`: cross-platform build pipeline.

## LAN-only access model (corporate use)

When **Require LAN key-share server** is enabled during encryption:

1. Client derives base key context from password + local system identity.
2. Client requests a network key share from LAN server.
3. Final key context includes password + system identity + network share component.
4. Decryption requires reaching the LAN key server; stolen offline files remain unusable.

### Server hardening notes

For production deployment:

- Bind `uvicorn` to an internal interface only.
- Place server in an isolated VLAN.
- Enforce mTLS at reverse proxy or ingress.
- Block WAN routes to the key-share port.

## Run locally

```bash
pip install -r requirements.txt
python main.py
```

### Optional: run LAN key-share server

```bash
export CIPHERLOCK_SERVER_MASTER_KEY="change-me"
uvicorn cipherlock.lan_server:app --host 192.168.10.20 --port 8443 --ssl-keyfile key.pem --ssl-certfile cert.pem
```

## Build artifacts

Local build:

```bash
pyinstaller --noconfirm --windowed --name cipherlocks main.py
```

CI build (GitHub Actions) produces:

- Windows: `.exe`
- macOS: `.app`
- Linux: AppImage
