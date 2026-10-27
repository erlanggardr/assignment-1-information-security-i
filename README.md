# Assignment 1 - Information Security

A Django web application demonstrating symmetric encryption (AES, DES, RC4) and cipher performance benchmarking for secure file and personal data storage.

## Features

- **Symmetric Ciphers:** AES-256-CBC, DES-CBC, and RC4 with authenticated envelopes (Encrypt-then-MAC).
- **Multi-Cipher Sealing:** Stores encrypted copies using all three ciphers alongside keyed integrity digests.
- **Key Management:** Password-derived KEK protecting Master User Keys (MUK) and per-object data keys.
- **In-Memory Session Keyring:** Unlocked master keys remain in server memory during active sessions.
- **Encrypted Storage:** Personal data (database), ID card images, office documents (PDF/DOC/XLS) and videos are each stored as three ciphertext copies (AES, DES, RC4). Small copies live in the database row, large ones on disk under opaque UUID names; file names and MIME types are encrypted too. Only the owner can download an item, and every download is verified (HMAC tag plus keyed plaintext digest).
- **Web Interface:**
  - User authentication (sign up, log in, password change).
  - Vault dashboard, personal data form, and upload pages for ID card, office document and video; download with a choice of cipher.
  - Encrypt demo page for testing text and file encryption.
  - Benchmark page comparing speed, throughput, and overhead across ciphers.

## Project Structure

- `vault/` - Core encryption engine, key hierarchy, keyring, and benchmark utilities.
- `accounts/` - User registration, authentication, and custom user model.
- `pages/` - Basic template views (home, about).
- `django_project/` - Project settings, URLs, and WSGI/ASGI configuration.

## Requirements & Setup

Requires Python 3.12+.

1. **Create and activate a virtual environment:**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run database migrations:**
   ```bash
   python manage.py migrate
   ```

4. **Start the development server:**
   ```bash
   python manage.py runserver
   ```

Open http://127.0.0.1:8000 in your browser, register a new account, and use **My vault** to store and retrieve your data. The **Encrypt Demo** and **Benchmark** pages are in the navigation bar. Encrypted files are written to `vault_data/` (git-ignored).

## Running Tests

Run the automated test suite with:
```bash
python manage.py test
```
