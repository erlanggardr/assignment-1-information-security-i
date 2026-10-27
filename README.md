# Assignment 1 - Information Security

A Django web application demonstrating symmetric encryption (AES, DES, RC4) and cipher performance benchmarking for secure file and personal data storage.

## Features

- **Symmetric Ciphers:** AES-256-CBC, DES-CBC, and RC4 with authenticated envelopes (Encrypt-then-MAC).
- **Multi-Cipher Sealing:** Stores encrypted copies using all three ciphers alongside keyed integrity digests.
- **Key Management:** Password-derived KEK protecting Master User Keys (MUK) and per-object data keys.
- **In-Memory Session Keyring:** Unlocked master keys remain in server memory during active sessions.
- **Web Interface:**
  - User authentication (sign up, log in, password change).
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

Open http://127.0.0.1:8000 in your browser, register a new account, and access the **Encrypt Demo** and **Benchmark** pages in the navigation bar.

## Running Tests

Run the automated test suite with:
```bash
python manage.py test
```
