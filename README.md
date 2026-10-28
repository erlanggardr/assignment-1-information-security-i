# Assignment 1 - Information Security

FinSecure is a small online-loan (pinjol) app built with Django. A borrower has to finish e-KYC before asking for a loan: personal details, an ID card (KTP) photo, proof of income (PDF/DOC/XLS) and a selfie video with a liveness check. All of it is stored encrypted with AES, DES and RC4, and only the owner can read it back.

## Scenario

A lender collects the ID card, the face and the income of each borrower in one place. If the database leaks, an attacker can apply for loans in someone else's name, so the stored data must be unreadable without the owner's password. There is one role, the borrower. Nobody else, including an admin, can open the data, so a forgotten password means the data is lost.

The loan itself is only an amount and a purpose (no term, interest or scoring). It unlocks once all four KYC steps are done, one request per user.

## Features

- **Ciphers:** AES-256-CBC, DES-CBC and RC4, each with Encrypt-then-MAC (HMAC-SHA256). RC4 gets a fresh per-message key from a random nonce and drops the first 3072 keystream bytes.
- **Three copies per item:** personal data, ID card, documents and video are each stored once per cipher, with a keyed digest of the plaintext. Small copies live in the database row, large ones on disk under random UUID names. File names and MIME types are encrypted too.
- **Keys:** password -> PBKDF2 key (KEK) -> per-user master key -> per-item data key -> subkeys for each cipher and the MAC. Unlocked keys stay in server memory for the session.
- **Owner-only access:** queries are filtered by user, other users get a 404, and every download is verified (HMAC and plaintext digest) before it is returned. Items can be downloaded with a chosen cipher and deleted.
- **Liveness video:** the camera opens as soon as the video step loads and the user follows one random instruction (see below).
- **Benchmark:** a page and a management command that compare the three ciphers (repeated downloads, ciphertext differences, size overhead).

## Project structure

- `vault/` - encryption engine, key hierarchy, keyring, storage, liveness check, benchmarks
- `accounts/` - user registration, authentication, custom user model
- `pages/` - home and about pages
- `django_project/` - settings, URLs, WSGI/ASGI

## Setup

Requires Python 3.12+.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python manage.py migrate
python manage.py runserver
```

Open http://127.0.0.1:8000, sign up, and follow **My application**. Encrypted files are written to `vault_data/` (git-ignored).

## Liveness check

The server picks one instruction at random (smile, surprise, turn left or right, blink). The browser records about 7 seconds of video, the server decodes frames from that same video, and the video is stored only if the instruction is detected. Frames stay in memory and are never written to disk. A challenge works once and expires after two minutes, and a user gets 10 attempts per hour.

The models come from [manhcuong02/eKYC](https://github.com/manhcuong02/eKYC) (MTCNN, emotion, face orientation and blink detection). That repo is a desktop app, so only its model classes are imported. The server-side checking logic is adapted from a Django port of it.

```bash
git clone https://github.com/manhcuong02/eKYC vendor/ekyc
pip install --index-url https://download.pytorch.org/whl/cpu torch==2.5.1 torchvision==0.20.1
pip install -r requirements-liveness.txt
python manage.py runserver
```

- The check is on when `vendor/ekyc` exists (or the path in `EKYC_PATH`). `LIVENESS_ENGINE=off` turns it off and the video step becomes a normal file upload.
- The clone already contains the weights this check uses. The first check loads the models, so it is slower.
- Browsers only allow the camera on `localhost` or HTTPS.

### Trying it on a phone

The camera needs HTTPS, so serve it with a self-signed certificate:

```bash
mkdir -p certs
openssl req -x509 -newkey rsa:2048 -nodes -days 30 -keyout certs/key.pem -out certs/cert.pem \
  -subj "/CN=<laptop-ip>" -addext "subjectAltName=IP:<laptop-ip>"

DJANGO_ALLOWED_HOSTS=<laptop-ip> DJANGO_CSRF_TRUSTED_ORIGINS=https://<laptop-ip>:8443 \
gunicorn django_project.wsgi -b 0.0.0.0:8443 \
  --certfile certs/cert.pem --keyfile certs/key.pem \
  --workers 1 --worker-class gthread --threads 8 --timeout 120
```

Open `https://<laptop-ip>:8443` on a phone on the same Wi-Fi and accept the certificate warning. Use a single worker, because the session keys live in the memory of one process. Allow port 8443 in the laptop firewall.

### Limits

- Liveness is a 2D challenge-response check. A replayed video or a deepfake can pass it, and there is no face match against the ID card.
- The eKYC repo has no license file, so check its terms before using it beyond this assignment.

## Tests and benchmark

```bash
python manage.py test
python manage.py benchmark_vault   # results go to bench_out/
```

The tests run without torch (the liveness engine is stubbed). Benchmark numbers depend on the machine, so run it on your own.


## Other links or AI Chat we use:
- https://claude.ai/share/9ef6f9cb-3048-467f-a655-f82bba41020f
- https://claude.ai/share/a8ecbb9a-b0ef-46e1-b1b8-36ad6642676b
- https://github.com/manhcuong02/eKYC
