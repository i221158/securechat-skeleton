# SecureChat – Assignment #2 (CS-3002 Information Security, Fall 2025)

This repository is the **official code skeleton** for your Assignment #2.
You will build a **console-based, PKI-enabled Secure Chat System** in **Python**, demonstrating how cryptographic primitives combine to achieve:

**Confidentiality, Integrity, Authenticity, and Non-Repudiation (CIANR)**.

## 🧩 Overview

You are provided only with the **project skeleton and file hierarchy**.
Each file contains docstrings and `TODO` markers describing what to implement.

Your task is to:
- Implement the **application-layer protocol**.
- Integrate cryptographic primitives correctly to satisfy the assignment spec.
- Produce evidence of security properties via Wireshark, replay/tamper tests, and signed session receipts.

## 🏗️ Folder Structure
```
securechat-skeleton/ 
├─ app/ 
│ ├─ client.py # Client workflow (plain TCP, no TLS) 
│ ├─ server.py # Server workflow (plain TCP, no TLS) 
│ ├─ chat.py # Handles the multi-threaded chat session 
│ ├─ crypto/ 
│ │ ├─ aes.py # AES-128(ECB)+PKCS#7 
│ │ ├─ dh.py # Classic DH helpers + key derivation │ │ ├─ pki.py # X.509 validation (CA signature, validity, CN) 
│ │ └─ sign.py # RSA SHA-256 sign/verify (PKCS#1 v1.5) 
│ ├─ common/ 
│ │ ├─ protocol.py # Pydantic message models (hello/login/msg/receipt) 
│ │ └─ utils.py # Helpers (base64, now_ms, sha256_hex) 
│ └─ storage/ 
│ ├─ db.py # MySQL user store (salted SHA-256 passwords) 
│ └─ transcript.py # Append-only transcript + transcript hash 
├─ scripts/ 
│ ├─ gen_ca.py # Create Root CA (RSA + self-signed X.509) 
│ └─ gen_cert.py # Issue client/server certs signed by Root CA 
├─ certs/ # Local certs/keys (gitignored) 
├─ logs/ # Session logs (gitignored) 
├─ .gitignore # Ignore secrets, binaries, logs, and certs 
├─ requirements.txt # Minimal dependencies 
└─ verify_transcript.py # Offline script to verify session receipts
```

## ⚙️ Setup Instructions

This implementation was built and tested on macOS using Homebrew for MySQL.

1.  **Fork this repository** to your own GitHub account.

2.  **Set up the Python environment**:
    ```bash
    # Create and activate a virtual environment
    python3 -m venv venv
    source venv/bin/activate

    # Create your requirements.txt file
    echo "cryptography" > requirements.txt
    echo "pydantic" >> requirements.txt
    echo "mysql-connector-python" >> requirements.txt

    # Install dependencies
    pip install -r requirements.txt
    ```

3.  **Initialize MySQL** (using Homebrew on macOS):
    ```bash
    # Install and start MySQL
    brew install mysql
    brew services start mysql

    # Log in to the MySQL shell
    mysql -u root
    ```

4.  **Create tables** (inside the `mysql>` prompt):
    ```sql
    -- Create the database
    CREATE DATABASE securechat_db;

    -- Select the database
    USE securechat_db;

    -- Create the users table
    CREATE TABLE users (
        email VARCHAR(255),
        username VARCHAR(255) UNIQUE,
        salt VARBINARY(16),
        pwd_hash CHAR(64)
    );

    -- Exit MySQL
    exit
    ```

5.  **Generate certificates**:
    ```bash
    # Create the root Certificate Authority
    python scripts/gen_ca.py

    # Create the server and client certificates
    python scripts/gen_cert.py
    ```

6.  **Create the `.gitignore` file** to prevent committing secrets:
    ```bash
    echo "
    venv/
    __pycache__/
    *.db
    .env
    certs/
    logs/
    " > .gitignore
    ```

## 🚀 How to Run

1.  **Run the server** (from the project root):
    ```bash
    # In Terminal 1
    python -m app.server
    ```

2.  **Run the client** (from the project root):
    ```bash
    # In Terminal 2
    python -m app.client
    ```

3.  Follow the client prompts to **(r)egister** a new user, then run again to **(l)ogin**.

4.  After logging in, the chat will start. Send messages. Type `quit` to exit cleanly and exchange session receipts.

## 🧪 Test Evidence Checklist

✔ **Wireshark capture (encrypted payloads only)**
  * **How:** Captured on `Loopback: lo0` with filter `tcp.port == 12345`.
  * **Result:** All application-layer packets after the initial (plaintext) certificate exchange are shown as unreadable, encrypted JSON payloads.

✔ **Invalid/self-signed cert rejected (`BAD_CERT`)**
  * **How:** The `app/crypto/pki.py` module's `validate_certificate` function performs three checks:
        1.  Verifies the signature against our loaded `ca.crt` (preventing self-signed certs).
        2.  Checks the `not_valid_before` and `not_valid_after` timestamps.
        3.  Checks the `COMMON_NAME` (e.g., must be "localhost" for the server).
  * **Result:** A failure on any check raises an exception, which causes the client/server to terminate the connection.

✔ **Tamper test → signature verification fails (`SIG_FAIL`)**
  * **How:** The `app/chat.py` module's `_verify_message` function re-computes the hash `h = SHA256(seqno || ts || ct)` for every received message.
  * **Result:** It then calls `sign.verify()` to check the RSA signature against this hash. Any tampering of the message (even one bit) will cause the hash to change and the signature verification to fail.

✔ **Replay test → rejected by seqno (`REPLAY`)**
  * **How:** The `ChatSession` class in `app/chat.py` maintains a `self.recv_seqno` counter for the session.
  * **Result:** Before verifying any message, it checks `if msg.seqno <= self.recv_seqno:`. If a message with an old or repeated sequence number is received, it is discarded, and an exception is raised.

✔ **Non-repudiation → exported transcript + signed SessionReceipt verified offline**
  * **How:**
        1.  `app/storage/transcript.py` logs every verified sent/received message to an append-only file.
        2.  Upon `quit`, `chat.py` computes a `SHA256` hash of the entire transcript (`get_transcript_hash`).
        3.  This hash is signed with the user's private key (`generate_receipt`) and sent to the peer.
  * **Result:** The included `verify_transcript.py` script provides offline verifiability. It takes a log file, the peer's certificate, and the peer's receipt, then confirms that the signature matches the log file's hash, proving the log is authentic.