# cryptography-aes-ecc



[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-archlinux%20%7C%20linux-lightgrey.svg)](https://archlinux.org/)

I built this project to implement a secure, hybrid cryptographic system using Python Sockets and the `cryptography` library. It combines asymmetric encryption (**ECC**) for secure key sharing with symmetric encryption (**AES-GCM**) for fast data transmission.

---

## How the Code Works

Instead of using a hardcoded static key, the code establishes a dynamic session key using the following pipeline:

1. **ECC Key Exchange:** The server and client generate ephemeral private/public keys using the `secp256k1` curve and exchange their public keys over the socket.
2. **ECDH Shared Secret:** Both sides perform an **ECDH** (Elliptic Curve Diffie-Hellman) exchange. This math allows both components to derive the exact same shared secret independently without ever sending it over the network.
3. **Key Derivation:** The shared secret is hashed using **SHA-256** to generate a secure, clean 32-byte symmetric key.
4. **AES-GCM Encryption:** The client generates a random 12-byte nonce, encrypts the payload using **AES-GCM** (which ensures both confidentiality and data integrity), and sends it. The server receives the package and decrypts it using the same derived key.

---

##  Project Structure

* `main.py` — The entry point. It handles multi-threading to run the server and client simultaneously.
* `server_service.py` — Sets up the server socket, shares its public key, performs the key exchange, and decrypts the incoming hex payload.
* `client_handler.py` — Connects to the server, reads the server's key, derives the symmetric key, encrypts the message, and transmits the payload.

---

## How to Run

### Dependencies
Make sure you have the `cryptography` library installed:

```bash
pip install cryptography

Execution

Just run the main script to see the handshake and the encrypted payload in real-time:
Bash

python main.py

Expected Terminal Output

When you run the project, the components will log their exact step-by-step handshake, displaying the raw cryptogram in Hexadecimal format right before it gets successfully decrypted:
Plaintext

==================================================
!!!STARTING HYBRID CRYPTOSYSTEM (AES + ECC)!!!
==================================================

Server starting and generating ECC keys (Secp)
Server waiting for conection: 127.0.0.1:65432
C: Connected to server.
S: Sending ECC public key to client...
S: Receiving encrypted data from client...
[C: Server public key received successfully.
C: Cryptogram generated (Hex): 4b6f790a1e3f8b... - the hash has over 92 caracteres
C: Encrypting and sending data...
C: Encrypted data sent successfully!
S: Cryptogram received (Hex): 4b6f790a1e3f8b...

========================================
[SUCCESS] Decrypted secret message: This repo owner is very clever
========================================

C: Connection closed.
S: Connection closed.

M: Done!
