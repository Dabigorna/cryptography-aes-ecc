import socket
import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def start_client(secret_msg="Dabigorna's highly confidential secret!"):
    # socket config
    HOST = "127.0.0.1"
    PORT = 65432

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        client.connect((HOST, PORT))
        print("[CLIENT] Connected to server.")

        # Get server public key
        server_key_bytes = client.recv(4096)
        pub_key_server = serialization.load_pem_public_key(server_key_bytes)
        print("[CLIENT] Server public key received successfully.")

        # Client ephemeral keys
        privkey_client = ec.generate_private_key(ec.SECP256K1())
        
        # Exporting client public key as PEM to avoid any version issues
        pub_client_bytes = privkey_client.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # ECDH and key derivation
        shared_secret = privkey_client.exchange(ec.ECDH(), pub_key_server)
        digest = hashes.Hash(hashes.SHA256())
        digest.update(shared_secret)
        aes_key = digest.finalize()

        # Encrypting text
        nonce = os.urandom(12)
        aesgcm = AESGCM(aes_key)
        textC = aesgcm.encrypt(nonce, secret_msg.encode('utf-8'), None)

        # Print da mensagem criptografada antes de enviar
        print(f"[CLIENT] Cryptogram generated (Hex): {textC.hex()}")

        # Sending data package
        print("[CLIENT] Encrypting and sending data...")
        client.sendall(len(pub_client_bytes).to_bytes(4, byteorder='big'))
        client.sendall(pub_client_bytes)
        client.sendall(nonce)
        client.sendall(textC)
        
        print("[CLIENT] Encrypted data sent successfully!")

    except Exception as e:
        print(f"[ERROR] Client failure: {e}")
    finally:
        client.close()
        print("[CLIENT] Connection closed.")

if __name__ == "__main__":
    start_client()