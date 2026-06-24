# This code was made by https://github.com/Dabigorna
#S = Server

import socket
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def start_server():
    print("Server starting and generating ECC keys (Secp)")
    privkey = ec.generate_private_key(ec.SECP256K1())
    pubkey =  privkey.public_key()

    # Convert key to PEM so it can travel safely through the network
    pubkeyBytes = pubkey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    HOST = "127.0.0.1"
    PORT = 65432

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(1)
    print(f"Server waiting for conection: {HOST}:{PORT}")

    conection, adress = server.accept()

    try:
        print("S: Sending ECC public key to client...")
        conection.sendall(pubkeyBytes)
        
        print("S: Receiving encrypted data from client...")
        # First 4 bytes tell us the exact size of the client's public key
        tmp_bytes = conection.recv(4)
        if not tmp_bytes: return
        tam_client_key = int.from_bytes(tmp_bytes, byteorder='big')
        
        # Unpack everything in order: client key, 12-byte nonce, and the actual ciphertext
        pub_key_client_bytes = conection.recv(tam_client_key)
        nonce = conection.recv(12)
        textC = conection.recv(4096)

        print(f"S: Cryptogram received (Hex): {textC.hex()}")

        # Load client's key and execute ECDH to find the shared secret
        pub_key_client = serialization.load_pem_public_key(pub_key_client_bytes)
        shared_secret = privkey.exchange(ec.ECDH(), pub_key_client)
        
        # Hash the shared secret with SHA256 to get a clean 32-byte AES key
        digest = hashes.Hash(hashes.SHA256())
        digest.update(shared_secret)
        aes_key = digest.finalize()

        # Decrypt everything using AES-GCM
        aesgcm = AESGCM(aes_key)
        decrypted_msg = aesgcm.decrypt(nonce, textC, None)

        print("\n" + "="*40)
        print(f"[SUCCESS] Decrypted secret message: {decrypted_msg.decode('utf-8')}")
        print("="*40 + "\n")

    except Exception as e:
        print(f"[ERROR] Processing failed: {e}")
    finally:
        conection.close()
        server.close()
        print("S: Connection closed.")

if __name__ == "__main__":
    start_server()