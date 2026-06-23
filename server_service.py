import socket
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric.padding import ECDH
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def start_server():
    print("Server starting and generating ECC keys (Secp)")
    privkey = ec.generate_private_key(ec.SECP256K1()) # private key
    pubkey =  privkey.public_key() # public key

    # Turning the keys into bytes so it can navegate via net
    pubkeyBytes = pubkey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # socket config
    HOST = "127.0.0.1"
    PORT = 65432

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT)) # Fixed from .bin to .bind
    server.listen(1)
    print(f"Server waiting for conection: {HOST}:{PORT}")

    conection, adress = server.accept()

    try:
        # Send the server ECC public key to the client
        print("[SERVER] Sending ECC public key to client...")
        conection.sendall(pubkeyBytes)
        
        print("[SERVER] Receiving encrypted data from client...")
        
        tmp_bytes = conection.recv(4)
        if not tmp_bytes: return
        tam_client_key = int.from_bytes(tmp_bytes, byteorder='big')
        
        pub_key_client_bytes = conection.recv(tam_client_key)
        nonce = conection.recv(12)
        textC = conection.recv(4096)

        # ECDH thing
        pub_key_client = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), pub_key_client_bytes)
        shared_secret = privkey.exchange(ec.ECDH(), pub_key_client)
        
        # Key derivation
        digest = hashes.Hash(hashes.SHA256())
        digest.update(shared_secret)
        aes_key = digest.finalize()

        # Decrypting
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
        print("[SERVER] Connection closed.")

if __name__ == "__main__":
    start_server()