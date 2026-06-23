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