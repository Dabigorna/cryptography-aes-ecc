# This code was made by https://github.com/Dabigorna
#M = main
import threading
import time
import server_service
import client_handler

def run_all():
    print("="*50)
    print("!!!STARTING HYBRID CRYPTOSYSTEM (AES + ECC)!!!")
    print("="*50 + "\n")

    # Spin up the server in a separate background thread
    server_thread = threading.Thread(target=server_service.start_server)
    server_thread.daemon = True 
    server_thread.start()

    # Give the server a second to bind to the port and listen
    time.sleep(1)

    # Fire up the client with our custom message
    msg = "This repo owner is very clever"
    client_handler.start_client(secret_msg=msg)

    time.sleep(1)
    print("\nM: Done!")

if __name__ == "__main__":
    run_all()