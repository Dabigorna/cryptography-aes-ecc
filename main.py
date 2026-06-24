import threading
import time
import server_service
import client_handler

def run_all():
    print("="*50)
    print("!!!STARTING HYBRID CRYPTOSYSTEM (AES + ECC)!!!")
    print("="*50 + "\n")

    # Start server thread
    server_thread = threading.Thread(target=server_service.start_server)
    server_thread.daemon = True 
    server_thread.start()

    # Wait server online
    time.sleep(1)

    # Run client with secret msg
    msg = "This repo owner is very clever"
    client_handler.start_client(secret_msg=msg)

    time.sleep(1)
    print("\nM: Done!")

if __name__ == "__main__":
    run_all()