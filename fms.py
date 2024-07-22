import socket
from key_management import *


def start_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('0.0.0.0', 65432)
    sock.bind(server_address)
    sock.listen(1)
    return sock


def handle_client(connection, challenges):
    global fms_private_key, fms_public_key, obu_public_key
    try:
        print('Connected to client.')
        client_address = connection.getpeername()[0]

        nonce = generate_nonce()
        print(f"Generated Nonce: {nonce}")
        connection.sendall(str(nonce).encode())

        proof = connection.recv(256).decode()
        print(f"Received Proof: {proof}")
        if client_address in challenges:
            expected_proof = hash_function(f"{nonce}{challenges[client_address]}")
        else:
            connection.sendall(b"ERROR: Challenge not found for OBU.")
            print("Challenge not found for OBU.")
            return

        if proof == expected_proof:
            print("Proof verified successfully.")
            connection.sendall(b"VERIFIED")

            fms_private_key, fms_public_key = generate_ecdsa_keys()
            public_key_fms_bytes = fms_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            print(f"Sending FMS Public Key:\n{public_key_fms_bytes.decode()}")
            connection.sendall(public_key_fms_bytes)

            obu_response = connection.recv(4096).decode()
            public_key_obu, session_key = obu_response.split(',')
            obu_public_key = serialization.load_pem_public_key(public_key_obu.encode(), backend=default_backend())
            print(f"Received OBU's Public Key:\n{public_key_obu}")
            print(f"Received Session Key: {session_key}")

            shared_secret_key = compute_shared_key(fms_private_key, obu_public_key)
            print(f"Computed Shared Secret Key: {shared_secret_key.hex()}")

            save_keys_and_session_id(f"fms_keys_{client_address}.txt", fms_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode(), public_key_fms_bytes.decode(), public_key_obu, session_key)
        else:
            connection.sendall(b"ERROR: Proof verification failed.")
            print("Proof verification failed.")
    finally:
        connection.close()


def main():
    challenges = load_challenges()
    print(challenges)
    sock = start_server()
    print('Waiting for a connection...')
    while True:
        connection, client_address = sock.accept()
        handle_client(connection, challenges)


if __name__ == "__main__":
    main()
