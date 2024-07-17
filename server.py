from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import hashlib
import random
import socket
import json


# Load challenges for OBUs from a text file
def load_challenges(filename='challenges.txt'):
    with open(filename, 'r') as file:
        return json.load(file)


# Save keys and session ID to a text file
def save_keys_and_session_id(filename, private_key, public_key, session_id):
    with open(filename, 'w') as file:
        file.write(f"Private Key:\n{private_key}\n")
        file.write(f"Public Key:\n{public_key}\n")
        file.write(f"Session ID:\n{session_id}\n")


# Generate nonce
def generate_nonce():
    return random.randint(1, 1000000)


# Hash function
def hash_function(data):
    return hashlib.sha256(data.encode()).hexdigest()


# Generate ECDSA keys
def generate_ecdsa_keys():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key


# Compute shared key
def compute_shared_key(private_key, public_key):
    shared_key = private_key.exchange(ec.ECDH(), public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_key)
    return derived_key


# Generate session key
def generate_session_key():
    return hashlib.sha256(str(random.getrandbits(256)).encode()).hexdigest()


# Start the server
def start_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('0.0.0.0', 65432)
    sock.bind(server_address)
    sock.listen(1)
    return sock


# Handle client connection
def handle_client(connection, challenges):
    global fms_private_key, fms_public_key, obu_public_key
    try:
        print('Connected to client.')
        client_address = connection.getpeername()[0]

        # Step 1: Generate and send nonce
        nonce = generate_nonce()
        print(f"Generated Nonce: {nonce}")
        connection.sendall(str(nonce).encode())

        # Step 2: Receive and verify proof
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

            # Step 3: Generate and send ECDSA public key
            fms_private_key, fms_public_key = generate_ecdsa_keys()
            public_key_fms_bytes = fms_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            print(f"Sending FMS Public Key:\n{public_key_fms_bytes.decode()}")
            connection.sendall(public_key_fms_bytes)

            # Step 4: Receive OBU's ECDSA public key and session key
            obu_response = connection.recv(4096).decode()
            public_key_obu, session_key = obu_response.split(',')
            obu_public_key = serialization.load_pem_public_key(public_key_obu.encode(), backend=default_backend())
            print(f"Received OBU's Public Key:\n{public_key_obu}")
            print(f"Received Session Key: {session_key}")

            # Step 5: Compute shared secret key
            shared_secret_key = compute_shared_key(fms_private_key, obu_public_key)
            print(f"Computed Shared Secret Key: {shared_secret_key.hex()}")

            # Save keys and session ID
            save_keys_and_session_id(f"fms_keys_{client_address}.txt", fms_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode(), public_key_fms_bytes.decode(), session_key)
        else:
            connection.sendall(b"ERROR: Proof verification failed.")
            print("Proof verification failed.")
    finally:
        connection.close()


def main():
    challenges = load_challenges()
    sock = start_server()
    print('Waiting for a connection...')
    while True:
        connection, client_address = sock.accept()
        handle_client(connection, challenges)


if __name__ == "__main__":
    main()
