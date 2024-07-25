from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from termcolor import colored, cprint
import hashlib
import random
import socket


# Load challenge from a text file
def load_challenge(filename='obu_challenge.txt'):
    with open(filename, 'r') as file:
        return file.read()
    

# Save keys and session ID to a text file
def save_keys_and_session_id(filename, private_key, public_key, session_id, fms_public_key):
    with open(filename, 'w') as file:
        file.write(f"Private Key:\n{private_key}\n")
        file.write(f"Public Key:\n{public_key}\n")
        file.write(f"Session ID:\n{session_id}\n")
        file.write(f"FMS Public Key:\n{fms_public_key}\n")


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


# Connect to server
def connect_to_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('localhost', 65432)  # Use 'localhost' instead of '0.0.0.0'
    sock.connect(server_address)
    return sock


# Handle server communication
def handle_server(sock):
    global obu_private_key, obu_public_key, fms_public_key, session_key
    try:
        # Step 1: Receive nonce
        nonce = int(sock.recv(256).decode())
        print(f"Received Nonce: {nonce}")

        # Load challenge
        challenge = load_challenge()
        print(challenge)

        # Step 2: Generate and send proof
        proof = hash_function(f"{nonce}{challenge}")
        print(f"Generated Proof: {proof}")
        sock.sendall(proof.encode())

        # Step 3: Receive verification result
        verification_result = sock.recv(256).decode()
        if verification_result != "VERIFIED":
            print(colored(f"Verification Failed: {verification_result}", 'red'))
        else:
            print(colored(f"Verification Status: {verification_result}", 'green'))


        # Step 4: Receive FMS's ECDSA public key
        fms_public_key_data = sock.recv(4096)
        print(f"Received FMS Public Key Data:\n{fms_public_key_data.decode()}")
        fms_public_key = serialization.load_pem_public_key(fms_public_key_data, backend=default_backend())

        # Step 5: Generate and send ECDSA public key and session key
        obu_private_key, obu_public_key = generate_ecdsa_keys()
        public_key_obu_bytes = obu_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        session_key = generate_session_key()
        obu_response = f"{public_key_obu_bytes},{session_key}"
        sock.sendall(obu_response.encode())
        print(f"Sent OBU's Public Key:\n{public_key_obu_bytes}")
        print(f"Generated Session Key: {session_key}")


        # Save keys and session ID
        save_keys_and_session_id('obu_keys.txt', obu_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode(), public_key_obu_bytes, session_key, fms_public_key_data.decode())
    finally:
        sock.close()


def main():
    sock = connect_to_server()
    handle_server(sock)


if __name__ == "__main__":
    main()
