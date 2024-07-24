from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import hashlib
import random
import socket


# Load challenge from a text file
def load_challenge(filename='challenges.txt'):
    with open(filename, 'r') as file:
        return file.read().strip()


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


# Create server socket
def create_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('localhost', 65432)
    sock.bind(server_address)
    sock.listen(1)
    print("Server listening on", server_address)
    return sock


# Handle client connection
def handle_client(connection):
    try:
        # Step 1: Send nonce
        nonce = random.randint(1000, 9999)
        print(f"Sending Nonce: {nonce}")
        connection.sendall(str(nonce).encode())

        # Step 2: Receive proof
        proof = connection.recv(256).decode()
        print(f"Received Proof: {proof}")

        # Load challenge
        challenge = load_challenge()

        # Verify proof
        expected_proof = hash_function(f"{nonce}{challenge}")
        if proof == expected_proof:
            connection.sendall("VERIFIED".encode())
            print("Verification Successful")

            # Step 4: Send FMS's ECDSA public key
            fms_private_key, fms_public_key = generate_ecdsa_keys()
            fms_public_key_data = fms_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            connection.sendall(fms_public_key_data)
            print(f"Sent FMS Public Key:\n{fms_public_key_data.decode()}")

            # Step 5: Receive OBU's public key and session key
            obu_response = connection.recv(4096).decode()
            public_key_obu_bytes, session_key = obu_response.split(',')
            obu_public_key = serialization.load_pem_public_key(public_key_obu_bytes.encode(), backend=default_backend())
            print(f"Received OBU Public Key:\n{public_key_obu_bytes}")
            print(f"Received Session Key: {session_key}")

            # Step 6: Compute shared secret key
            shared_secret_key = compute_shared_key(fms_private_key, obu_public_key)
            print(f"Computed Shared Secret Key: {shared_secret_key.hex()}")

            # Save keys and session ID
            save_keys_and_session_id('fms_keys.txt', fms_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode(), fms_public_key_data.decode(), session_key, public_key_obu_bytes)
        else:
            connection.sendall("FAILED".encode())
            print("Verification Failed")
    finally:
        connection.close()


def main():
    server_sock = create_server()
    while True:
        connection, client_address = server_sock.accept()
        try:
            handle_client(connection)
        except Exception as e:
            print(f"An error occurred: {e}")
        finally:
            connection.close()


if __name__ == "__main__":
    main()
