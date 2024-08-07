import socket
import json
import os
import hashlib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


# Load OBU data from the file
def load_obu_data(filename='obu_data.txt'):
    with open(filename, 'r') as file:
        data = file.read().split('\n')
        sid = data[1]
        challenge = data[3]
    return sid, challenge


# Save OBU data to the file
def save_obu_data(obu_private_key, obu_public_key, fms_public_key, shared_secret, session_id,
                  filename='obu_keys.txt'):
    with open(filename, 'w') as file:
        file.write(f"OBU Private Key:\n{obu_private_key}\n")
        file.write(f"OBU Public Key:\n{obu_public_key}\n")
        file.write(f"FMS Public Key:\n{fms_public_key}\n")
        file.write(f"Shared Secret:\n{shared_secret}\n")
        file.write(f"Session ID:\n{session_id}\n")


# Establish keys with FMS
def establish_keys_with_fms():
    sid, challenge = load_obu_data()
    request = json.dumps({'type': 'request_nonce', 'sid': sid}).encode()

    # Create socket and connect to FMS
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('localhost', 65339)
    sock.connect(server_address)
    try:
        sock.sendall(request)

        # Receive nonce from FMS
        data = sock.recv(4096)
        response = json.loads(data.decode())
        nonce = response['nonce']
        print("Received nonce:", nonce)

        # Calculate proof
        proof = hashlib.sha256((nonce + challenge).encode()).hexdigest()
        proof_request = json.dumps({'sid': sid, 'proof': proof}).encode()
        sock.sendall(proof_request)

        # Receive authentication result and FMS public key
        data = sock.recv(4096)
        auth_response = json.loads(data.decode())
        if auth_response['status'] == 'failed':
            print("Authentication failed")
            return

        fms_public_key_pem = auth_response['fms_public_key']
        print("Received FMS public key:", fms_public_key_pem)

        # Generate OBU key pair
        obu_private_key = ec.generate_private_key(ec.SECP256R1())
        obu_public_key = obu_private_key.public_key()

        obu_private_key_pem = obu_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()

        obu_public_key_pem = obu_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

        # Send OBU public key to FMS
        obu_key_request = json.dumps({'sid': sid, 'obu_public_key': obu_public_key_pem}).encode()
        sock.sendall(obu_key_request)

        # Receive shared secret and session ID from FMS
        data = sock.recv(4096)
        key_response = json.loads(data.decode())
        shared_secret = key_response['shared_secret']
        session_id = key_response['session_id']
        print("Received shared secret and session ID")

        # Save all data to OBU data file
        save_obu_data(obu_private_key_pem, obu_public_key_pem, fms_public_key_pem, shared_secret,
                      session_id)
        print("Authentication and Key Establishment Phase Successful")

    finally:
        sock.close()


def main():
    establish_keys_with_fms()


if __name__ == "__main__":
    main()
