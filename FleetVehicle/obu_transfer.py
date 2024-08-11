from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import socket
import json
import hashlib
import os
import re


# Load OBU keys, session ID, and shared secret
def load_obu_keys(filename='obu_keys.txt'):
    with open(filename, 'r') as file:
        text = file.read()

    # Extract OBU Private Key
    obu_private_key_match = re.search(
        r'OBU Private Key:\n(-----BEGIN EC PRIVATE KEY-----[\s\S]+?-----END EC PRIVATE KEY-----)', text)
    obu_private_key = obu_private_key_match.group(1).strip() if obu_private_key_match else None

    # Extract OBU Public Key
    obu_public_key_match = re.search(r'OBU Public Key:\n(-----BEGIN PUBLIC KEY-----[\s\S]+?-----END PUBLIC KEY-----)',
                                     text)
    obu_public_key = obu_public_key_match.group(1).strip() if obu_public_key_match else None

    # Extract FMS Public Key
    fms_public_key_match = re.search(r'FMS Public Key:\n(-----BEGIN PUBLIC KEY-----[\s\S]+?-----END PUBLIC KEY-----)',
                                     text)
    fms_public_key = fms_public_key_match.group(1).strip() if fms_public_key_match else None

    # Extract Shared Secret
    shared_secret_match = re.search(r'Shared Secret:\n([a-fA-F0-9]+)', text)
    shared_secret = shared_secret_match.group(1).strip() if shared_secret_match else None

    # Extract Session ID
    session_id_match = re.search(r'Session ID:\n([a-fA-F0-9]+)', text)
    session_id = session_id_match.group(1).strip() if session_id_match else None

    return obu_private_key,fms_public_key,session_id,obu_public_key,shared_secret.encode()


# Hash function
def hash_message(message):
    return hashlib.sha256(message.encode()).hexdigest()


# Encrypt a message using AES
def encrypt_message(key, iv, plaintext):
    encryptor = Cipher(
        algorithms.AES(key),
        modes.CFB(iv),
        backend=default_backend()
    ).encryptor()
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    return ciphertext


# Sign the message using HMAC
def sign_message(key, message):
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(message.encode())
    return h.finalize()


# Create data packet
def create_data_packet(message, session_id, signature):
    data_packet = {
        'session_id': session_id,
        'message': message,
        'signature': signature.hex()
    }
    return json.dumps(data_packet)


# Encrypt data packet
def encrypt_data_packet(shared_secret, data_packet):
    # Use the first 32 bytes of the shared secret as the AES key
    key = shared_secret[:32]
    # Generate random IV for AES
    iv = os.urandom(16)
    # Encrypt data packet using AES key
    ciphertext = encrypt_message(key, iv, data_packet)
    return iv, ciphertext


# Send the message to FMS
def send_message_to_fms(message, session_id, shared_secret):
    # Sign the message
    signature = sign_message(shared_secret, message)

    # Create data packet
    data_packet = create_data_packet(message, session_id, signature)

    # Encrypt the data packet using the shared secret
    iv, encrypted_data_packet = encrypt_data_packet(shared_secret, data_packet)
    print(f"Sending data packet: {encrypted_data_packet.hex()}")
    # Send data to FMS
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('localhost', 65439)
    sock.connect(server_address)

    try:
        # Combine IV and ciphertext into one message
        message_to_send = iv + encrypted_data_packet
        sock.sendall(message_to_send)
    finally:
        sock.close()


def main():
    message = "Hello FMS, this is OBU."
    _, _, session_id, _, shared_secret = load_obu_keys()
    send_message_to_fms(message, session_id, shared_secret)


if __name__ == "__main__":
    main()