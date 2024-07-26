from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import socket
import json
import hashlib
import re


# Load FMS keys, session ID, and shared secret
def load_fms_keys(filename='fms_keys.txt'):
    with open(filename, 'r') as file:
        content = file.read()
        # Extract private key
        private_key = re.search(r'-----BEGIN PRIVATE KEY-----(.+?)-----END PRIVATE KEY-----', content, re.DOTALL)
        private_key = private_key.group().strip() if private_key else None
        # Extract public key
        public_key = re.search(r'-----BEGIN PUBLIC KEY-----(.+?)-----END PUBLIC KEY-----', content, re.DOTALL)
        public_key = public_key.group().strip() if public_key else None
        # Extract session ID
        session_id = re.search(r'Session ID:\s*(\S+)', content)
        session_id = session_id.group(1).strip() if session_id else None
        # Extract OBU public key
        obu_public_key = re.search(r'OBU Public Key:\s*(-----BEGIN PUBLIC KEY-----(.+?)-----END PUBLIC KEY-----)',
                                   content, re.DOTALL)
        obu_public_key = obu_public_key.group(1).strip() if obu_public_key else None
        # Extract shared key
        shared_key = re.search(r'Shared Key:\s*(\S+)', content)
        shared_key = shared_key.group(1).strip() if shared_key else None

    return private_key, public_key, session_id, obu_public_key, shared_key.encode()


# Hash function
def hash_message(message):
    return hashlib.sha256(message.encode()).hexdigest()


# Decrypt a message using AES
def decrypt_message(key, iv, ciphertext):
    decryptor = Cipher(
        algorithms.AES(key),
        modes.CFB(iv),
        backend=default_backend()
    ).decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext.decode()


# Verify the message signature using HMAC
def verify_signature(key, message, signature):
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(message.encode())
    try:
        h.verify(bytes.fromhex(signature))
        return True
    except:
        return False


# Receive and process message from OBU
def receive_message_from_obu(shared_secret):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('localhost', 65432)
    sock.bind(server_address)
    sock.listen(1)

    print("Waiting for connection...")
    connection, client_address = sock.accept()
    try:
        print("Connection from", client_address)

        # Receive the data
        data = connection.recv(4096)
        print(f"Received data: {data.hex()}")
        # Extract IV and ciphertext
        iv = data[:16]
        ciphertext = data[16:]

        # Decrypt the data packet
        key = shared_secret[:32]  # Use the first 32 bytes of the shared secret as the AES key
        decrypted_data = decrypt_message(key, iv, ciphertext)

        # Parse the decrypted data
        data_packet = json.loads(decrypted_data)

        # Verify the signature
        if verify_signature(shared_secret, data_packet['message'], data_packet['signature']):
            print("Signature verified successfully.")

            # Verify the message hash
            if hash_message(data_packet['message']) == data_packet['message_hash']:
                print("Message hash verified successfully.")
                print("Received message:", data_packet['message'])
            else:
                print("Message hash verification failed.")
        else:
            print("Signature verification failed.")

    finally:
        connection.close()


def main():
    _, _, _, _, shared_secret = load_fms_keys()
    receive_message_from_obu(shared_secret)


if __name__ == "__main__":
    main()