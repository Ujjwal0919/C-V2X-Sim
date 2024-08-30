from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
import socket
import json
import hashlib
import sqlite3
import re


# Load FMS keys, session ID, and shared secret
def load_fms_keys():
    conn = sqlite3.connect('fms_database.db')
    cursor = conn.cursor()
    conn = sqlite3.connect('fms_database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT public_key, private_key FROM fms_keys LIMIT 1")
    result = cursor.fetchone()
    fms_public_key, fms_private_key = result
    cursor = conn.cursor()
    cursor.execute("SELECT SID, public_key, shared_secret, session_id FROM obu_keys")
    result = cursor.fetchone()
    SID, obu_public_key, obu_shared_secret, obu_session_id = result
    return fms_private_key,fms_public_key, obu_session_id,obu_public_key, obu_shared_secret.encode()





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
    server_address = ('localhost', 65334)
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
            print("Received Message: " + data_packet['message'])
        else:
            print("Signature verification failed.")

    finally:
        connection.close()


def main():
    _, _, _, _, shared_secret = load_fms_keys()
    receive_message_from_obu(shared_secret)


if __name__ == "__main__":
    main()