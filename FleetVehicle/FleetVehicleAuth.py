import socket
import json
import hashlib
from cryptography.fernet import Fernet
import base64


# Load OBU data from the file
def load_obu_data(filename='obu_data.txt'):
    with open(filename, 'r') as file:
        data = file.read().split('\n')
        sid = data[1]
        challenge = data[3]
    return sid, challenge


def encrypt_message(message, challenge):
    challenge_hash = hashlib.sha256(challenge.encode()).digest()
    encryption_key = base64.urlsafe_b64encode(challenge_hash[:32])
    cipher_suite = Fernet(encryption_key)
    encrypted_message = cipher_suite.encrypt(message.encode())
    return encrypted_message.decode()


def decrypt_message(message, challenge):
    challenge_hash = hashlib.sha256(challenge.encode()).digest()
    decryption_key = base64.urlsafe_b64encode(challenge_hash[:32])
    cipher_suite = Fernet(decryption_key)
    decrypted_message = cipher_suite.decrypt(message).decode()
    return decrypted_message


# Save OBU data to the file
def save_obu_data( shared_secret, session_id,
                  filename='obu_keys.txt'):
    with open(filename, 'w') as file:
        file.write(f"Shared Secret:\n{shared_secret}\n")
        file.write(f"Session ID:\n{session_id}\n")


# Establish keys with FMS
def establish_keys_with_fms():
    sid, challenge = load_obu_data()
    print("Loading OBU data from file")
    print("SID: " + sid + "Challenge: " + challenge)
    authentication_request = json.dumps({'type': 'request_nonce', 'sid': sid}).encode()

    # Create socket and connect to FMS
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('localhost', 65334)
    sock.connect(server_address)
    try:
        # Step 1 Send Authentication Request to FMS
        sock.sendall(authentication_request)

        # Step 2 Receive nonce from FMS
        request = sock.recv(4096)
        challenge_request = json.loads(request.decode())
        nonce = challenge_request['nonce']
        decrypted_nonce = decrypt_message(nonce, challenge)
        print("Received nonce:", decrypted_nonce)

        # Step 3 Calculating and sending challenge response
        proof = hashlib.sha256((decrypted_nonce + challenge).encode()).hexdigest()
        encrypted_proof = encrypt_message(proof, challenge)
        challenge_response = json.dumps({'sid': sid, 'proof': encrypted_proof}).encode()
        sock.sendall(challenge_response)
        print("Sending Challenge Response:", proof)

        # Step 4: Receive authentication result and FMS public key
        data = sock.recv(4096)
        auth_response = json.loads(data.decode())
        if auth_response['status'] == 'failed':
            print("Authentication failed")
            return
        # Receive shared secret and session ID from FMS
        key_response = json.loads(data.decode())
        shared_secret = decrypt_message(key_response['shared_secret'], challenge)
        session_id = decrypt_message(key_response['session_id'], challenge)
        print("Received shared secret and session ID")

        # Save all data to OBU data file
        save_obu_data(shared_secret, session_id)
        print("Authentication and Key Establishment Phase Successful")

    finally:
        sock.close()


def main():
    establish_keys_with_fms()


if __name__ == "__main__":
    main()
