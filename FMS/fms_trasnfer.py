from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature, decode_dss_signature
from cryptography.hazmat.primitives import serialization
import socket
import json


# Load FMS keys and session ID
def load_fms_keys(filename='fms_keys.txt'):
    with open(filename, 'r') as file:
        data = file.read()
        private_key_pem = data.split('Private Key:\n')[1].split('Public Key:\n')[0].strip()
        public_key_pem = data.split('Public Key:\n')[1].split('Session ID:\n')[0].strip()
        session_id = data.split('Session ID:\n')[1].split('OBU Public Key:\n')[0].strip()
        obu_public_key_pem = data.split('OBU Public Key:\n')[1].strip()

    private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    public_key = serialization.load_pem_public_key(public_key_pem.encode())
    obu_public_key = serialization.load_pem_public_key(obu_public_key_pem.encode())

    return private_key, public_key, session_id, obu_public_key


# Verify a message
def verify_message(public_key, message, signature):
    r, s = decode_dss_signature(bytes.fromhex(signature))
    try:
        public_key.verify(
            encode_dss_signature(r, s),
            message.encode(),
            ec.ECDSA(hashes.SHA256())
        )
        return True
    except:
        return False


# Receive and handle data from OBU
def handle_client(connection):
    try:
        data = connection.recv(4096).decode()
        data_packet = json.loads(data)

        session_id = data_packet['session_id']
        message = data_packet['message']
        signature = data_packet['signature']

        _, _, fms_session_id, obu_public_key = load_fms_keys()

        if session_id != fms_session_id:
            print("Session ID mismatch!")
            return

        if verify_message(obu_public_key, message, signature):
            print(f"Received message: {message}")
        else:
            print("Signature verification failed!")
    finally:
        connection.close()


# Create server to listen for connections
def create_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('localhost', 65432)
    sock.bind(server_address)
    sock.listen(1)
    print("FMS server listening on", server_address)
    return sock


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
