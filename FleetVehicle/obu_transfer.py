from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature, decode_dss_signature
from cryptography.hazmat.primitives import serialization
import socket
import json


# Load OBU keys and session ID
def load_obu_keys(filename='obu_keys.txt'):
    with open(filename, 'r') as file:
        data = file.read()
        private_key_pem = data.split('Private Key:\n')[1].split('Public Key:\n')[0].strip()
        public_key_pem = data.split('Public Key:\n')[1].split('Session ID:\n')[0].strip()
        session_id = data.split('Session ID:\n')[1].split('FMS Public Key:\n')[0].strip()
        fms_public_key_pem = data.split('FMS Public Key:\n')[1].strip()

    private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    public_key = serialization.load_pem_public_key(public_key_pem.encode())
    fms_public_key = serialization.load_pem_public_key(fms_public_key_pem.encode())

    return private_key, public_key, session_id, fms_public_key


# Sign a message
def sign_message(private_key, message):
    signature = private_key.sign(
        message.encode(),
        ec.ECDSA(hashes.SHA256())
    )
    return encode_dss_signature(*decode_dss_signature(signature))


# Connect to FMS and send the message
def send_message_to_fms(message, session_id):
    private_key, public_key, session_id, fms_public_key = load_obu_keys()
    signed_message = sign_message(private_key, message)

    # Create a data packet
    data_packet = {
        'session_id': session_id,
        'message': message,
        'signature': signed_message.hex()
    }

    # Send data to FMS
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('localhost', 65432)
    sock.connect(server_address)

    try:
        sock.sendall(json.dumps(data_packet).encode())
    finally:
        sock.close()


def main():
    message = "Hello FMS, this is OBU."
    session_id = load_obu_keys()[2]
    send_message_to_fms(message, session_id)


if __name__ == "__main__":
    main()
