import socket
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, ec


def load_obu_keys(file_path):
    with open(file_path, 'r') as file:
        content = file.read()

    private_key_pem = content.split('Private Key:\n')[1].split('Public Key:')[0].strip()
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode(),
        password=None
    )

    session_id = content.split('Session ID:\n')[1].split('FMS Public Key:')[0].strip()

    return private_key, session_id


def create_data_frame(message, session_id):
    return f"{session_id}:{message}"


def encrypt_message(message, private_key):
    return private_key.sign(
        message.encode(),
        ec.ECDSA(hashes.SHA256())
    )


def send_to_fms(encrypted_message, host='localhost', port=65432):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        s.sendall(encrypted_message)
        print("Encrypted message sent to FMS")


def main():
    obu_private_key, session_id = load_obu_keys('obu_keys.txt')

    dummy_message = "This is a test message from OBU"
    data_frame = create_data_frame(dummy_message, session_id)

    encrypted_message = encrypt_message(data_frame, obu_private_key)

    send_to_fms(encrypted_message)


if __name__ == "__main__":
    main()