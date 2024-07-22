import socket
from key_management import *


def connect_to_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('localhost', 65432)
    sock.connect(server_address)
    return sock


def handle_server(sock):
    global obu_private_key, obu_public_key, fms_public_key, session_key
    try:
        nonce = int(sock.recv(256).decode())
        print(f"Received Nonce: {nonce}")

        challenge = load_challenge()

        proof = hash_function(f"{nonce}{challenge}")
        print(f"Generated Proof: {proof}")
        sock.sendall(proof.encode())

        verification_result = sock.recv(256).decode()
        if verification_result != "VERIFIED":
            print(f"Verification Failed: {verification_result}")
            return

        fms_public_key_data = sock.recv(4096)
        print(f"Received FMS Public Key Data:\n{fms_public_key_data.decode()}")
        fms_public_key = serialization.load_pem_public_key(fms_public_key_data, backend=default_backend())
        print(f"Loaded FMS Public Key: {fms_public_key}")

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

        shared_secret_key = compute_shared_key(obu_private_key, fms_public_key)
        print(f"Computed Shared Secret Key: {shared_secret_key.hex()}")

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
