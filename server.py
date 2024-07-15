import hashlib
import random
import socket


def hash_function(data):
    return hashlib.sha256(data.encode()).hexdigest()


def generate_diffie_hellman_keys():
    g = 2
    p = 23  # A small prime number for simplicity in this example
    private_key = random.randint(1, p - 1)
    public_key = pow(g, private_key, p)
    return private_key, public_key


def compute_shared_key(public_key, private_key, p=23):
    return pow(public_key, private_key, p)


def generate_session_key():
    return hashlib.sha256(str(random.getrandbits(256)).encode()).hexdigest()


def main():
    # Unique challenge stored within the OBU
    obu_unique_challenge = "OBU_UNIQUE_CHALLENGE"

    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('localhost', 65432)
    sock.connect(server_address)

    try:
        # Step 1: Receive nonce
        nonce = int(sock.recv(256).decode())
        print(f"Received Nonce: {nonce}")

        # Step 2: Generate and send proof
        proof = hash_function(f"{nonce}{obu_unique_challenge}")
        print(f"Generated Proof: {proof}")
        sock.sendall(proof.encode())

        # Step 3: Receive FMS's Diffie-Hellman public key
        public_key_fms = int(sock.recv(256).decode())
        print(f"Received FMS's Public Key: {public_key_fms}")

        # Step 4: Generate and send Diffie-Hellman public key and session key
        private_key_obu, public_key_obu = generate_diffie_hellman_keys()
        session_key = generate_session_key()
        sock.sendall(str(public_key_obu).encode())
        sock.sendall(session_key.encode())
        print(f"Sent OBU's Public Key: {public_key_obu}")
        print(f"Generated Session Key: {session_key}")

        # Step 5: Compute shared secret key
        shared_secret_key = compute_shared_key(public_key_fms, private_key_obu)
        print(f"Computed Shared Secret Key: {shared_secret_key}")

    finally:
        sock.close()


if __name__ == "__main__":
    main()
