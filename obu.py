import hashlib
import random
import socket


def generate_nonce():
    return random.randint(1, 1000000)


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


def main():
    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('localhost', 65432)
    sock.bind(server_address)
    sock.listen(1)

    print('Waiting for a connection...')
    connection, client_address = sock.accept()
    try:
        print('Connection from', client_address)

        # Step 1: Generate and send nonce
        nonce = generate_nonce()
        print(f"Generated Nonce: {nonce}")
        connection.sendall(str(nonce).encode())

        # Step 2: Receive and verify proof
        proof = connection.recv(256).decode()
        print(f"Received Proof: {proof}")

        # Assuming OBU's unique challenge is known to the FMS as "OBU_UNIQUE_CHALLENGE"
        obu_unique_challenge = "OBU_UNIQUE_CHALLENGE"
        expected_proof = hash_function(f"{nonce}{obu_unique_challenge}")

        if proof == expected_proof:
            print("Proof verified successfully.")

            # Step 3: Generate and send Diffie-Hellman public key
            private_key_fms, public_key_fms = generate_diffie_hellman_keys()
            connection.sendall(str(public_key_fms).encode())

            # Step 4: Receive OBU's Diffie-Hellman public key and session key
            public_key_obu = int(connection.recv(256).decode())
            session_key = connection.recv(256).decode()
            print(f"Received OBU's Public Key: {public_key_obu}")
            print(f"Received Session Key: {session_key}")

            # Step 5: Compute shared secret key
            shared_secret_key = compute_shared_key(public_key_obu, private_key_fms)
            print(f"Computed Shared Secret Key: {shared_secret_key}")
        else:
            print("Proof verification failed.")

    finally:
        connection.close()


if __name__ == "__main__":
    main()
