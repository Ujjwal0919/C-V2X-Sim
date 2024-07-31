import sqlite3
import socket
import json
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


# Fetch FMS keys from the database
def fetch_fms_keys():
    conn = sqlite3.connect('fms_database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT public_key, private_key FROM fms_keys LIMIT 1")
    result = cursor.fetchone()
    conn.close()
    public_key_pem, private_key_pem = result
    public_key = serialization.load_pem_public_key(public_key_pem.encode())
    private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    return public_key, private_key


# Fetch OBU challenge from the database
def fetch_obu_challenge(sid):
    conn = sqlite3.connect('fms_database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT challenge FROM obu_challenges WHERE sid=?", (sid,))
    result = cursor.fetchone()
    conn.close()
    if result:
        return result[0]
    return None


# Fetch or save OBU key information in the database
def save_obu_keys(sid, public_key_pem, shared_secret, session_id):
    conn = sqlite3.connect('fms_database.db')
    cursor = conn.cursor()
    cursor.execute("INSERT OR REPLACE INTO obu_keys (sid, public_key, shared_secret, session_id) VALUES (?, ?, ?, ?)",
                   (sid, public_key_pem, shared_secret, session_id))
    conn.commit()
    conn.close()


# Handle OBU requests
def handle_obu_request(connection):
    try:
        data = connection.recv(4096)
        request = json.loads(data.decode())
        print("Received request:", request)

        if request['type'] == 'request_nonce':
            sid = request['sid']
            challenge = fetch_obu_challenge(sid)
            if not challenge:
                raise ValueError(f"No challenge found for SID: {sid}")

            nonce = os.urandom(16).hex()
            response = {'nonce': nonce, 'sid': sid}
            connection.sendall(json.dumps(response).encode())

            # Wait for proof from OBU
            data = connection.recv(4096)
            proof_response = json.loads(data.decode())
            received_proof = proof_response['proof']

            # Calculate expected proof
            expected_proof = hashes.Hash(hashes.SHA256())
            expected_proof.update(nonce.encode())
            expected_proof.update(challenge.encode())
            calculated_proof = expected_proof.finalize().hex()

            if received_proof == calculated_proof:
                print("Authentication successful")
                # Send FMS public key
                fms_public_key, _ = fetch_fms_keys()
                fms_public_key_pem = fms_public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode()
                connection.sendall(json.dumps({'status': 'success', 'fms_public_key': fms_public_key_pem}).encode())

                # Receive OBU public key and calculate shared secret
                data = connection.recv(4096)
                obu_public_key_response = json.loads(data.decode())
                obu_public_key_pem = obu_public_key_response['obu_public_key']
                obu_public_key = serialization.load_pem_public_key(obu_public_key_pem.encode())

                fms_private_key = fetch_fms_keys()[1]
                shared_secret = fms_private_key.exchange(ec.ECDH(), obu_public_key).hex()
                session_id = os.urandom(16).hex()

                # Save OBU keys and shared secret
                save_obu_keys(sid, obu_public_key_pem, shared_secret, session_id)

                # Send shared secret and session ID to OBU
                connection.sendall(json.dumps({'shared_secret': shared_secret, 'session_id': session_id}).encode())
                print("Authentication and Key Establishment Phase Successful")
            else:
                print("Authentication failed")
                connection.sendall(json.dumps({'status': 'failed'}).encode())

    except Exception as e:
        print("An error occurred:", e)
    finally:
        connection.close()


# Create server to listen for connections
def create_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('0.0.0.0', 65331)
    sock.bind(server_address)
    sock.listen(1)
    print("FMS server listening on", server_address)
    return sock


def main():
    server_sock = create_server()
    while True:
        connection, client_address = server_sock.accept()
        try:
            handle_obu_request(connection)
        except Exception as e:
            print(f"An error occurred: {e}")
        finally:
            connection.close()


if __name__ == "__main__":
    main()
