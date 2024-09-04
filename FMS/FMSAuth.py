import sqlite3
import socket
import json
import os
from cryptography.hazmat.primitives import hashes, serialization
import pyodbc
import hashlib
from cryptography.fernet import Fernet
import base64


def get_azure_sql_connection():
    server = 'fleetmanagementdb.database.windows.net'
    database = 'fleet-management-db'
    username = 'fmsadmin@fleetmanagementdb'
    password = 'Ujjwal0919@'  # Replace with your actual password
    driver = '{ODBC Driver 17 for SQL Server}'

    connection_str = f'DRIVER={driver};SERVER={server};PORT=1433;DATABASE={database};UID={username};PWD={password};Encrypt=yes;TrustServerCertificate=no;Connection Timeout=30;'
    conn = pyodbc.connect(connection_str)
    return conn


def fetch_challenge(sid):
    conn = get_azure_sql_connection()
    cursor = conn.cursor()
    query = "SELECT challenge FROM dbo.obu_challenges WHERE sid=?"
    cursor.execute(query, (sid,))
    result = cursor.fetchone()
    conn.close()
    if result:
        return result[0]
    else:
        return None


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


# Fetch OBU challenge from the database
def fetch_obu_challenge(sid):
    conn = sqlite3.connect('fms_database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT challenge, SID FROM obu_challenges WHERE sid=?", (sid,))
    result = cursor.fetchone()
    conn.close()
    if result:
        return result[0], result[1]
    return None


# Fetch or save OBU key information in the database


def store_obu_data(sid, shared_secret, session_id):
    conn = get_azure_sql_connection()
    cursor = conn.cursor()
    insert_query = '''
    INSERT INTO dbo.obu_data (sid, shared_secret, session_id)
    VALUES (?, ?, ?)
    '''
    cursor.execute(insert_query, (sid, shared_secret, session_id))
    conn.commit()
    conn.close()


# Handle OBU requests
def handle_obu_request(connection):
    try:
        data = connection.recv(4096)
        request = json.loads(data.decode())
        print("Received request type:", request['type'] + ' ' + request['sid'])
        # Step 1: Receive Authentication Request
        if request['type'] == 'request_nonce':
            sid = request['sid']
            challenge = fetch_challenge(sid)
            print("Determined challenge and SID:" + sid)
            if not challenge:
                raise ValueError(f":{sid} not found")
            # Step 2: Generate and Send Challenge Request
            nonce = os.urandom(16).hex()
            print("Generated Plaintext Nonce: ", nonce)
            encrypted_nonce = encrypt_message(nonce, challenge)
            print("Encrypted Nonce: ", encrypted_nonce)
            challenge_request = {'nonce': encrypted_nonce, 'sid': sid}
            connection.sendall(json.dumps(challenge_request).encode())
            print(f"Sending Nonce: {nonce}")

            # Step 3: Receive and validate Challenge Response
            data = connection.recv(4096)
            challenge_response = json.loads(data.decode())
            encrypted_proof = challenge_response['proof']
            decrypted_proof = decrypt_message(encrypted_proof, challenge)

            print(f"Got proof: {decrypted_proof}")

            # Calculate expected proof
            calculated_proof = hashlib.sha256((nonce + challenge).encode()).hexdigest()
            print(f"Calculated proof: {calculated_proof}")

            if decrypted_proof == calculated_proof:
                print("Proof Matched and Authentication successful")
                shared_secret = os.urandom(32).hex()
                session_id = os.urandom(16).hex()
                print("Shared Secret & session_id Calculated")
                # Save OBU keys and shared secret
                store_obu_data(sid, shared_secret, session_id)
                shared_sec_enc = encrypt_message(shared_secret, challenge)
                session_id_enc = encrypt_message(session_id, challenge)

                # Step 6: Send shared secret and session ID to OBU
                connection.sendall(json.dumps(
                    {'status': 'Success', 'shared_secret': shared_sec_enc, 'session_id': session_id_enc}).encode())
                print("Authentication and Key Establishment Phase Successful")
                connection.close()
                exit()
            else:
                print("Authentication failed")
                connection.sendall(json.dumps({'status': 'failed'}).encode())
                connection.close()
                exit()
    except Exception as e:
        print("An error occurred:", e)
    finally:
        connection.close()


# Create server to listen for connections
def create_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('0.0.0.0', 65334)
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
