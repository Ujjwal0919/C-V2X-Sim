import sqlite3
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


def initialize_database():
    conn = sqlite3.connect('fms_database.db')
    cursor = conn.cursor()

    cursor.execute('''CREATE TABLE IF NOT EXISTS fms_keys (
                        id INTEGER PRIMARY KEY,
                        private_key TEXT,
                        public_key TEXT)''')

    cursor.execute('''CREATE TABLE IF NOT EXISTS obu_challenges (
                        sid TEXT PRIMARY KEY,
                        challenge TEXT)''')

    cursor.execute('''CREATE TABLE IF NOT EXISTS obu_data (
                        sid TEXT PRIMARY KEY,
                        public_key TEXT,
                        shared_secret TEXT,
                        session_id TEXT)''')

    conn.commit()
    conn.close()


def generate_and_store_fms_keys():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()

    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    conn = sqlite3.connect('fms_database.db')
    cursor = conn.cursor()
    cursor.execute("INSERT INTO fms_keys (private_key, public_key) VALUES (?, ?)",
                   (private_key_pem, public_key_pem))
    conn.commit()
    conn.close()


if __name__ == "__main__":
    initialize_database()
    generate_and_store_fms_keys()
    print("Database initialized and FMS keys generated.")
