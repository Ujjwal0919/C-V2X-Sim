from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend


# Load OBU and FMS keys
def load_keys(filename='obu_keys.txt'):
    with open(filename, 'r') as file:
        data = file.read()
        private_key_pem = data.split('Private Key:\n')[1].split('Public Key:\n')[0].strip()
        public_key_pem = data.split('Public Key:\n')[1].split('Session ID:\n')[0].strip()
        session_id = data.split('Session ID:\n')[1].split('FMS Public Key:\n')[0].strip()
        fms_public_key_pem = data.split('FMS Public Key:\n')[1].strip()

    private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None, backend=default_backend())
    public_key = serialization.load_pem_public_key(public_key_pem.encode(), backend=default_backend())
    fms_public_key = serialization.load_pem_public_key(fms_public_key_pem.encode(), backend=default_backend())

    return private_key, public_key, session_id, fms_public_key


# Generate shared secret key
def generate_shared_secret(obu_private_key, fms_public_key):
    shared_key = obu_private_key.exchange(ec.ECDH(), fms_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_key)
    return derived_key


# Save shared secret key
def save_shared_secret(filename='obu_keys.txt', shared_secret=None):
    with open(filename, 'a') as file:
        file.write(f"\nShared Secret Key:\n{shared_secret.hex()}")


def main():
    obu_private_key, _, _, fms_public_key = load_keys()
    shared_secret = generate_shared_secret(obu_private_key, fms_public_key)
    save_shared_secret(shared_secret=shared_secret)


if __name__ == "__main__":
    main()
