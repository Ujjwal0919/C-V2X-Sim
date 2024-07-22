import json
import random
import hashlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend


def load_challenges(filename='challenges.txt'):
    with open(filename, 'r') as file:
        return json.load(file)


def load_challenge(filename='obu_challenge.txt'):
    with open(filename, 'r') as file:
        return file.read().strip()



def save_keys_and_session_id(filename, private_key, public_key, session_id, fms_public_key):
    with open(filename, 'w') as file:
        file.write(f"Private Key:\n{private_key}\n")
        file.write(f"Public Key:\n{public_key}\n")
        file.write(f"Session ID:\n{session_id}\n")
        file.write(f"FMS Public Key:\n{fms_public_key}\n")


def generate_nonce():
    return random.randint(1, 1000000)


def hash_function(data):
    return hashlib.sha256(data.encode()).hexdigest()


def generate_ecdsa_keys():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key


def compute_shared_key(private_key, public_key):
    shared_key = private_key.exchange(ec.ECDH(), public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_key)
    return derived_key


def generate_session_key():
    return hashlib.sha256(str(random.getrandbits(256)).encode()).hexdigest()
