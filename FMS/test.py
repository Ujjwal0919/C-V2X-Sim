import sqlite3
import re
from cryptography.hazmat.primitives import hashes, serialization


# Load FMS keys, session ID, and shared secret
conn = sqlite3.connect('fms_database.db')
cursor = conn.cursor()
cursor.execute("SELECT public_key, private_key FROM fms_keys LIMIT 1")
result = cursor.fetchone()
public_key_pem, private_key_pem = result
public_key = serialization.load_pem_public_key(public_key_pem.encode())
private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
print(public_key)
print(private_key)
cursor = conn.cursor()
cursor.execute("SELECT SID, public_key, shared_secret, session_id FROM obu_keys")
result = cursor.fetchone()
SID, obu_public_key, obu_shared_secret, obu_session_id = result
print(SID)
print(obu_public_key)
print(obu_shared_secret)
print(obu_session_id)

