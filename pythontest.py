from ecdsa import SigningKey
sk = SigningKey.generate()
print(sk) # uses NIST192p
vk = sk.verifying_key
signature = sk.sign(b"message")
assert vk.verify(signature, b"message")