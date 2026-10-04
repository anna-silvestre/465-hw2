message: how can I use the cryptography package to use AES-CTR in python

response: With the Python cryptography package, AES-CTR looks like this:

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

key = b"0123456789abcdef"       # 16, 24, or 32 bytes
nonce = b"1234567890abcdef"     # 16 bytes for AES's CTR counter block

cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))

# Encrypt
encryptor = cipher.encryptor()
ciphertext = encryptor.update(b"Hello, world!") + encryptor.finalize()

# Decrypt — use the same key and nonce
decryptor = Cipher(algorithms.AES(key), modes.CTR(nonce)).decryptor()
plaintext = decryptor.update(ciphertext) + decryptor.finalize()

print(ciphertext)
print(plaintext)

Important: Never reuse the same (key, nonce) pair for two different messages with CTR mode. CTR provides confidentiality but does not authenticate the ciphertext; for new designs, AES-GCM is usually preferable.