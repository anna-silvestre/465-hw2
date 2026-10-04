import json
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Relay Function (prior to values, no key access)
def relay(ciphertext):
    # Decrypt the ciphertext
    print("-- RELAY --")
    new_text = bytearray(ciphertext)
    og_command = b"READ"
    new_command = b"POST"

    offset = 11
    for i in range(len(og_command)):
        attack_xor = og_command[i] ^ new_command[i]
        new_text[offset+i] ^= attack_xor

    print(f"XOR: {bytearray([attack_xor])} VAL: {attack_xor}")

    print(f"Intercepted Ciphertext: {new_text}")
    return new_text

def sender(plaintext, key, nonce):
    print("-- SENDER --")


    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))

    # Encryption
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    print(f"Ciphertext: {ciphertext}")
    return ciphertext

def receiver(ciphertext, key, nonce):
    print("-- RECEIVER --")
    # Decryption
    decryptor = Cipher(algorithms.AES(key), modes.CTR(nonce)).decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    print(f"Decrypted Text: {plaintext}")
    return plaintext

command = b'{"action":"READ","path":"notes.txt"}'
print("TASK 1")
print(f"Command: {command}\n")

key = os.urandom(16)  # 16 bytes for AES-128
nonce = os.urandom(16)  # 16 bytes for AES's CTR counter

ciphertext = sender(command, key, nonce)

print("\nNORMAL EXCHANGE")
decrypted_text = receiver(ciphertext, key, nonce)

print("\nINTERCEPTED EXCHANGE")
modified_ciphertext = relay(ciphertext)
decrypted_text = receiver(modified_ciphertext, key, nonce)