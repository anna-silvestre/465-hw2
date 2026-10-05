import os
from cryptography.hazmat.primitives import Cipher, algorithms, modes, hashes, hmac
# task 3

# header = version(1 byte) || direction(1 byte) || sequence(8 bytes) || message_type(1 byte) || ciphertext_length(4 bytes)
# iv = session_id(8 bytes) || sequence(8 bytes)
# ciphertext = AES-256-CTR(K_enc, iv, plaintext)
# tag = HMAC-SHA-256(K_mac, header || iv || ciphertext)

def seal(handshake_details, version, direction, sequence, message_type, plaintext):
    # TODO
    session_id = handshake_details['session_id']
    K_enc = handshake_details['K_enc']
    K_mac = handshake_details['K_mac']
    header = version.to_bytes(1, byteorder='big') + direction.to_bytes(1, byteorder='big') + sequence.to_bytes(8, byteorder='big') + message_type.to_bytes(1, byteorder='big') + len(plaintext).to_bytes(4, byteorder='big')
    iv = session_id + sequence.to_bytes(8, byteorder='big')
    cipher = Cipher(algorithms.AES(K_enc), modes.CTR(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    h = hmac.HMAC(K_mac, hashes.SHA256())
    h.update(header + iv + ciphertext)
    tag = h.finalize()
    return (header + iv + ciphertext + tag)

def open_record(handshake_details, version, direction, sequence, message_type, payload):
    # TODO
    # assert len(payload) >= 15 + 16 + 32, "payload too short"
    # verify hmac tag
    tag = payload[-32:]
    header = payload[:15]
    iv = payload[15:31]
    ciphertext = payload[31:-32]
    K_mac = handshake_details['K_mac']
    
    h = hmac.HMAC(K_mac, hashes.SHA256())
    h.update(header + iv + ciphertext)

    try:
        h.verify(tag)
    except Exception as e:
        raise ValueError("HMAC verification failed") from e

    header_version = int.from_bytes(header[0:1], byteorder='big')
    header_direction = int.from_bytes(header[1:2], byteorder='big')
    header_sequence = int.from_bytes(header[2:10], byteorder='big')
    header_message_type = int.from_bytes(header[10:11], byteorder='big')
    session_id = handshake_details['session_id']

    if len(ciphertext) != len(plaintext):
        raise ValueError("Ciphertext length mismatch")
    if header_version != version:
        raise ValueError("Version mismatch")
    if header_direction != direction:
        raise ValueError("Direction mismatch")
    if header_sequence != sequence:
        raise ValueError("Sequence mismatch")
    if header_message_type != message_type:
        raise ValueError("Message type mismatch")

    expected_iv = session_id + sequence.to_bytes(8, byteorder='big')
    if iv != expected_iv:
        raise ValueError("IV mismatch")
    
    # decrypt 
    K_enc = handshake_details['K_enc']
    cipher = Cipher(algorithms.AES(K_enc), modes.CTR(iv))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    return plaintext

# hehe haha hohoho
# handshake_details = session(gateway_rsa_private_key, node_rsa_private_key)