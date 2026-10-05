import os
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, dh

# task 2

def verify_signature(public_key, signature, role, transcript_hash):
    try:
        public_key.verify(
            signature,
            role + transcript_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"{role.capitalize()} signature verification failed:", str(e))
        return False

def session(gateway_rsa_private_key, node_rsa_private_key):
    # STEP 1: Generate fresh random values
    print("generating fresh random values")
    # Gateway long-term RSA key pair
    gateway_rsa_public_key = gateway_rsa_private_key.public_key()

    # Node long-term RSA key pair
    node_rsa_public_key = node_rsa_private_key.public_key()

    #### SESSION ####
    # STEP 2
    # fresh DH parameters using ffdhe3072, fresh 16-byte nonces
    # load group file
    with open(os.path.join(os.path.dirname(__file__), "ffdhe3072.pem"), "rb") as f:
        ffdhe3072_pem = f.read()
    ffdhe3072_parameters = serialization.load_pem_parameters(ffdhe3072_pem) #load_pem_dh_aramters

    print("generating diffie-hellman keys")
    gateway_dh_private_key = ffdhe3072_parameters.generate_private_key()
    gateway_dh_public_key = gateway_dh_private_key.public_key()

    node_dh_private_key = ffdhe3072_parameters.generate_private_key()
    node_dh_public_key = node_dh_private_key.public_key()

    gateway_nonce = os.urandom(16)
    node_nonce = os.urandom(16)

    # construct ONE transcript

    #   protocol label CSCE465-HS-v2, group identifier ffdhe3072, and both party identities;
    #   both ephemeral Diffie–Hellman public values and both random nonces
    #           Encode the transcript as those fields concatenated in that exact order, each preceded by its
    #           length as a 4-byte big-endian integer (a length-prefixed / TLV encoding). Plain
    #           concatenation is ambiguous (two different field splits can produce the same byte string), so
    #           a length-prefixed encoding is required for the transcript to be truly canonical. A field with an
    #           incorrectly declared length must be rejected before hashing.

    print("generating transcript")
    transcript = b""
    transcript += len(b"CSCE465-HS-v2").to_bytes(4, byteorder='big') + b"CSCE465-HS-v2"
    transcript += len(b"ffdhe3072").to_bytes(4, byteorder='big') + b"ffdhe3072"
    transcript += len(b"gateway").to_bytes(4, byteorder='big') + b"gateway"
    transcript += len(b"node").to_bytes(4, byteorder='big') + b"node"
    transcript += len(gateway_dh_public_key.public_numbers().y.to_bytes(384, byteorder="big")).to_bytes(4, byteorder='big') + gateway_dh_public_key.public_numbers().y.to_bytes(384, byteorder="big")
    transcript += len(node_dh_public_key.public_numbers().y.to_bytes(384, byteorder="big")).to_bytes(4, byteorder='big') + node_dh_public_key.public_numbers().y.to_bytes(384, byteorder="big")
    transcript += len(gateway_nonce).to_bytes(4, byteorder='big') + gateway_nonce
    transcript += len(node_nonce).to_bytes(4, byteorder='big') + node_nonce

    # print("Transcript:", transcript.hex())

    # STEP 4
    TH = hashes.Hash(hashes.SHA256())
    TH.update(transcript)
    transcript_hash = TH.finalize()

    # Each party signs role || SHA-256(transcript)
    gateway_signature = gateway_rsa_private_key.sign(
        b"gateway" + transcript_hash,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    node_signature = node_rsa_private_key.sign(
        b"node" + transcript_hash,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    # verifies the peer RSA-PSS signature
    # rejects an unexpected identity before accepting the session.

    # verify gateway signature
    if not verify_signature(gateway_rsa_public_key, gateway_signature, b"gateway", transcript_hash):
        raise ValueError("Gateway signature verification failed.")

    # verify node signature
    if not verify_signature(node_rsa_public_key, node_signature, b"node", transcript_hash):
        raise ValueError("Node signature verification failed.")

    # STEP 5
    # Let TH = SHA-256(transcript) and let Z be the Diffie–Hellman shared secret encoded as a 384-byte
    # big-endian string, the byte width of the ffdhe3072 modulus (3072 bits), zero-padded on the left if the
    # integer is shorter. Encode each party's ephemeral Diffie–Hellman public value the same way (384-
    # byte big-endian) wherever it appears in the transcript.

    gateway_Z = gateway_dh_private_key.exchange(node_dh_public_key)

    node_Z = node_dh_private_key.exchange(gateway_dh_public_key)

    assert gateway_Z == node_Z, "shared secret does not match"

    K_master = hashes.Hash(hashes.SHA256())
    K_master.update(b"CSCE465-KDF-v1" + gateway_Z + transcript_hash)

    KM = K_master.finalize()

    K_g2n_enc = hmac.HMAC(KM, hashes.SHA256())
    K_g2n_enc.update(b"gateway-to-node encryption" + transcript_hash)
    K_g2n_enc = K_g2n_enc.finalize()

    K_g2n_mac = hmac.HMAC(KM, hashes.SHA256())
    K_g2n_mac.update(b"gateway-to-node MAC" + transcript_hash)
    K_g2n_mac = K_g2n_mac.finalize()

    K_n2g_enc = hmac.HMAC(KM, hashes.SHA256())
    K_n2g_enc.update(b"node-to-gateway encryption" + transcript_hash)
    K_n2g_enc = K_n2g_enc.finalize()

    K_n2g_mac = hmac.HMAC(KM, hashes.SHA256())
    K_n2g_mac.update(b"node-to-gateway MAC" + transcript_hash)
    K_n2g_mac = K_n2g_mac.finalize()

    session_id = hmac.HMAC(KM, hashes.SHA256())
    session_id.update(b"session identifier" + transcript_hash)
    session_id = session_id.finalize()[:8]  # first 8 bytes

    print("Handshake completed successfully.")
    print(f"Session ID (8 bytes hex): {session_id.hex()}")
    print(f"K_g2n_enc: {K_g2n_enc.hex()}")
    print(f"K_n2g_enc: {K_n2g_enc.hex()}")

    return {
        "session_id": session_id,
        "K_g2n_enc": K_g2n_enc,
        "K_g2n_mac": K_g2n_mac,
        "K_n2g_enc": K_n2g_enc,
        "K_n2g_mac": K_n2g_mac
    }
    # K_master = SHA-256("CSCE465-KDF-v1" || Z || TH)
    # K_g2n_enc = HMAC-SHA-256(K_master, "gateway-to-node encryption" || TH)
    # K_g2n_mac = HMAC-SHA-256(K_master, "gateway-to-node MAC" || TH)
    # K_n2g_enc = HMAC-SHA-256(K_master, "node-to-gateway encryption" || TH)
    # K_n2g_mac = HMAC-SHA-256(K_master, "node-to-gateway MAC" || TH)
    # session_id = first 8 bytes of HMAC-SHA-256(K_master, "session identifier" || TH)

if __name__ == "__main__":
    # STEP 1
    print("generating key pairs...")
    # Gateway long-term RSA key pair
    gateway_rsa_private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    gateway_rsa_public_key = gateway_rsa_private_key.public_key()

    # Node long-term RSA key pair
    node_rsa_private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    node_rsa_public_key = node_rsa_private_key.public_key()

    while True:
        print("\nStarting a new handshake...\n")
        session(gateway_rsa_private_key, node_rsa_private_key)
        input("\nPress Enter to start a new handshake or Ctrl+C to exit...")
    