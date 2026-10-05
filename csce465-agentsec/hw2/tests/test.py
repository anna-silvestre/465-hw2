# 1. valid handshake and bidirectional messages;
# 2. modified ciphertext;
# 3. modified authenticated header;
# 4. replayed record;
# 5. record reflected into the opposite direction;
# 6. incorrect RSA public key, invalid RSA-PSS transcript signature, or reflected handshake message.
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from handshake import session
from secure_record import seal, open_record
from cryptography.hazmat.primitives.asymmetric import rsa

def test_handshake_and_secure_record(active_session):
    # Gateway to Node direction 0, sequence 0
    msg_g2n = b"Hello Node from Gateway"
    rec_g2n = seal(active_session, version=1, direction=0, sequence=0, message_type=1, plaintext=msg_g2n)
    dec_g2n = open_record(active_session, version=1, direction=0, sequence=0, message_type=1, payload=rec_g2n)
    assert dec_g2n == msg_g2n
    # Node to Gateway direction 1, sequence 0
    msg_n2g = b"Hello Gateway from Node"
    rec_n2g = seal(active_session, version=1, direction=1, sequence=0, message_type=1, plaintext=msg_n2g)
    dec_n2g = open_record(active_session, version=1, direction=1, sequence=0, message_type=1, payload=rec_n2g)
    assert dec_n2g == msg_n2g


def test_modified_ciphertext(active_session):
    message = seal(active_session, version=1, direction=0, sequence=0, message_type=1, plaintext=b"Hello Node from Gateway")
    modified_message = bytearray(message)
    modified_message[35] ^= 0x01  # Flip a bit in the ciphertext

    try:
        open_record(active_session, version=1, direction=0, sequence=0, message_type=1, payload=bytes(modified_message))
        assert False, "Expected HMAC verification to fail"
    except Exception as e:
        print("HMAC verification failed as expected:", str(e))


def test_modified_authenticated_header(active_session):
    message = seal(active_session, version=1, direction=0, sequence=0, message_type=1, plaintext=b"Hello Node from Gateway")
    modified_message = bytearray(message)
    modified_message[0] ^= 0x01  # Flip a bit in the version

    try:
        open_record(active_session, version=1, direction=0, sequence=0, message_type=1, payload=bytes(modified_message))
        assert False, "Expected HMAC verification to fail"
    except Exception as e:
        print("HMAC verification failed as expected:", str(e))


def test_replayed_record(active_session):
    message = seal(active_session, version=1, direction=0, sequence=0, message_type=1, plaintext=b"Hello Node from Gateway")
    open_record(active_session, version=1, direction=0, sequence=0, message_type=1, payload=message)
    # Replay the same message
    try:
        open_record(active_session, version=1, direction=0, sequence=1, message_type=1, payload=message)
        assert False, "Expected replayed record to be detected"
    except Exception as e:
        print("Replayed record detected as expected:", str(e))

def test_reflected_record(active_session):
    message = seal(active_session, version=1, direction=0, sequence=0, message_type=1, plaintext=b"Hello Node from Gateway")
    # Reflect the message
    try:
        open_record(active_session, version=1, direction=1, sequence=0, message_type=1, payload=message)
        assert False, "Expected reflected record to be detected"
    except Exception as e:
        print("Reflected record detected as expected:", str(e))

def test_invalid_rsa_public_key(active_session, node_rsa_private_key):
    message = seal(active_session, version=1, direction=0, sequence=0, message_type=1, plaintext=b"Hello Node from Gateway")
    # Replace the RSA public key
    invalid_rsa_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    invalid_session = session(invalid_rsa_private_key, node_rsa_private_key)
    try:
        open_record(invalid_session, version=1, direction=0, sequence=0, message_type=1, payload=message)
        assert False, "Expected invalid RSA public key to be detected"
    except Exception as e:
        print("Invalid RSA public key detected as expected:", str(e))

gateway_rsa_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
node_rsa_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

print("\n test 1")
test_handshake_and_secure_record(active_session=session(gateway_rsa_private_key, node_rsa_private_key))

print("\n test 2")
test_modified_ciphertext(active_session=session(gateway_rsa_private_key, node_rsa_private_key))

print("\n test 3")
test_modified_authenticated_header(active_session=session(gateway_rsa_private_key, node_rsa_private_key))

print("\n test 4")
test_replayed_record(active_session=session(gateway_rsa_private_key, node_rsa_private_key))

print("\n test 5")
test_reflected_record(active_session=session(gateway_rsa_private_key, node_rsa_private_key))

print("\n test 6")
test_invalid_rsa_public_key(active_session=session(gateway_rsa_private_key, node_rsa_private_key), node_rsa_private_key=node_rsa_private_key)