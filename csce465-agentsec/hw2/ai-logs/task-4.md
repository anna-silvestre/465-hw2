message: "How do I go about implementing task 4 tests?"

response: To implement Task 4, you'll set up automated unit tests in the tests/ directory (typically using pytest) to verify that your system operates correctly in valid runs and fails safely when subjected to adversarial tampering1.Task 4 explicitly requires automated tests covering 6 specific adversarial scenarios1. Here is how to structure each test:1. Structure of tests/test_secure_record.pyYou can use a pytest suite that imports your session (or run_handshake) from handshake.py and seal / open_record from secure_record.py:import pytest
from handshake import session, GW_RSA_PRIV, GW_RSA_PUB, NODE_RSA_PRIV, NODE_RSA_PUB
from secure_record import seal, open_record

@pytest.fixture
def active_session():
    """Fixture that generates fresh long-term RSA keys and completes a valid handshake."""
    # Returns handshake_details dictionary with K_g2n_enc, K_g2n_mac, K_n2g_enc, K_n2g_mac, session_id
    return session(GW_RSA_PRIV, NODE_RSA_PRIV)
2. The 6 Required Test CasesTest 1: Valid Handshake & Bidirectional MessagesVerify that a clean handshake completes and messages can be sealed and opened in both directions (Gateway $\rightarrow$ Node with direction 0, Node $\rightarrow$ Gateway with direction 1)1.def test_valid_bidirectional_flow(active_session):
    # Gateway to Node (direction=0, sequence=0)
    msg_g2n = b"Hello Node from Gateway"
    rec_g2n = seal(active_session, version=1, direction=0, sequence=0, message_type=1, plaintext=msg_g2n)
    dec_g2n = open_record(active_session, expected_version=1, expected_direction=0, expected_sequence=0, expected_message_type=1, payload=rec_g2n)
    assert dec_g2n == msg_g2n

    # Node to Gateway (direction=1, sequence=0)
    msg_n2g = b"Hello Gateway from Node"
    rec_n2g = seal(active_session, version=1, direction=1, sequence=0, message_type=1, plaintext=msg_n2g)
    dec_n2g = open_record(active_session, expected_version=1, expected_direction=1, expected_sequence=0, expected_message_type=1, payload=rec_n2g)
    assert dec_n2g == msg_n2g
Test 2: Modified CiphertextFlip a single bit inside the ciphertext section of the record and verify that open_record() rejects it via MAC verification failure before attempting decryption12.def test_modified_ciphertext(active_session):
    record = seal(active_session, version=1, direction=0, sequence=0, message_type=1, plaintext=b"Secret Data")
    
    # Mutate a byte in the ciphertext portion (bytes 31 to -32)
    tampered = bytearray(record)
    tampered[3] ^= 0xFF  # Bit-flip in ciphertext
    
    with pytest.raises(ValueError, match="HMAC verification failed"):
        open_record(active_session, expected_version=1, expected_direction=0, expected_sequence=0, expected_message_type=1, payload=bytes(tampered))
Test 3: Modified Authenticated HeaderMutate a header byte (e.g., sequence number or message type in bytes 0..14). Because the MAC covers the header, h.verify() must fail12.def test_modified_header(active_session):
    record = seal(active_session, version=1, direction=0, sequence=0, message_type=1, plaintext=b"Secret Data")
    
    # Mutate sequence number in header (byte index 2)
    tampered = bytearray(record)
    tampered[4] ^= 0x01
    
    with pytest.raises(ValueError, match="HMAC verification failed"):
        open_record(active_session, expected_version=1, expected_direction=0, expected_sequence=0, expected_message_type=1, payload=bytes(tampered))
Test 4: Replayed RecordAttempt to open the exact same valid record a second time when the receiver expects the next sequence number (sequence=1)12.def test_replayed_record(active_session):
    record = seal(active_session, version=1, direction=0, sequence=0, message_type=1, plaintext=b"Command")
    
    # First arrival succeeds
    open_record(active_session, expected_version=1, expected_direction=0, expected_sequence=0, expected_message_type=1, payload=record)
    
    # Replay arrival fails sequence check
    with pytest.raises(ValueError, match="Sequence mismatch"):
        open_record(active_session, expected_version=1, expected_direction=0, expected_sequence=1, expected_message_type=1, payload=record)
Test 5: Record Reflected in Opposite DirectionTake a valid Gateway $\rightarrow$ Node record (direction=0) and attempt to feed it to a receiver expecting Node $\rightarrow$ Gateway (expected_direction=1). The MAC check fails because different directional keys (K_g2n_mac vs. K_n2g_mac) are used12.def test_reflected_record_direction(active_session):
    record = seal(active_session, version=1, direction=0, sequence=0, message_type=1, plaintext=b"Gateway Command")
    
    # Attacker reflects G2N message back to Gateway (which expects direction=1)
    with pytest.raises(ValueError, match="HMAC verification failed"):
        open_record(active_session, expected_version=1, expected_direction=1, expected_sequence=0, expected_message_type=1, payload=record)
Test 6: Invalid RSA-PSS Signature or Handshake TamperingVerify that if an attacker alters a nonce or DH public value during the handshake, signature verification fails and no session keys are returned13.def test_invalid_handshake_signature():
    # Simulate a handshake where an attacker modifies the transcript signature or role
    from handshake import verify_signature, GW_RSA_PUB
    
    bad_signature = b"\x00" * 384  # Forged/garbage signature
    fake_transcript_hash = b"\x00" * 32
    
    assert verify_signature(GW_RSA_PUB, bad_signature, b"gateway", fake_transcript_hash) is False
Running the SuiteYou can execute your tests in the course VM by running:pytest tests/
💡 Would you like to review what needs to go into the 500–700 word Security Note section of your report.pdf next1?infoSaved responses are view onlyconvert_to_text Convert to source 