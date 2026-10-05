question: (pasted task 2 and 3 instructions) How do these two tasks relate to each other?

response: Task 2 and Task 3 form **two layers of the same secure communication protocol**:

 - **Task 2 = handshake/key establishment.** Gateway and node authenticate each other using RSA-PSS signatures, perform ephemeral finite-field Diffie–Hellman, and derive separate encryption/MAC keys plus a `session_id`.
- **Task 3 = protected data communication.** It takes those derived keys and uses them to securely encrypt and authenticate application records with AES-256-CTR + HMAC-SHA-256.

 The flow is essentially:

 `RSA authentication + ephemeral DH → shared secret Z → K_master → directional keys/session_id → encrypted records`

 Task 2 provides **who you're talking to and fresh session keys**; Task 3 uses those keys to provide **confidentiality, integrity, replay protection, and direction separation** for actual messages.

 The `session_id` and sequence number from Task 2/3 also connect directly: Task 3 constructs each IV as `session_id || sequence`, ensuring unique IVs for each direction under the derived encryption key.