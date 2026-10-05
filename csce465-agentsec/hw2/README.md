# CSCE 465/765 HW2: Secure Agent Message Framework

This repository is for homework 2

---

## Repository Structure
```text
hw2/
├── baseline_ctr.py      # Task 1
├── handshake.py         # Task 2
├── secure_record.py     # Task 3
├── ffdhe3072.pem        # Task 2
├── tests/
│   └── test.py          # Task 4
├── report.pdf           
├── README.md            
├── AI_USAGE.md          
└── AI_LOGS/             

1. Environment Setup
Activate Virtual Environment and Install Dependencies
From the repository root (csce465-agentsec):
# Create and activate the virtual environment
python3 -m venv .venv
source .venv/bin/activate
# Upgrade pip and install exact dependency versions
python -m pip install --upgrade pip
python -m pip install cryptography==49.0.0 pytest==9.1.1
Generate Group File
Generate the standard 3072-bit Diffie–Hellman parameter file required for Task 2:
cd hw2
openssl genpkey -genparam -algorithm DH -pkeyopt group:ffdhe3072 -out ffdhe3072.pem

2. Running the Code & Tasks
Task 1: AES-CTR Bit-Flip and Replay Demo
Demonstrates why encryption without integrity fails against byte manipulation and replay attacks:
python baseline_ctr.py
Task 2: Authenticated Handshake Demo
Runs the interactive/standalone Diffie–Hellman handshake execution using RSA-PSS signatures:
python handshake.py
Task 4: Running the Automated Test Suite
To run all adversarial test cases directly via Python:
python tests/test.py
Or using pytest:
pytest tests/

3. Test Cases Covered
1. valid handshake and bidirectional messages;
2. modified ciphertext;
3. modified authenticated header;
4. replayed record;
5. record reflected into the opposite direction;
6. incorrect RSA public key