# PSB7031CE-Cryptography
**Course: PSB7031CE - Cryptography
Student: Lu Hanhao
Student ID: 14090147
Project Overview**
This project implements three cryptographic schemes for different scenarios:

IoT Device Encryption - ChaCha20 stream cipher
Banking Transaction System - AES-256-CBC + RSA-2048 hybrid encryption
Enterprise File Sharing - AES-128-CBC + ECDH key negotiation

File Description
ChaCha20.py

Scenario: IoT device data transmission
Algorithm: ChaCha20 stream cipher with 256-bit key
Features: Lightweight, suitable for resource-constrained devices

AES-256 + RSA-2048.py

Scenario: Banking financial transactions
Algorithm: AES-256-CBC + RSA-2048 hybrid encryption
Features: Maximum security level with digital signatures

AES-128 + ECDH.py

Scenario: Enterprise file sharing
Algorithm: AES-128-CBC + ECDH key negotiation
Features: Elliptic curve key exchange, efficient file encryption

Runtime Environment
bashpip install cryptography==45.0.4
System Requirements:

Python 3.11+
cryptography library version 45.0.4

How to Run
bash# IoT encryption demo
python ChaCha20.py

# Banking encryption demo
python "AES-256 + RSA-2048.py"

# Enterprise encryption demo
python "AES-128 + ECDH.py"
Output Results
Each script displays:

Encryption and decryption process demonstration
Performance testing (1KB, 1MB, 10MB data)
Encryption and decryption timing
Security verification results

Code Structure
Each implementation includes:

Encryption class definition
Key generation
Encryption method
Decryption method
Performance testing
Demo functionality

Usage Instructions
This code is an academic research project that demonstrates practical applications and performance comparisons of cryptographic algorithms in different scenarios. The code follows security best practices and uses mature cryptographic libraries.
Disclaimer
This code is for educational and research purposes only and is not suitable for direct use in production environments.
