import os
import time
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes


class BankingEncryption:
    def __init__(self):
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()

    def encrypt(self, data, recipient_public_key):
        session_key = os.urandom(32)
        plaintext = data.encode('utf-8')
        iv = os.urandom(16)
        pad_len = 16 - (len(plaintext) % 16)
        padded_data = plaintext + bytes([pad_len] * pad_len)
        cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        encrypted_key = recipient_public_key.encrypt(
            session_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                         algorithm=hashes.SHA256(), label=None)
        )
        signature = self.private_key.sign(
            plaintext,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return {
            'encrypted_data': encrypted_data,
            'encrypted_key': encrypted_key,
            'iv': iv,
            'signature': signature
        }

    def decrypt(self, encrypted_package, sender_public_key):
        session_key = self.private_key.decrypt(
            encrypted_package['encrypted_key'],
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                         algorithm=hashes.SHA256(), label=None)
        )
        cipher = Cipher(algorithms.AES(session_key), modes.CBC(encrypted_package['iv']))
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted_package['encrypted_data']) + decryptor.finalize()
        pad_len = padded_data[-1]
        plaintext = padded_data[:-pad_len]
        sender_public_key.verify(
            encrypted_package['signature'],
            plaintext,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return plaintext.decode('utf-8')


def main():
    print("=== Banking Transaction Encryption Demo ===")
    bank_a = BankingEncryption()
    bank_b = BankingEncryption()
    transaction_data = json.dumps({
        "transaction_id": "TXN202500001111",
        "from_account": "ACC-123456789",
        "to_account": "ACC-987654321",
        "amount": 50000.00,
        "currency": "USD",
        "description": "None"
    }, ensure_ascii=False)
    print(f"\nOriginal Data:")
    print(f"Plaintext: {transaction_data}")
    print(f"Plaintext size: {len(transaction_data.encode('utf-8'))} bytes")
    encrypted = bank_a.encrypt(transaction_data, bank_b.public_key)
    print(f"\n=== Step 1: AES-256 Encryption ===")
    print(f"Ciphertext size: {len(encrypted['encrypted_data'])} bytes")
    print(f"Ciphertext: {encrypted['encrypted_data'].hex()}")
    print(f"Signature size: {len(encrypted['signature'])} bytes")
    print(f"Digital Signature: {encrypted['signature'].hex()}")
    print(f"\n=== Step 2: RSA-2048 Key Encryption ===")
    print(f"Encrypted key size: {len(encrypted['encrypted_key'])} bytes")
    print(f"RSA ciphertext: {encrypted['encrypted_key'].hex()}")
    total_size = len(encrypted['encrypted_data']) + len(encrypted['encrypted_key']) + len(encrypted['signature'])
    print(f"\nTotal encrypted data size: {total_size} bytes")
    try:
        decrypted = bank_b.decrypt(encrypted, bank_a.public_key)
        print(f"\n=== Decryption & Verification ===")
        print(f"Decrypted content: {decrypted}")
        print(f"Content verification: {'Success' if transaction_data == decrypted else 'Failure'}")
        print(f"Signature: Verified")
    except Exception as e:
        print(f"Decryption failed: {e}")
    print(f"\n=== Performance Test ===")
    test_sizes = [1000, 1000000, 10000000]
    for size in test_sizes:
        test_data = "X" * size
        start_time = time.perf_counter()
        encrypted = bank_a.encrypt(test_data, bank_b.public_key)
        encrypt_time = time.perf_counter() - start_time
        start_time = time.perf_counter()
        decrypted = bank_b.decrypt(encrypted, bank_a.public_key)
        decrypt_time = time.perf_counter() - start_time
        print(f"{size:5d} bytes: Encrypt {encrypt_time * 1000:.3f}ms, Decrypt {decrypt_time * 1000:.3f}ms")


if __name__ == "__main__":
    main()