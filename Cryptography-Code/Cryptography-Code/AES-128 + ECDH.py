import os
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class EnterpriseEncryption:
    def __init__(self):
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()
        print("Enterprise File Encryption System Initialized - AES-128 + ECDH")

    def generate_shared_key(self, peer_public_key):
        shared_key = self.private_key.exchange(ec.ECDH(), peer_public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=16,
            salt=None,
            info=b'enterprise_file_key'
        ).derive(shared_key)
        return derived_key

    def encrypt(self, data, peer_public_key):
        aes_key = self.generate_shared_key(peer_public_key)
        plaintext = data.encode('utf-8')
        iv = os.urandom(16)
        pad_len = 16 - (len(plaintext) % 16)
        padded_data = plaintext + bytes([pad_len] * pad_len)
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return {
            'ciphertext': ciphertext,
            'iv': iv,
            'public_key': self.public_key
        }

    def decrypt(self, encrypted_data, sender_public_key):
        aes_key = self.generate_shared_key(sender_public_key)
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(encrypted_data['iv']))
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted_data['ciphertext']) + decryptor.finalize()
        pad_len = padded_data[-1]
        plaintext = padded_data[:-pad_len]
        return plaintext.decode('utf-8')


def main():
    print("=== Enterprise File Encryption Demo ===")
    user_alice = EnterpriseEncryption()
    user_bob = EnterpriseEncryption()
    file_content = """
        CONFIDENTIAL BUSINESS DOCUMENT
        Project: ABCDE
        Department: Engineering & Development
        Budget: $12,400,000
        Timeline: Q1-Q4 2025
        Team: 12 engineers
        This is just confidential information I wrote casually, 
        with the sole purpose of increasing the number of words 
        in the plain text as much as possible.
    """.strip()
    print(f"\nOriginal File Data:")
    print(f"Content preview: {file_content[:200]}...")
    print(f"Byte count: {len(file_content.encode('utf-8'))} bytes")
    encrypted = user_alice.encrypt(file_content, user_bob.public_key)
    print(f"\nEncrypted Data:")
    print(f"Ciphertext size: {len(encrypted['ciphertext'])} bytes")
    print(f"Ciphertext: {encrypted['ciphertext'].hex()}")
    print(f"IV: {encrypted['iv'].hex()}")
    decrypted = user_bob.decrypt(encrypted, user_alice.public_key)
    print(f"\nDecrypted Data:")
    print(f"Content preview: {decrypted}")
    print(f"Verification: {'Success' if file_content == decrypted else 'Failure'}")
    print(f"\n=== Performance Test ===")
    test_sizes = [1000, 1000000, 10000000]
    for size in test_sizes:
        test_data = "A" * size
        start_time = time.perf_counter()
        encrypted = user_alice.encrypt(test_data, user_bob.public_key)
        encrypt_time = time.perf_counter() - start_time
        start_time = time.perf_counter()
        decrypted = user_bob.decrypt(encrypted, user_alice.public_key)
        decrypt_time = time.perf_counter() - start_time
        print(f"{size:6d} bytes: Encrypt {encrypt_time * 1000:.3f}ms, Decrypt {decrypt_time * 1000:.3f}ms")


if __name__ == "__main__":
    main()