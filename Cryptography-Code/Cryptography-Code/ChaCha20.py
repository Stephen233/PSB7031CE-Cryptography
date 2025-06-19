import os
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms


class IoTEncryption:
    def __init__(self):
        self.key = os.urandom(32)
        print("IoT Device Initialized - ChaCha20 Encryption")

    def encrypt(self, data):
        plaintext = data.encode('utf-8')
        nonce = os.urandom(16)
        cipher = Cipher(algorithms.ChaCha20(self.key, nonce), mode=None)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return {'ciphertext': ciphertext, 'nonce': nonce}

    def decrypt(self, encrypted_data):
        cipher = Cipher(algorithms.ChaCha20(self.key, encrypted_data['nonce']), mode=None)
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(encrypted_data['ciphertext']) + decryptor.finalize()
        return plaintext.decode('utf-8')


def main():
    print("=== IoT Device Encryption Demo ===")
    iot = IoTEncryption()
    sensor_data = "122333444455555"
    print(f"\nOriginal Data:")
    print(f"Content: {sensor_data}")
    print(f"Byte count: {len(sensor_data.encode('utf-8'))} bytes")
    encrypted = iot.encrypt(sensor_data)
    print(f"\nEncrypted Data:")
    print(f"Ciphertext size: {len(encrypted['ciphertext'])} bytes")
    print(f"Ciphertext: {encrypted['ciphertext'].hex()}")
    print(f"Nonce: {encrypted['nonce'].hex()}")
    decrypted = iot.decrypt(encrypted)
    print(f"\nDecrypted Data:")
    print(f"Content: {decrypted}")
    print(f"Verification: {'Success' if sensor_data == decrypted else 'Failure'}")
    print(f"\n=== Performance Test ===")
    test_sizes = [1000, 1000000, 10000000]
    for size in test_sizes:
        test_data = "X" * size
        start_time = time.perf_counter()
        encrypted = iot.encrypt(test_data)
        encrypt_time = time.perf_counter() - start_time
        start_time = time.perf_counter()
        decrypted = iot.decrypt(encrypted)
        decrypt_time = time.perf_counter() - start_time
        print(f"{size:6d} bytes: Encrypt {encrypt_time * 1000:.3f}ms, Decrypt {decrypt_time * 1000:.3f}ms")


if __name__ == "__main__":
    main()