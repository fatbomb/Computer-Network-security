import socket
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.asymmetric.padding import PSS, MGF1
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import os
import json
from datetime import datetime


class EnhancedClient:
    def __init__(self, host='localhost', port=12345):
        self.host = host
        self.port = port
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.dh_parameters = None
        self.dh_private_key = None
        self.dh_public_key = None
        self.shared_secret = None
        self.aes_key = None
        self.server_rsa_public_key = None
        self.log_file = "client_log.txt"

        # Initialize log file
        with open(self.log_file, 'w') as f:
            f.write("CLIENT LOG - Started at: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\n")
            f.write("=" * 50 + "\n\n")

    def log(self, message, level="INFO"):
        """Log messages with timestamp and level"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{level}] {message}\n"
        print(log_entry.strip())
        with open(self.log_file, 'a') as f:
            f.write(log_entry)

    def connect(self):
        """Connect to server"""
        self.log(f"Connecting to server at {self.host}:{self.port}...")
        self.client_socket.connect((self.host, self.port))
        self.log("Connected to server successfully")

    def perform_key_exchange(self):
        """Perform Diffie-Hellman key exchange"""
        self.log("Starting key exchange with server...")

        # Receive DH parameters from server
        self.log("Waiting for DH parameters from server...")
        dh_params_len = int.from_bytes(self.client_socket.recv(4), 'big')
        dh_params_bytes = self.client_socket.recv(dh_params_len)
        self.dh_parameters = serialization.load_pem_parameters(
            dh_params_bytes,
            backend=default_backend()
        )
        self.log("Received DH parameters from server")

        # Receive server's DH public key
        self.log("Waiting for server's DH public key...")
        server_dh_pub_key_len = int.from_bytes(self.client_socket.recv(4), 'big')
        server_dh_pub_key_bytes = self.client_socket.recv(server_dh_pub_key_len)

        # Receive server's RSA public key
        self.log("Waiting for server's RSA public key...")
        server_rsa_pub_key_len = int.from_bytes(self.client_socket.recv(4), 'big')
        server_rsa_pub_key_bytes = self.client_socket.recv(server_rsa_pub_key_len)
        self.server_rsa_public_key = serialization.load_pem_public_key(
            server_rsa_pub_key_bytes,
            backend=default_backend()
        )
        self.log("Received server's RSA public key")

        # Generate client's DH keys
        self.log("Generating client DH keys...")
        self.dh_private_key = self.dh_parameters.generate_private_key()
        self.dh_public_key = self.dh_private_key.public_key()

        # Send client's DH public key to server
        client_dh_pub_key_bytes = self.dh_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.client_socket.send(len(client_dh_pub_key_bytes).to_bytes(4, 'big'))
        self.client_socket.send(client_dh_pub_key_bytes)
        self.log("Sent client's DH public key to server")

        # Derive shared secret
        server_dh_public_key = serialization.load_pem_public_key(
            server_dh_pub_key_bytes,
            backend=default_backend()
        )
        self.shared_secret = self.dh_private_key.exchange(server_dh_public_key)
        self.log(f"Shared secret derived: {self.shared_secret.hex()[:20]}...")

        # Derive AES key
        self.derive_aes_key()
        self.log("Key exchange completed successfully")

    def derive_aes_key(self):
        """Derive AES key from shared secret using HKDF"""
        self.log("Deriving AES key using HKDF...")
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # 256-bit key for AES
            salt=None,
            info=b'AES key derivation',
            backend=default_backend()
        )
        self.aes_key = hkdf.derive(self.shared_secret)
        self.log(f"AES key derived: {self.aes_key.hex()[:20]}...")

    def encrypt_aes(self, data):
        """Encrypt data using AES-CTR mode"""
        self.log(f"Encrypting data: {data[:20]}...")
        iv = os.urandom(16)  # 128-bit IV for CTR mode
        cipher = Cipher(algorithms.AES(self.aes_key), modes.CTR(iv),
                       backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(data) + encryptor.finalize()
        result = iv + encrypted_data
        self.log(f"Encrypted data: {result.hex()[:20]}...")
        return result

    def decrypt_aes(self, encrypted_data):
        """Decrypt data using AES-CTR mode"""
        self.log(f"Decrypting data: {encrypted_data.hex()[:20]}...")
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        cipher = Cipher(algorithms.AES(self.aes_key), modes.CTR(iv),
                       backend=default_backend())
        decryptor = cipher.decryptor()
        result = decryptor.update(ciphertext) + decryptor.finalize()
        self.log(f"Decrypted data: {result.decode()}")
        return result

    def verify_signature(self, data, signature):
        """Verify signature using server's RSA public key"""
        self.log(f"Verifying signature for data: {data[:20]}...")
        try:
            self.server_rsa_public_key.verify(
                signature,
                data,
                PSS(
                    mgf=MGF1(hashes.SHA256()),
                    salt_length=PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            self.log("Signature verification: VALID", "SUCCESS")
            return True
        except InvalidSignature:
            self.log("Signature verification: INVALID", "ERROR")
            return False

    def send_message(self, message):
        """Send encrypted message to server"""
        self.log(f"Sending message: {message}")
        encrypted_msg = self.encrypt_aes(message.encode())
        self.client_socket.send(len(encrypted_msg).to_bytes(4, 'big'))
        self.client_socket.send(encrypted_msg)

        # Receive response
        response_len = int.from_bytes(self.client_socket.recv(4), 'big')
        encrypted_response = self.client_socket.recv(response_len)
        decrypted_response = self.decrypt_aes(encrypted_response)
        self.log(f"Server response: {decrypted_response.decode()}")

    def request_signature(self, data):
        """Request server to sign data and verify it"""
        self.log(f"Requesting signature for: {data}")
        message = f"SIGN:{data}".encode()
        encrypted_msg = self.encrypt_aes(message)
        self.client_socket.send(len(encrypted_msg).to_bytes(4, 'big'))
        self.client_socket.send(encrypted_msg)

        # Receive signature
        signature_len = int.from_bytes(self.client_socket.recv(4), 'big')
        signature = self.client_socket.recv(signature_len)

        # Verify signature
        is_valid = self.verify_signature(data.encode(), signature)
        return is_valid

    def test_tampered_data(self, original_data, tampered_data):
        """Test signature verification with tampered data"""
        self.log("Testing tampered data detection...", "WARNING")
        self.log(f"Original data: {original_data}")
        self.log(f"Tampered data: {tampered_data}")

        # Request server to sign the original data but send both for testing
        message = f"TAMPER_TEST:{original_data}:{tampered_data}".encode()
        encrypted_msg = self.encrypt_aes(message)
        self.client_socket.send(len(encrypted_msg).to_bytes(4, 'big'))
        self.client_socket.send(encrypted_msg)

        # Receive response
        response_len = int.from_bytes(self.client_socket.recv(4), 'big')
        encrypted_response = self.client_socket.recv(response_len)
        decrypted_response = self.decrypt_aes(encrypted_response)

        response_data = json.loads(decrypted_response.decode())
        signature = bytes.fromhex(response_data["signature"])

        self.log("Testing with original data (should succeed):")
        valid_original = self.verify_signature(original_data.encode(), signature)

        self.log("Testing with tampered data (should fail):")
        valid_tampered = self.verify_signature(tampered_data.encode(), signature)

        return valid_original, valid_tampered

    def run(self):
        """Main client execution"""
        try:
            self.connect()
            self.perform_key_exchange()

            # Test symmetric encryption
            self.log("\n--- Testing Symmetric Encryption ---", "HEADER")
            test_messages = [
                "Hello, Server!",
                "This is a secret message",
                "Testing AES-CTR mode"
            ]

            for msg in test_messages:
                self.log(f"\nSending: {msg}")
                self.send_message(msg)

            # Test asymmetric signature
            self.log("\n--- Testing Asymmetric Signature ---", "HEADER")
            data_to_sign = "Important data that needs signing"
            self.log(f"Requesting signature for: {data_to_sign}")
            self.request_signature(data_to_sign)

            # Test tampered data detection
            self.log("\n--- Testing Tampered Data Detection ---", "HEADER")
            original = "This is the original message"
            tampered = "This is the tampered message"
            valid_original, valid_tampered = self.test_tampered_data(original, tampered)

            self.log(f"Original data verification: {'SUCCESS' if valid_original else 'FAILED'}",
                "SUCCESS" if valid_original else "ERROR")
            self.log(f"Tampered data verification: {'SUCCESS' if valid_tampered else 'FAILED'}",
                "SUCCESS" if valid_tampered else "ERROR")

            if not valid_original and not valid_tampered:
                self.log("Both tests failed - this might indicate an issue with the signature", "WARNING")

        except Exception as e:
            self.log(f"Error: {e}", "ERROR")
        finally:
            self.client_socket.close()
            self.log("Client connection closed")

if __name__ == "__main__":
    client = EnhancedClient()
    client.run()
