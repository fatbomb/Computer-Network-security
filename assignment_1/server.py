import socket
import threading
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import dh, rsa
from cryptography.hazmat.primitives.asymmetric.padding import PSS, MGF1
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import os
import json
from datetime import datetime

class EnhancedServer:
    def __init__(self, host='localhost', port=12345):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.dh_parameters = None
        self.dh_private_key = None
        self.dh_public_key = None
        self.shared_secret = None
        self.aes_key = None
        self.rsa_private_key = None
        self.rsa_public_key = None
        self.log_file = "server_log.txt"
        
        # Initialize log file
        with open(self.log_file, 'w') as f:
            f.write("SERVER LOG - Started at: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\n")
            f.write("=" * 50 + "\n\n")
    
    def log(self, message, level="INFO"):
        """Log messages with timestamp and level"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{level}] {message}\n"
        print(log_entry.strip())
        with open(self.log_file, 'a') as f:
            f.write(log_entry)
    
    def generate_dh_parameters(self):
        """Generate Diffie-Hellman parameters"""
        self.log("Generating DH parameters...")
        self.dh_parameters = dh.generate_parameters(generator=2, key_size=2048, 
                                                  backend=default_backend())
        self.log("DH parameters generated successfully")
    
    def generate_dh_keys(self):
        """Generate DH private and public keys"""
        self.log("Generating DH keys...")
        self.dh_private_key = self.dh_parameters.generate_private_key()
        self.dh_public_key = self.dh_private_key.public_key()
        self.log("DH keys generated successfully")
    
    def generate_rsa_keys(self):
        """Generate RSA private and public keys"""
        self.log("Generating RSA keys...")
        self.rsa_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.rsa_public_key = self.rsa_private_key.public_key()
        self.log("RSA keys generated successfully")
    
    def derive_shared_secret(self, peer_public_key_bytes):
        """Derive shared secret from peer's public key"""
        self.log("Loading peer's public key...")
        peer_public_key = serialization.load_pem_public_key(
            peer_public_key_bytes,
            backend=default_backend()
        )
        self.log("Deriving shared secret...")
        self.shared_secret = self.dh_private_key.exchange(peer_public_key)
        self.log(f"Shared secret derived: {self.shared_secret.hex()[:20]}...")
    
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
    
    def sign_data(self, data):
        """Sign data using RSA private key"""
        self.log(f"Signing data: {data[:20]}...")
        signature = self.rsa_private_key.sign(
            data,
            PSS(
                mgf=MGF1(hashes.SHA256()),
                salt_length=PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        self.log(f"Signature created: {signature.hex()[:20]}...")
        return signature
    
    def handle_client(self, client_socket, addr):
        """Handle client connection"""
        client_id = f"{addr[0]}:{addr[1]}"
        self.log(f"Handling client {client_id}")
        
        try:
            self.log("Starting key exchange...")
            
            # Send DH parameters and public key
            dh_params_bytes = self.dh_parameters.parameter_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.ParameterFormat.PKCS3
            )
            dh_pub_key_bytes = self.dh_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            # Send RSA public key
            rsa_pub_key_bytes = self.rsa_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            # Send all public keys to client
            self.log("Sending DH parameters to client...")
            client_socket.send(len(dh_params_bytes).to_bytes(4, 'big'))
            client_socket.send(dh_params_bytes)
            
            self.log("Sending DH public key to client...")
            client_socket.send(len(dh_pub_key_bytes).to_bytes(4, 'big'))
            client_socket.send(dh_pub_key_bytes)
            
            self.log("Sending RSA public key to client...")
            client_socket.send(len(rsa_pub_key_bytes).to_bytes(4, 'big'))
            client_socket.send(rsa_pub_key_bytes)
            
            # Receive client's DH public key
            self.log("Waiting for client's DH public key...")
            client_dh_pub_key_len = int.from_bytes(client_socket.recv(4), 'big')
            client_dh_pub_key = client_socket.recv(client_dh_pub_key_len)
            self.log("Received client's DH public key")
            
            # Perform key exchange
            self.derive_shared_secret(client_dh_pub_key)
            self.derive_aes_key()
            self.log("Key exchange completed successfully")
            
            # Main communication loop
            while True:
                # Receive encrypted message
                self.log("Waiting for message from client...")
                msg_len_data = client_socket.recv(4)
                if not msg_len_data:
                    self.log("Client disconnected", "WARNING")
                    break
                    
                msg_len = int.from_bytes(msg_len_data, 'big')
                if msg_len == 0:
                    self.log("Client sent termination signal", "INFO")
                    break
                
                encrypted_msg = client_socket.recv(msg_len)
                self.log(f"Received encrypted message of length {msg_len}")
                
                # Decrypt message
                decrypted_msg = self.decrypt_aes(encrypted_msg)
                self.log(f"Full decrypted message: {decrypted_msg.decode()}")
                
                # If client requests signature
                if decrypted_msg.startswith(b"SIGN:"):
                    data_to_sign = decrypted_msg[5:]  # Remove "SIGN:" prefix
                    self.log(f"Signature requested for: {data_to_sign.decode()}")
                    signature = self.sign_data(data_to_sign)
                    
                    # Send signature back to client
                    client_socket.send(len(signature).to_bytes(4, 'big'))
                    client_socket.send(signature)
                    self.log("Signature sent to client")
                
                # If client sends tampered data for testing
                elif decrypted_msg.startswith(b"TAMPER_TEST:"):
                    self.log("Tamper test request received", "WARNING")
                    parts = decrypted_msg.decode().split(":", 2)
                    if len(parts) >= 3:
                        original_data = parts[1]
                        tampered_data = parts[2]
                        self.log(f"Original: {original_data}, Tampered: {tampered_data}")
                        
                        # Sign the original data
                        signature = self.sign_data(original_data.encode())
                        
                        # Send both the signature and a flag indicating this is a tamper test
                        response_data = json.dumps({
                            "type": "tamper_test",
                            "signature": signature.hex(),
                            "original_data": original_data,
                            "tampered_data": tampered_data
                        }).encode()
                        
                        encrypted_response = self.encrypt_aes(response_data)
                        client_socket.send(len(encrypted_response).to_bytes(4, 'big'))
                        client_socket.send(encrypted_response)
                
                # Normal message
                else:
                    # Echo back encrypted response
                    response = f"Server received: {decrypted_msg.decode()}"
                    encrypted_response = self.encrypt_aes(response.encode())
                    client_socket.send(len(encrypted_response).to_bytes(4, 'big'))
                    client_socket.send(encrypted_response)
                    self.log("Response sent to client")
                
        except Exception as e:
            self.log(f"Error handling client: {e}", "ERROR")
        finally:
            client_socket.close()
            self.log(f"Connection with {client_id} closed")
    
    def start(self):
        """Start the server"""
        self.log("Initializing server...")
        self.generate_dh_parameters()
        self.generate_dh_keys()
        self.generate_rsa_keys()
        
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        self.log(f"Server listening on {self.host}:{self.port}")
        
        while True:
            client_socket, addr = self.server_socket.accept()
            self.log(f"Accepted connection from {addr[0]}:{addr[1]}")
            client_thread = threading.Thread(target=self.handle_client, args=(client_socket, addr))
            client_thread.start()

if __name__ == "__main__":
    server = EnhancedServer()
    server.start()