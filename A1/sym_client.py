import socket, struct, os
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

HOST = '127.0.0.1'
PORT = 50000

def send_bytes(conn, b: bytes):
    conn.sendall(struct.pack('!I', len(b)))
    conn.sendall(b)

def recv_bytes(conn):
    raw = conn.recv(4)
    if len(raw) < 4:
        raise ConnectionError("Connection closed or protocol error")
    n = struct.unpack('!I', raw)[0]
    data = b''
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Connection closed unexpectedly")
        data += chunk
    return data

def derive_aes_key(shared_key: bytes, length=32):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=b'handshake data',
    )
    return hkdf.derive(shared_key)

def aes_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()

def aes_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        
        server_pub_bytes = recv_bytes(s)
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        server_public_key = load_pem_public_key(server_pub_bytes)
        print("[client] Received server DH public key.")

        # Extract parameters from server public key to generate client private key compatible with server
        params = server_public_key.public_numbers().parameter_numbers
        parameter_numbers = dh.DHParameterNumbers(p=params.p, g=params.g)
        parameters = parameter_numbers.parameters()
        client_private_key = parameters.generate_private_key()
        client_public_key = client_private_key.public_key()

        # Serialize and send client public key to server
        client_pub_bytes = client_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        send_bytes(s, client_pub_bytes)
        print("[client] Sent client's DH public key to server.")

        # Compute shared secret
        shared_key = client_private_key.exchange(server_public_key)
        print(f"[client] Raw shared key (len {len(shared_key)}): {shared_key[:20].hex()}...")

        # Derive AES key
        aes_key = derive_aes_key(shared_key, length=32)
        print(f"[client] Derived AES key (hex first 16): {aes_key[:16].hex()}")

        # Prepare an encrypted message and send iv + ciphertext
        plaintext = b"\n\n[MSG] Amra ei message ta send korte chai!\n\n"
        iv = os.urandom(16)
        ciphertext = aes_encrypt(aes_key, iv, plaintext)

        send_bytes(s, iv)
        send_bytes(s, ciphertext)
        print("[client] Sent encrypted message to server.")

        # Receive server encrypted reply
        reply_iv = recv_bytes(s)
        reply_ct = recv_bytes(s)
        reply_plain = aes_decrypt(aes_key, reply_iv, reply_ct)
        print("[client] Received encrypted reply. Decrypted plaintext:")
        print(reply_plain.decode('utf-8'))

if __name__ == '__main__':
    main()
