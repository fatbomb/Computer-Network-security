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
    # Derive an AES key (length bytes) from the shared secret
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=b'handshake data',
    )
    return hkdf.derive(shared_key)

def aes_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

def aes_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()

def main():
    parameters = dh.generate_parameters(generator=2, key_size=2048)
    server_private_key = parameters.generate_private_key()
    server_public_key = server_private_key.public_key()
    
    # print(server_private_key)
    # print()
    # print(server_public_key)
    # print()
    
    # Serialize server public key to send to client
    server_pub_bytes = server_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen(1)
        print(f"[server] Listening on {HOST}:{PORT} ...")
        conn, addr = s.accept()
        with conn:
            print(f"[server] Connection from {addr}")

            send_bytes(conn, server_pub_bytes)
            print("[server] Sent DH public key (PEM) to client.")

            client_pub_bytes = recv_bytes(conn)
            print("[server] Received client's DH public key.")

            client_public_key = serialization.load_pem_public_key(client_pub_bytes)

            # Compute shared secret
            shared_key = server_private_key.exchange(client_public_key)
            print(f"[server] Raw shared key (len {len(shared_key)}): {shared_key[:20].hex()}...")

            # Derive AES key
            aes_key = derive_aes_key(shared_key, length=32)
            print(f"[server] Derived AES key (hex first 16): {aes_key[:16].hex()}")

            # Now receive an encrypted message from client: first iv then ciphertext (both length-prefixed)
            iv = recv_bytes(conn)
            ciphertext = recv_bytes(conn)
            plaintext = aes_decrypt(aes_key, iv, ciphertext)
            print("[server] Received encrypted message from client. Decrypted plaintext:")
            print(plaintext.decode('utf-8'))

            # Reply: send an encrypted acknowledgement
            reply = b"Server received your secure message. Thanks!"
            reply_iv = os.urandom(16)
            reply_ct = aes_encrypt(aes_key, reply_iv, reply)
            send_bytes(conn, reply_iv)
            send_bytes(conn, reply_ct)
            print("[server] Sent encrypted acknowledgement to client. Done.")

if __name__ == '__main__':
    main()
