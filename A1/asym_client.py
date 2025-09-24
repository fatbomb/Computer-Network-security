import socket, struct
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

HOST = '127.0.0.1'
PORT = 50001

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

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))

        # Receive server public key PEM
        public_pem = recv_bytes(s)
        server_public_key = serialization.load_pem_public_key(public_pem)
        print("[RSA client] Received server public key PEM.")

        # 1) Ask server to sign a message
        message = b"Please sign this message: Client->Server signature test. \n\n[MSG] Eta ekta message!!\n\n"
        send_bytes(s, b'SIGN')  # command
        send_bytes(s, message)
        print("[RSA client] Sent SIGN request and message.")

        signature = recv_bytes(s)
        print(f"[RSA client] Received signature (len {len(signature)}) from server. Verifying...")

        # verify
        try:
            server_public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print("[RSA client] Signature verified successfully.")
        except Exception as e:
            print("[RSA client] Signature verification failed:", e)
            return

        # 2) Encrypt a short message with RSA-OAEP to send to server and request decryption
        secret = b"\n\n[MSG] Eta ekta secret message. Ei message ta ke encrypt kore pathano hocche.\n\n"
        enc = server_public_key.encrypt(
            secret,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        # tell server we're sending encrypted blob
        send_bytes(s, b'ENC')
        send_bytes(s, enc)
        print("[RSA client] Sent RSA-OAEP encrypted blob to server.")

        # Optionally receive server acknowledgement
        ack = recv_bytes(s)
        print("[RSA client] Server acknowledgement:", ack.decode('utf-8'))

if __name__ == '__main__':
    main()
