import socket, struct
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

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
    # Generate RSA key pair
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen(1)
        print(f"[RSA server] Listening on {HOST}:{PORT} ...")
        conn, addr = s.accept()
        with conn:
            print(f"[RSA server] Connection from {addr}")

            # Send public key PEM to client
            send_bytes(conn, public_pem)
            print("[RSA server] Sent public key PEM to client.")

            # Handle multiple requests in a loop
            while True:
                try:
                    cmd = recv_bytes(conn)
                except ConnectionError:
                    print("[RSA server] Client disconnected.")
                    break

                if cmd == b'SIGN':
                    msg = recv_bytes(conn)
                    print("[RSA server] Received message to sign:", msg.decode('utf-8'))

                    signature = private_key.sign(
                        msg,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()
                    )
                    send_bytes(conn, signature)
                    print("[RSA server] Sent signature back to client.")

                elif cmd == b'ENC':
                    enc = recv_bytes(conn)
                    plaintext = private_key.decrypt(
                        enc,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    print("[RSA server] Decrypted RSA-OAEP message:", plaintext.decode('utf-8'))
                    send_bytes(conn, b"Server decrypted your encrypted message successfully.")

                else:
                    print("[RSA server] Unknown command:", cmd)
                    break

if __name__ == '__main__':
    main()
