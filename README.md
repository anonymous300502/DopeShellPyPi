# **DopeShell**

## **Introduction**

**DopeShell** is a Python library designed to simplify the creation of secure reverse shells with advanced features like session management, encryption, multiple connections, and obfuscation techniques. This library provides an easy-to-use interface for setting up both the client and server sides of a reverse shell, with the ability to manage multiple sessions, simulate command-line prompts, and more.

## **Features**

- **Encrypted Communication**: Utilizes AES encryption to secure data transmitted between the client and server.
- **Session Management**: Handles multiple active sessions and allows the server operator to switch between them.
- **Command Prompt Simulation**: The reverse shell simulates the target's command-line interface, making it appear as if the commands are being executed locally.
- **Obfuscation Techniques**: Implements basic obfuscation to avoid detection by security systems.
- **Customizable**: Easily configure host, port, and encryption key via command-line arguments.

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