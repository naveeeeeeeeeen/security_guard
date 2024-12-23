import os
import re
import sys
import shlex
import socket
import threading
import subprocess
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# Constants
MAX_CLIENTS = 5
ALLOWED_COMMAND_PREFIXES = ["./setup", "./logappend", "./logread"]
IPV4_PATTERN = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"

# Semaphore to limit concurrent clients
client_semaphore = threading.Semaphore(MAX_CLIENTS)

# Dictionary to store AES keys associated with client addresses
client_aes_keys = {}

# Global event to signal server shutdown
shutdown_event = threading.Event()

# Lists to manage active client threads and connections
active_threads = []
active_connections = []

# Function to generate RSA key pair
def generate_keys():
    """Generate and save RSA key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Save private key to a file
    with open("private_key.pem", "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    # Save public key to a file
    public_key = private_key.public_key()
    with open("public_key.pem", "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
    print("RSA key pair generated.")
    return private_key, public_key

# Generate or load RSA keys
if not (os.path.exists("private_key.pem") and os.path.exists("public_key.pem")):
    private_key, _ = generate_keys()
else:
    with open("private_key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )

# Send the public key to the client
def send_public_key(conn):
    """Send the server's public key to the client."""
    with open("public_key.pem", "rb") as pub_key_file:
        public_key_data = pub_key_file.read()
    conn.sendall(len(public_key_data).to_bytes(4, 'big'))  # Send length first
    conn.sendall(public_key_data)

# Client handler
def handle_client(conn, addr):
    """Handle communication with a connected client."""
    print(f"Connected by {addr}")
    active_connections.append(conn)  # Track active connections
    with conn:
        send_public_key(conn)

        try:
            # Receive and decrypt AES key
            encrypted_aes_key = conn.recv(256)
            if encrypted_aes_key:
                fernet_key = private_key.decrypt(
                    encrypted_aes_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                client_aes_keys[addr] = fernet_key

            fernet = Fernet(client_aes_keys[addr])

            while not shutdown_event.is_set():  # Check shutdown flag
                encrypted_command = conn.recv(256)
                if not encrypted_command:
                    print(f"Client {addr} disconnected")
                    break

                # Decrypt and process the command
                command = fernet.decrypt(encrypted_command).decode()
                print(f"Received command from {addr}")

                # Validate command
                if len(command) > 256:
                    response = f"Error: Command exceeds maximum length of {256} characters."
                    conn.sendall(fernet.encrypt(response.encode()))
                    continue

                if command.lower() == 'exit':
                    break

                if '\\' in command or "'" in command or '"' in command:
                    response = "Error: Invalid characters in command."
                    conn.sendall(fernet.encrypt(response.encode()))
                    continue

                parts = shlex.split(command)
                base_command = parts[0] if parts else ""

                if base_command in ALLOWED_COMMAND_PREFIXES:
                    if base_command == './setup' and len(parts) == 3:
                        validated_command = parts
                    elif base_command == './logappend' and len(parts) >= 3:
                        validated_command = parts
                    elif base_command == './logread' and len(parts) >= 2:
                        validated_command = parts
                    else:
                        response = "Error: Invalid command format."
                        conn.sendall(fernet.encrypt(response.encode()))
                        continue
                else:
                    response = "Error: Command not allowed."
                    conn.sendall(fernet.encrypt(response.encode()))
                    continue

                try:
                    output = subprocess.check_output(validated_command, stderr=subprocess.STDOUT)
                    response = output.decode()
                except subprocess.CalledProcessError as e:
                    response = e.output.decode()

                conn.sendall(fernet.encrypt(response.encode()))
        except Exception as e:
            print(f"An error occurred with {addr}: {e}")
        finally:
            active_connections.remove(conn)  # Remove connection from active list
            client_semaphore.release()
    print(f"Connection with {addr} closed")

# Validation helpers
def is_valid_ip(ip):
    """Validate IPv4 address."""
    if re.match(IPV4_PATTERN, ip):
        return all(0 <= int(part) <= 255 for part in ip.split('.'))
    return False

def is_valid_port(port):
    """Validate port number."""
    return port.isdigit() and 1 <= int(port) <= 65535

# Main server function
def main():
    """Start the server."""
    host = '127.0.0.1'
    port = 12345

    if len(sys.argv) >= 2:
        if is_valid_ip(sys.argv[1]):
            host = sys.argv[1]
        else:
            print("Error: Invalid IP address format.")
            sys.exit(1)

    if len(sys.argv) == 3:
        if is_valid_port(sys.argv[2]):
            port = int(sys.argv[2])
        else:
            print("Error: Invalid port number. Must be between 1 and 65535.")
            sys.exit(1)

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.bind((host, port))
            server_socket.listen()
            print(f"Server listening on {host}:{port}")

            while not shutdown_event.is_set():
                try:
                    client_semaphore.acquire()
                    conn, addr = server_socket.accept()
                    thread = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
                    thread.start()
                    active_threads.append(thread)  # Track active thread
                except KeyboardInterrupt:
                    break
    except KeyboardInterrupt:
        pass
    finally:
        print("\nShutting down server...")
        shutdown_event.set()  # Signal threads to stop

        # Close all active client connections
        for conn in active_connections:
            conn.close()

        print("Server shut down gracefully.")

if __name__ == "__main__":
    main()
