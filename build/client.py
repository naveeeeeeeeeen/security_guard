import sys
import socket
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes


def receive_public_key(conn):
    """
    Receive and load the server's public key.
    """
    # Receive the length of the public key file (4 bytes)
    key_length = int.from_bytes(conn.recv(4), 'big')
    public_key_data = conn.recv(key_length)

    # Save the received public key to a file
    with open("public_key.pem", "wb") as pub_key_file:
        pub_key_file.write(public_key_data)

    # Load the public key for encryption
    public_key = serialization.load_pem_public_key(public_key_data)
    print("Public key received from server and loaded successfully.")

    return public_key


def generate_and_send_aes_key(conn, public_key):
    """
    Generate a Fernet (AES) key and send it to the server after encrypting it with the server's public key.
    """
    # Generate the Fernet key (AES key)
    fernet_key = Fernet.generate_key()

    # Encrypt the Fernet key with the server's public key
    encrypted_aes_key = public_key.encrypt(
        fernet_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # Send the encrypted AES key to the server
    conn.sendall(encrypted_aes_key)
    return fernet_key


def is_valid_ip(ip):
    """
    Validate the IPv4 address format.
    """
    parts = ip.split('.')
    return len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)


def is_valid_port(port):
    """
    Validate the port number.
    """
    return port.isdigit() and 1 <= int(port) <= 65535


def main():
    """
    Main function to handle client-server communication.
    """
    # Default IP and port
    host = '127.0.0.1'
    port = 12345

    # Parse command-line arguments for IP and port
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
            print("Error: Invalid port number. Must be an integer between 1 and 65535.")
            sys.exit(1)
    elif len(sys.argv) > 3:
        print("Usage: python3 client.py [<ip> <port>]")
        sys.exit(1)

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.connect((host, port))

            # Step 1: Receive and load the server's public key
            public_key = receive_public_key(client_socket)

            # Step 2: Generate and send AES key to the server
            fernet_key = generate_and_send_aes_key(client_socket, public_key)

            # Step 3: Create a Fernet instance using the generated AES key
            fernet = Fernet(fernet_key)

            while True:
                try:
                    # Get user input for the command
                    command = input("Enter command (or 'exit' to quit): ").strip()
                    if command.lower() == 'exit':
                        print("Disconnecting from the server...")
                        break

                    # Encrypt the command using Fernet
                    encrypted_command = fernet.encrypt(command.encode())
                    client_socket.sendall(encrypted_command)

                    # Receive and decrypt the server's response
                    encrypted_response = client_socket.recv(4096)
                    response = fernet.decrypt(encrypted_response).decode()

                    print("Response from server:")
                    print(response)
                except KeyboardInterrupt:
                    print("\nClient disconnected gracefully.")
                    sys.exit(0)
                except Exception as e:
                    print(f"An error occurred while processing the response: {e}")
                    break
    except Exception as e:
        print(f"An error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
