import pathlib
import socket
import sys
import time
from datetime import datetime
import secrets
import traceback

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend


def convert_int_to_bytes(x):
    """
    Convenience function to convert Python integers to a length-8 byte representation
    """
    return x.to_bytes(8, "big")


def convert_bytes_to_int(xbytes):
    """
    Convenience function to convert byte value to integer value
    """
    return int.from_bytes(xbytes, "big")

def read_bytes(socket, length):
    """
    Reads the specified length of bytes from the given socket and returns a bytestring
    """
    buffer = []
    bytes_received = 0
    while bytes_received < length:
        data = socket.recv(min(length - bytes_received, 1024))
        if not data:
            raise Exception("Socket connection broken")
        buffer.append(data)
        bytes_received += len(data)

    return b"".join(buffer)

def main(args):
    port = int(args[0]) if len(args) > 0 else 4321
    server_address = args[1] if len(args) > 1 else "localhost"

    start_time = time.time()

    # try:
    print("Establishing connection to server...")
    # Connect to server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((server_address, port))
        print("Connected")

        # send mode:3 to the server
        s.sendall(convert_int_to_bytes(3))

        # followed by two messages
        # M1: The authentication message size in bytes
        # M2: The authentication message itself
        auth_message = bytes("This is an authentication message", encoding="utf-8")
        s.sendall(convert_int_to_bytes(len(auth_message)))
        s.sendall(auth_message)

        # Receive and read four messages from server
        signed_auth_message_len = convert_bytes_to_int(read_bytes(s, 8))
        signed_auth_message = read_bytes(s, signed_auth_message_len)
        server_signed_cert_length = convert_bytes_to_int(read_bytes(s, 8))
        server_signed_cert = read_bytes(s, server_signed_cert_length)

        # Perform Check
        # get CA's public key first
        verified_state = True
        f = open("auth/cacsertificate.crt", "rb")
        ca_cert_raw = f.read()

        # use the x509 method to load it and get the ca's public key
        ca_cert = x509.load_pem_x509_certificate(
            data=ca_cert_raw, backend=default_backend()
        )
        ca_public_key = ca_cert.public_key()

        # verify the ca's public key
        server_cert = x509.load_pem_x509_certificate(
            data=server_signed_cert, backend=default_backend()
        )
        try:
            ca_public_key.verify(
                signature=server_cert.signature,
                data=server_cert.tbs_certificate_bytes,
                padding=padding.PKCS1v15(),
                algorithm=server_cert.signature_hash_algorithm
            )
        except InvalidSignature:
            verified_state = False

        # extract server’s public key from server_signed_cert
        server_public_key = server_cert.public_key()

        # Also need to check server certificate validity
        try:
            assert server_cert.not_valid_before <= datetime.utcnow() <= server_cert.not_valid_after
        except AssertionError:
            verified_state = False

        # Decrypt signed message then do the check with the original message
        try:
            server_public_key.verify(
                signed_auth_message,
                auth_message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256()
            )
        except InvalidSignature:
            verified_state = False

        # If check failed, send a Mode2 to client and close connection immediately.
        if not verified_state:
            s.sendall(convert_int_to_bytes(2))
            print("Authentication failed, close connection")

        # If check is successful, the regular non-secure FTP should proceed
        else:
            while verified_state:
                filename = input(
                    "Enter a filename to send (enter -1 to exit):"
                ).strip()

                while filename != "-1" and (not pathlib.Path(filename).is_file()):
                    filename = input("Invalid filename. Please try again:").strip()

                if filename == "-1":
                    s.sendall(convert_int_to_bytes(2))
                    break

                filename_bytes = bytes(filename, encoding="utf8")

                # Send the filename
                s.sendall(convert_int_to_bytes(0))
                s.sendall(convert_int_to_bytes(len(filename_bytes)))
                s.sendall(filename_bytes)

                # Send the file
                with open(filename, mode="rb") as fp:
                    data = fp.read()
                    # use public key to encrypt the file
                    # use OAEP padding and cut it into 128 bytes block
                    blocks = [data[i: i + 62] for i in range(0, len(data), 62)]
                    s.sendall(convert_int_to_bytes(len(blocks)))
                    encrypted_blocks = []
                    # encrypt each block one by one
                    for b in blocks:
                        encrypted_block = server_public_key.encrypt(
                            b,
                            padding.OAEP(
                                mgf=padding.MGF1(hashes.SHA256()),
                                algorithm=hashes.SHA256(),
                                label=None,
                            ),
                        )
                        # send encrypted block and its size to server
                        s.sendall(convert_int_to_bytes(len(encrypted_block)))
                        s.sendall(encrypted_block)
                        encrypted_blocks.append(encrypted_block)

                    #
                    filename = "enc_" + filename.split("/")[-1]
                    with open(
                            f"send_files_enc/{filename}", mode="wb"
                    ) as fp:
                        fp.write(b''.join(encrypted_blocks))
                    print(
                        "Saved before sent."
                    )

        # Close the connection
        s.sendall(convert_int_to_bytes(2))
        print("Closing connection...")

    end_time = time.time()
    print(f"Program took {end_time - start_time}s to run.")


if __name__ == "__main__":
    main(sys.argv[1:])
