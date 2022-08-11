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
    address = args[1] if len(args) > 1 else "localhost"

    try:
        with open("auth/server_private_key.pem", mode="r", encoding="utf8") as key_file:
            private_key = serialization.load_pem_private_key(
                bytes(key_file.read(), encoding="utf8"), password=None
            )
        public_key = private_key.public_key()
    except Exception as e:
        print(e)

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((address, port))
            s.listen()

            client_socket, client_address = s.accept()
            with client_socket:
                while True:
                    match convert_bytes_to_int(read_bytes(client_socket, 8)):
                        case 0:
                            # If the packet is for transferring the filename
                            print("Receiving file...")
                            filename_len = convert_bytes_to_int(
                                read_bytes(client_socket, 8)
                            )
                            filename = read_bytes(
                                client_socket, filename_len
                            ).decode("utf-8")
                            # print(filename)
                        case 1:
                            # If the packet is for transferring a chunk of the file
                            start_time = time.time()
                            file_datas = []
                            file_datas_len = convert_bytes_to_int(
                                read_bytes(client_socket, 8)
                            )
                            raw_file_datas = []
                            for i in range(file_datas_len):
                                file_data_len = convert_bytes_to_int(
                                    read_bytes(client_socket, 8)
                                )
                                raw_file_data = read_bytes(client_socket, file_data_len)
                                raw_file_datas.append(raw_file_data)
                                decrypted_file_data = private_key.decrypt(
                                    raw_file_data,  # in bytes
                                    padding.OAEP(  # padding should match whatever used during encryption
                                        mgf=padding.MGF1(hashes.SHA256()),
                                        algorithm=hashes.SHA256(),
                                        label=None,
                                    ),
                                )
                                file_datas.append(decrypted_file_data)

                            enc_filename = "enc_recv_" + filename.split("/")[-1]
                            # Write the file with 'enc_recv_' prefix
                            with open(
                                    f"recv_files_enc/{enc_filename}", mode="wb"
                            ) as fp_raw:
                                fp_raw.write(b''.join(raw_file_datas))
                            print(
                                f"Finished receiving raw enc file in {(time.time() - start_time)}s"
                            )

                            dec_filename = "recv_" + filename.split("/")[-1]
                            # Write the file with 'recv_' prefix
                            with open(
                                    f"recv_files/{dec_filename}", mode="wb"
                            ) as fp:
                                fp.write(b''.join(file_datas))
                            print(
                                f"Finished receiving file in {(time.time() - start_time)}s!"
                            )
                        case 2:
                            # Close the connection
                            # Python context used here so no need to explicitly close the socket
                            print("Closing connection...")
                            s.close()
                            break
                        case 3:
                            auth_message_len = convert_bytes_to_int(read_bytes(client_socket, 8))

                            auth_message = read_bytes(
                                client_socket, auth_message_len
                            )

                            signed_message = private_key.sign(
                                auth_message, # message in bytes format
                                padding.PSS(
                                    mgf=padding.MGF1(hashes.SHA256()),
                                    salt_length=padding.PSS.MAX_LENGTH,
                                ),
                                hashes.SHA256()  # hashing algorithm used to hash the data before encryption
                            )

                            # Reading Certificate
                            f = open("auth/server_signed.crt", "rb")
                            ca_cert_raw = f.read()

                            # M1 from server: size of incoming M2 in bytes
                            client_socket.sendall(convert_int_to_bytes(len(signed_message)))
                            # M2 from server: signed authentication message
                            client_socket.sendall(signed_message)
                            # another M1 from server: size of incoming M2 in bytes (this is server_signed.crt)
                            client_socket.sendall(convert_int_to_bytes(len(ca_cert_raw)))
                            # another M2 from server: server_signed.crt
                            client_socket.sendall(ca_cert_raw)



    except Exception as e:
        print(e)
        s.close()


if __name__ == "__main__":
    main(sys.argv[1:])
