import argparse
import pickle
import socket
import threading

from crypto import (
    create_derived_key,
    decrypt_message,
    encrypt_message,
    generate_key_pair,
    generate_random_salt,
    parse_key,
    serialize_key,
)
from net import connect, listen


def handle_client(sock: socket.socket) -> None:
    """Handle a single client connection by exchanging keys and printing messages."""
    pk, sk = generate_key_pair()
    _ = sock.send(serialize_key(pk))  # type: taint[sink]
    peer_name = sock.getpeername()
    while True:
        payload = sock.recv(2048)
        if not payload:
            break
        other_pk, iv, ciphertext = pickle.loads(payload)
        aes_key = create_derived_key(parse_key(other_pk), sk)  # type: ignore
        plaintext = decrypt_message(aes_key, ciphertext, iv)
        print(f"{peer_name[0]}:{peer_name[1]}: {plaintext}")
    sock.close()


def listen_loop(sock: socket.socket) -> None:
    """Listen for incoming connections and create a new thread to handle each one."""
    threads = []
    try:
        while True:
            client_sock, addr = sock.accept()
            print(f"Connection from {addr[0]} on port {addr[1]}")
            t = threading.Thread(target=handle_client, args=(client_sock,))
            t.start()
            threads.append(t)
    finally:
        sock.close()
        for t in threads:
            t.join()


def client_loop(sock: socket.socket) -> None:
    """Send encrypted messages to server."""
    other_pk = sock.recv(2048)
    while True:
        try:
            message = input("> ")  # type: taint[source]
            pk, sk = generate_key_pair()
            aes_key = create_derived_key(parse_key(other_pk), sk)  # type: ignore
            iv = generate_random_salt(12)
            ciphertext = encrypt_message(aes_key, message, iv)
            payload = pickle.dumps((serialize_key(pk), iv, ciphertext))
            _ = sock.send(payload)  # type: taint[sink]
        except KeyboardInterrupt:
            break
    sock.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="")
    parser.add_argument("host", type=str, nargs="?", default="localhost")
    parser.add_argument("port", type=int, nargs="?", default=9000)
    parser.add_argument("-l", "--listen", action="store_true")
    args = parser.parse_args()

    if args.listen:
        sock = listen(args.host, args.port)
        listen_loop(sock)
    else:
        sock = connect(args.host, args.port)
        client_loop(sock)
