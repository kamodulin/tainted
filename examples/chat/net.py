import socket


def listen(host: str, port: int) -> socket.socket:
    """Create a TCP socket and listen for incoming connections."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen()
    sock_name = sock.getsockname()
    print(f"Listening on {sock_name[0]} port {sock_name[1]}")
    return sock


def connect(host: str, port: int) -> socket.socket:
    """Create a TCP socket and connect to a listening peer."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    peer_name = sock.getpeername()
    print(f"Connection to {peer_name[0]} on port {peer_name[1]} succeeded")
    return sock

