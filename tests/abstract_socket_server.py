#!/usr/bin/env python3
"""Simple abstract Unix socket server for testing Landlock scope restrictions."""

import socket
import sys

SOCKET_NAME = "\0landlock_test_socket"

def main():
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.bind(SOCKET_NAME)
        sock.listen(1)
        print(f"Listening on abstract socket: @landlock_test_socket", flush=True)
        print("Waiting for connections... (Ctrl+C to stop)", flush=True)

        while True:
            conn, _ = sock.accept()
            print("Connection received!", flush=True)
            conn.sendall(b"Hello from outside the sandbox!\n")
            conn.close()
    except KeyboardInterrupt:
        print("\nShutting down.")
    finally:
        sock.close()

if __name__ == "__main__":
    main()
