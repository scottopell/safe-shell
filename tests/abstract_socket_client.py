#!/usr/bin/env python3
"""Client to test connection to abstract Unix socket."""

import socket
import sys

SOCKET_NAME = "\0landlock_test_socket"

def main():
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        print(f"Attempting to connect to @landlock_test_socket...", flush=True)
        sock.connect(SOCKET_NAME)
        data = sock.recv(1024)
        print(f"Received: {data.decode()}", flush=True)
        print("SUCCESS: Connected to socket outside sandbox!", flush=True)
    except PermissionError as e:
        print(f"BLOCKED (PermissionError): {e}", flush=True)
        print("Abstract Unix socket scoping is working!", flush=True)
        sys.exit(0)
    except ConnectionRefusedError as e:
        print(f"Connection refused (server not running?): {e}", flush=True)
        sys.exit(2)
    except Exception as e:
        print(f"Error: {type(e).__name__}: {e}", flush=True)
        sys.exit(1)
    finally:
        sock.close()

if __name__ == "__main__":
    main()
