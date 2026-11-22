import hashlib
import json
import os
import socket
import struct

CHUNK_SIZE = 1024 * 1024
DEFAULT_PORT = 5000
MAX_HEADER = 1024 * 1024

def recv_exact(sock, size):
    chunks = []
    remaining = size
    while remaining:
        data = sock.recv(min(CHUNK_SIZE, remaining))
        if not data:
            raise ConnectionError("Connection closed before all expected data arrived.")
        chunks.append(data)
        remaining -= len(data)
    return b"".join(chunks)

def send_json(sock, obj):
    payload = json.dumps(obj).encode("utf-8")
    sock.sendall(struct.pack("!I", len(payload)))
    sock.sendall(payload)

def recv_json(sock):
    length = struct.unpack("!I", recv_exact(sock, 4))[0]
    if length <= 0 or length > MAX_HEADER:
        raise ValueError("Invalid protocol header size.")
    return json.loads(recv_exact(sock, length).decode("utf-8"))

def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()

def safe_filename(name):
    name = os.path.basename(str(name).replace("\\", "/")).strip()
    return name or "received_file"

def local_ipv4_addresses():
    found = []
    try:
        for item in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = item[4][0]
            if not ip.startswith("127.") and ip not in found:
                found.append(ip)
    except OSError:
        pass
    return found or ["127.0.0.1"]
