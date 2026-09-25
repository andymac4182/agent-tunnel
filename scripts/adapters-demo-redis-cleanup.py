#!/usr/bin/env python3
"""Delete one demo run's Redis keys (scripts/adapters-demo.sh cleanup).

    adapters-demo-redis-cleanup.py REDISS_URL CA_FILE NAMESPACE

Removes every key whose name contains NAMESPACE, which the demo makes unique
per run (`adapters-demo-<pid>-<time>`), so a Redis supplied through
DEMO_REDIS_URL is left as it was found. Refuses a namespace that does not start
with `adapters-demo-`, so a mistaken argument cannot sweep someone else's keys.
Standard library only: a minimal RESP client over TLS, SCAN then UNLINK.
Prints one line with the count; never prints a key's value.
"""

import socket
import ssl
import sys
from urllib.parse import unquote, urlsplit


def encode(*parts):
    out = [f"*{len(parts)}\r\n".encode()]
    for part in parts:
        data = part if isinstance(part, bytes) else str(part).encode()
        out.append(f"${len(data)}\r\n".encode() + data + b"\r\n")
    return b"".join(out)


class Resp:
    def __init__(self, sock):
        self.file = sock.makefile("rb")
        self.sock = sock

    def call(self, *parts):
        self.sock.sendall(encode(*parts))
        return self.read()

    def read(self):
        line = self.file.readline()
        if not line:
            raise ConnectionError("redis closed the connection")
        kind, rest = line[:1], line[1:-2]
        if kind == b"+":
            return rest.decode()
        if kind == b"-":
            raise RuntimeError(rest.decode())
        if kind == b":":
            return int(rest)
        if kind == b"$":
            size = int(rest)
            if size < 0:
                return None
            data = self.file.read(size + 2)[:-2]
            return data
        if kind == b"*":
            return [self.read() for _ in range(int(rest))]
        raise RuntimeError("unexpected RESP reply")


def main():
    url, ca, namespace = sys.argv[1], sys.argv[2], sys.argv[3]
    if not namespace.startswith("adapters-demo-") or any(c in namespace for c in "*?[]"):
        print("redis cleanup: refused, namespace is not a demo namespace", file=sys.stderr)
        return 2
    parts = urlsplit(url)
    if parts.scheme != "rediss":
        print("redis cleanup: refused, only rediss:// is supported", file=sys.stderr)
        return 2
    context = ssl.create_default_context(cafile=ca)
    raw = socket.create_connection((parts.hostname, parts.port or 6379), timeout=10)
    sock = context.wrap_socket(raw, server_hostname=parts.hostname)
    redis = Resp(sock)
    if parts.password is not None:
        user = unquote(parts.username) if parts.username else "default"
        redis.call("AUTH", user, unquote(parts.password))
    db = parts.path.lstrip("/") or "0"
    redis.call("SELECT", db)
    cursor, deleted = "0", 0
    while True:
        cursor, keys = redis.call("SCAN", cursor, "MATCH", f"*{namespace}*", "COUNT", 1000)
        cursor = cursor.decode()
        if keys:
            deleted += redis.call("UNLINK", *keys)
        if cursor == "0":
            break
    remaining, cursor = [], "0"
    while True:
        cursor, keys = redis.call("SCAN", cursor, "MATCH", f"*{namespace}*", "COUNT", 1000)
        cursor = cursor.decode()
        remaining.extend(keys)
        if cursor == "0":
            break
    print(f"redis cleanup: deleted {deleted} key(s) in namespace {namespace}; {len(remaining)} remain")
    sock.close()
    return 0 if not remaining else 1


if __name__ == "__main__":
    sys.exit(main())
