"""A TLS front for a plaintext test Redis, for scripts/m3-sdk-conformance.sh.

`tunnel-relay serve` refuses a plaintext catalog (`redis_url` must be
`rediss://`).  CI's M3 job and local development already run a plaintext
Redis (`TEST_REDIS_URL`), so rather than start a second Redis this terminates
TLS with the run's synthetic server certificate on 127.0.0.1 and copies bytes
to that Redis.  It never parses or logs traffic.

    python3 redis_tls_proxy.py serve <cert> <key> <redis-host> <redis-port> <port-file>
    python3 redis_tls_proxy.py purge <redis-host> <redis-port> <substring>

`purge` deletes every key whose name contains <substring> (the run's unique
nonce), so a run leaves nothing in a shared Redis.
"""

from __future__ import annotations

import asyncio
import os
import socket
import ssl
import sys


async def pump(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
    except (ConnectionError, ssl.SSLError):
        pass
    finally:
        try:
            writer.close()
        except Exception:  # noqa: BLE001
            pass


async def serve(cert: str, key: str, host: str, port: int, port_file: str) -> None:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert, key)

    async def handle(client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter) -> None:
        try:
            upstream_reader, upstream_writer = await asyncio.open_connection(host, port)
        except OSError:
            client_writer.close()
            return
        await asyncio.gather(pump(client_reader, upstream_writer), pump(upstream_reader, client_writer))

    server = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=context)
    bound = server.sockets[0].getsockname()[1]
    with open(port_file + ".part", "w") as out:
        out.write(f"{bound}\n")
    os.replace(port_file + ".part", port_file)
    async with server:
        await server.serve_forever()


def resp(*parts: str) -> bytes:
    out = [f"*{len(parts)}\r\n".encode()]
    for part in parts:
        raw = part.encode()
        out.append(f"${len(raw)}\r\n".encode() + raw + b"\r\n")
    return b"".join(out)


def read_reply(stream) -> object:
    line = stream.readline().rstrip(b"\r\n")
    kind, rest = line[:1], line[1:]
    if kind in (b"+", b":"):
        return rest.decode()
    if kind == b"-":
        raise RuntimeError("redis error")
    if kind == b"$":
        size = int(rest)
        if size < 0:
            return None
        data = stream.read(size + 2)[:-2]
        return data.decode("utf-8", "replace")
    if kind == b"*":
        return [read_reply(stream) for _ in range(int(rest))]
    raise RuntimeError("unexpected redis reply")


def purge(host: str, port: int, substring: str) -> int:
    with socket.create_connection((host, port), timeout=10) as sock:
        stream = sock.makefile("rwb")
        cursor, deleted = "0", 0
        while True:
            stream.write(resp("SCAN", cursor, "MATCH", f"*{substring}*", "COUNT", "1000"))
            stream.flush()
            cursor, keys = read_reply(stream)
            for key in keys:
                stream.write(resp("UNLINK", key))
                stream.flush()
                deleted += int(read_reply(stream))
            if cursor == "0":
                break
    print(f"purged_keys={deleted}")
    return 0


def main() -> int:
    args = sys.argv[1:]
    if len(args) == 6 and args[0] == "serve":
        asyncio.run(serve(args[1], args[2], args[3], int(args[4]), args[5]))
        return 0
    if len(args) == 4 and args[0] == "purge":
        return purge(args[1], int(args[2]), args[3])
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
