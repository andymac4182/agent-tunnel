#!/usr/bin/env python3
"""A loopback TLS front for a plaintext Redis (scripts/adapters-demo.sh).

    adapters-demo-tls-forward.py LISTEN_PORT CERT_CHAIN KEY TARGET_HOST TARGET_PORT

`tunnel-relay serve` accepts only `rediss://` (its config refuses plaintext),
while the shared verification Redis on 127.0.0.1:63790 is plaintext. With
DEMO_ALLOW_SHARED_REDIS=1 the demo puts this forwarder between them: it
terminates TLS on 127.0.0.1:LISTEN_PORT with the run's synthetic relay leaf and
copies bytes to TARGET_HOST:TARGET_PORT. Loopback only, standard library only,
no logging of traffic. It prints `ready` once listening and runs until killed.
"""

import socket
import ssl
import sys
import threading


def pump(source, sink):
    try:
        while True:
            data = source.recv(65536)
            if not data:
                break
            sink.sendall(data)
    except OSError:
        pass
    finally:
        for sock in (source, sink):
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def serve(client, context, target):
    try:
        tls = context.wrap_socket(client, server_side=True)
        upstream = socket.create_connection(target, timeout=10)
        upstream.settimeout(None)
        tls.settimeout(None)
    except (OSError, ssl.SSLError):
        client.close()
        return
    threading.Thread(target=pump, args=(tls, upstream), daemon=True).start()
    threading.Thread(target=pump, args=(upstream, tls), daemon=True).start()


def main():
    port, chain, key, host, target_port = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]
    if host not in ("127.0.0.1", "localhost"):
        print("refusing a non-loopback target", file=sys.stderr)
        return 2
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(chain, key)
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", int(port)))
    listener.listen(64)
    print("ready", flush=True)
    while True:
        client, _ = listener.accept()
        threading.Thread(target=serve, args=(client, context, (host, int(target_port))), daemon=True).start()


if __name__ == "__main__":
    sys.exit(main())
