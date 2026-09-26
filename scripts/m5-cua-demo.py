#!/usr/bin/env python3
"""Host-side helpers for scripts/m5-cua-demo.sh (M5 Lane B end-to-end demo).

Nothing here touches the host's screen or input. The consumer talks only to
the local relay's consumer listener; every screen capture and every input
event happens inside the disposable Tart guest, where the CUA backend runs.

Subcommands:
  jwks KEY OUT                 write a JWKS for an RSA private key (openssl)
  token KEY ISSUER AUD SUB     print a short-lived RS256 access token
  tls-forward CHAIN KEY UPSTREAM PORTFILE
                               TLS terminator in front of the plaintext Redis
  redis-clean HOST:PORT DB NAMESPACE
                               delete the demo namespace's keys
  consumer ...                 the demo consumer (see --help)
"""

import argparse
import asyncio
import base64
import hashlib
import json
import os
import socket
import ssl
import struct
import subprocess
import sys
import time
import zlib


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def cmd_jwks(args) -> int:
    out = subprocess.run(
        ["openssl", "rsa", "-noout", "-modulus", "-in", args.key],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    modulus = bytes.fromhex(out.split("=", 1)[1])
    with open(args.out, "w") as handle:
        json.dump({"keys": [{"kid": "m5-cua-demo", "kty": "RSA", "alg": "RS256",
                             "n": b64url(modulus), "e": "AQAB"}]}, handle)
    return 0


def cmd_token(args) -> int:
    now = int(time.time())
    header = b64url(json.dumps({"alg": "RS256", "typ": "JWT", "kid": "m5-cua-demo"}).encode())
    claims = b64url(json.dumps({
        "iss": args.issuer, "aud": args.audience, "sub": args.subject,
        "iat": now, "exp": now + 900, "scope": "http:invoke",
    }).encode())
    signing_input = f"{header}.{claims}".encode()
    signature = subprocess.run(
        ["openssl", "dgst", "-sha256", "-sign", args.key],
        input=signing_input, check=True, capture_output=True,
    ).stdout
    print(f"{header}.{claims}.{b64url(signature)}")
    return 0


def cmd_tls_forward(args) -> int:
    host, port = args.upstream.rsplit(":", 1)
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(args.chain, args.key)

    async def pump(reader, writer):
        try:
            while data := await reader.read(65536):
                writer.write(data)
                await writer.drain()
        except (ConnectionError, OSError):
            pass
        finally:
            writer.close()

    async def serve_one(client_reader, client_writer):
        try:
            up_reader, up_writer = await asyncio.open_connection(host, int(port))
        except OSError:
            client_writer.close()
            return
        await asyncio.gather(pump(client_reader, up_writer), pump(up_reader, client_writer))

    async def main():
        server = await asyncio.start_server(serve_one, "127.0.0.1", 0, ssl=context)
        bound = server.sockets[0].getsockname()[1]
        with open(args.portfile + ".tmp", "w") as handle:
            handle.write(str(bound))
        os.replace(args.portfile + ".tmp", args.portfile)
        async with server:
            await server.serve_forever()

    asyncio.run(main())
    return 0


def resp(sock, *parts: str):
    payload = f"*{len(parts)}\r\n".encode()
    for part in parts:
        data = part.encode()
        payload += f"${len(data)}\r\n".encode() + data + b"\r\n"
    sock.sendall(payload)
    time.sleep(0.2)
    return sock.recv(1 << 20).decode(errors="replace")


def cmd_redis_clean(args) -> int:
    host, port = args.address.rsplit(":", 1)
    with socket.create_connection((host, int(port)), timeout=5) as sock:
        resp(sock, "SELECT", str(args.db))
        reply = resp(sock, "KEYS", f"*{args.namespace}*")
        keys = [line for line in reply.split("\r\n") if args.namespace in line]
        if keys:
            resp(sock, "DEL", *keys)
    print(f"redis-clean namespace={args.namespace} deleted={len(keys)}")
    return 0


# ---- the consumer --------------------------------------------------------

def png_pixels(png: bytes):
    """Minimal PNG decoder: 8-bit RGB/RGBA, non-interlaced. Returns (w, h, get)."""
    assert png[:8] == b"\x89PNG\r\n\x1a\n", "not a PNG"
    pos, idat, width = 8, b"", 0
    while pos < len(png):
        length, kind = struct.unpack(">I4s", png[pos:pos + 8])
        data = png[pos + 8:pos + 8 + length]
        if kind == b"IHDR":
            width, height, depth, colour, _, _, interlace = struct.unpack(">IIBBBBB", data)
            assert depth == 8 and colour in (2, 6) and interlace == 0, "unsupported PNG"
            channels = 3 if colour == 2 else 4
        elif kind == b"IDAT":
            idat += data
        pos += 12 + length
    raw = zlib.decompress(idat)
    stride = width * channels
    rows, prev, off = [], bytearray(stride), 0
    for _ in range(height):
        kind = raw[off]
        line = bytearray(raw[off + 1:off + 1 + stride])
        off += 1 + stride
        for i in range(stride):
            a = line[i - channels] if i >= channels else 0
            b = prev[i]
            c = prev[i - channels] if i >= channels else 0
            if kind == 1:
                line[i] = (line[i] + a) & 255
            elif kind == 2:
                line[i] = (line[i] + b) & 255
            elif kind == 3:
                line[i] = (line[i] + (a + b) // 2) & 255
            elif kind == 4:
                p = a + b - c
                pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                line[i] = (line[i] + (a if pa <= pb and pa <= pc else b if pb <= pc else c)) & 255
        rows.append(line)
        prev = line

    def get(x, y):
        px = rows[y][x * channels:x * channels + 3]
        return "#%02x%02x%02x" % tuple(px)

    return width, height, get


def markers(png: bytes, state: dict) -> dict:
    width, height, get = png_pixels(png)
    s = state["marker_size"] // 2
    cx, cy = width // 2, height // 2
    return {
        "png_width": width, "png_height": height,
        "top_left": get(s, s), "top_right": get(width - s, s),
        "bottom_left": get(s, height - s), "bottom_right": get(width - s, height - s),
        "centre": get(cx, cy),
    }


def markers_match(found: dict, state: dict) -> bool:
    expected = dict(zip(["top_left", "top_right", "bottom_left", "bottom_right"],
                        state["corner_colours"]))
    expected["centre"] = state["centre_colour"]
    return all(found[key] == value for key, value in expected.items())


class Consumer:
    def __init__(self, args):
        self.args = args
        self.url = (f"https://127.0.0.1:{args.consumer_port}/v1/devices/{args.device}"
                    f"/services/{args.service}/http/computer")
        self.log = []
        # The bearer token goes in a 0600 header file, never on a command
        # line where `ps` would show it.
        import tempfile
        handle, self.header_file = tempfile.mkstemp(prefix="m5-cua-demo-auth.")
        with os.fdopen(handle, "w") as header:
            header.write(f"authorization: Bearer {args.token}\n")

    def call(self, operation: str, params: dict | None = None) -> dict:
        body = json.dumps({"version": "computer.v1", "operation": operation,
                           "params": params or {}})
        started = time.monotonic()
        proc = subprocess.run(
            # curl's stock `accept: */*` is sent on purpose: the relay drops
            # it for computer-v1, which does not allowlist it (M5-C26).
            ["curl", "-sS", "--http2", "--max-time", "60", "--cacert", self.args.ca,
             "-H", f"@{self.header_file}",
             "-H", "content-type: application/json",
             "-w", "\n%{http_code} %{http_version}", "--data-binary", "@-", self.url],
            input=body, capture_output=True, text=True,
        )
        elapsed = round((time.monotonic() - started) * 1000)
        text, _, trailer = proc.stdout.rpartition("\n")
        status, _, version = trailer.partition(" ")
        try:
            answer = json.loads(text)
        except json.JSONDecodeError:
            answer = {"unparsed_bytes": len(text)}
        record = {"operation": operation, "http_status": status, "http_version": version,
                  "elapsed_ms": elapsed, "outcome": answer.get("outcome"),
                  "error": answer.get("error")}
        # Never record typed text; params are recorded only for pointer input.
        if operation in ("click", "double_click", "move"):
            record["params"] = params
        result = answer.get("result")
        if isinstance(result, dict) and "image_data" in result:
            png = base64.b64decode(result["image_data"])
            record["result"] = {k: v for k, v in result.items() if k != "image_data"}
            record["result"]["image_sha256"] = hashlib.sha256(png).hexdigest()
            record["result"]["image_bytes"] = len(png)
            answer["_png"] = png
        elif result is not None:
            record["result"] = result
        self.log.append(record)
        print(f"consumer {operation}: http={status} {version} outcome={answer.get('outcome')} "
              f"code={(answer.get('error') or {}).get('code')} ms={elapsed}", file=sys.stderr)
        return answer


def cmd_consumer(args) -> int:
    state = json.load(open(args.state))
    with open(args.token_file) as handle:
        args.token = handle.read().strip()
    consumer = Consumer(args)
    out = args.out
    os.makedirs(out, exist_ok=True)

    described = consumer.call("describe")
    info = consumer.call("screen_info")
    cursor = consumer.call("cursor_position")
    capture = consumer.call("capture")
    if capture.get("outcome") != "ok":
        print("consumer: capture failed; no input will be sent", file=sys.stderr)
        json.dump({"markers_match_fixture": False, "calls": consumer.log},
                  open(os.path.join(out, "consumer.json"), "w"), indent=2)
        return 3
    png = capture.pop("_png")
    found = markers(png, state)
    with open(os.path.join(out, "screenshot-tunnel.png"), "wb") as handle:
        handle.write(png)
    # The fixture-marker gate: no input unless the frame is the fixture's.
    if not markers_match(found, state):
        print(f"consumer: frame is not the fixture ({found}); no input will be sent",
              file=sys.stderr)
        json.dump({"markers": found, "calls": consumer.log}, open(os.path.join(out, "consumer.json"), "w"), indent=2)
        return 3
    identity = capture["result"]["capture"]

    unleased = consumer.call("click", {"capture": identity, "x": 1, "y": 1})
    lease = consumer.call("acquire_input_lease")
    entry, button = state["entry"], state["button"]
    focus = consumer.call("click", {"capture": identity,
                                    "x": entry["x"] + entry["width"] // 2,
                                    "y": entry["y"] + entry["height"] // 2})
    typed = consumer.call("type_text", {"text": args.text})
    clicked = consumer.call("click", {"capture": identity,
                                      "x": button["x"] + button["width"] // 2,
                                      "y": button["y"] + button["height"] // 2})
    # A stale capture is refused: capture again, then click on the old one.
    fresh = consumer.call("capture")
    fresh.pop("_png", None)
    stale = consumer.call("click", {"capture": identity,
                                    "x": button["x"] + 5, "y": button["y"] + 5})
    released = consumer.call("release_input_lease")
    summary = {
        "markers": found,
        "markers_match_fixture": True,
        "negotiated_operations": (described.get("result") or {}).get("operations"),
        "screen_info": info.get("result"),
        "cursor_position": cursor.get("result"),
        "unleased_click": (unleased.get("error") or {}).get("code"),
        "lease": lease.get("outcome"),
        "focus_click": focus.get("outcome"),
        "type_text": typed.get("outcome"),
        "typed_characters": len(args.text),
        "button_click": clicked.get("outcome"),
        "stale_click": (stale.get("error") or {}).get("code"),
        "release": released.get("outcome"),
        "fresh_capture": fresh.get("outcome"),
        "calls": consumer.log,
    }
    with open(os.path.join(out, "consumer.json"), "w") as handle:
        json.dump(summary, handle, indent=2, sort_keys=True)
    os.unlink(consumer.header_file)
    ok = (clicked.get("outcome") == "ok" and typed.get("outcome") == "ok"
          and focus.get("outcome") == "ok")
    return 0 if ok else 4


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("jwks"); p.add_argument("key"); p.add_argument("out"); p.set_defaults(fn=cmd_jwks)
    p = sub.add_parser("token")
    for name in ("key", "issuer", "audience", "subject"):
        p.add_argument(name)
    p.set_defaults(fn=cmd_token)
    p = sub.add_parser("tls-forward")
    for name in ("chain", "key", "upstream", "portfile"):
        p.add_argument(name)
    p.set_defaults(fn=cmd_tls_forward)
    p = sub.add_parser("redis-clean")
    p.add_argument("address"); p.add_argument("db", type=int); p.add_argument("namespace")
    p.set_defaults(fn=cmd_redis_clean)
    p = sub.add_parser("consumer")
    for name in ("--consumer-port", "--device", "--service", "--ca", "--token-file", "--state", "--out", "--text"):
        p.add_argument(name, required=True)
    p.set_defaults(fn=cmd_consumer)
    args = parser.parse_args()
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
