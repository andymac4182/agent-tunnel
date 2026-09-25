#!/usr/bin/env python3
"""Read-only probe of a cua-computer-server running INSIDE the M5 guest VM.

Runs on the host, standard library only, and talks exclusively to BASE_URL,
which scripts/m5-cua-vm.sh points at an SSH forward into the guest's loopback.
It sends no input: only /status, /commands and the /cmd commands version,
get_screen_size, get_cursor_position and screenshot, plus get_desktop_state
and get_capture_scope_state where a backend advertises them. It never talks to a
server on the host, and there is none: the host script refuses to start one.

Output: one JSON document on stdout (the evidence), and the screenshot PNG
written next to it when --out-dir is given. Screen content is the synthetic
fixture app.
"""

import argparse
import base64
import json
import struct
import sys
import urllib.error
import urllib.request
import zlib
from pathlib import Path

READ_ONLY_COMMANDS = ("version", "get_screen_size", "get_cursor_position", "screenshot")
# State queries only some backends register (the Cua Driver backend does).
# Both are captures/reads, never input; probed only when advertised.
OPTIONAL_READ_ONLY = ("get_desktop_state", "get_capture_scope_state")


def http(method: str, url: str, body: dict | None = None, timeout: float = 60.0):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.headers.get("Content-Type"), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("Content-Type"), e.read()


def cmd(base: str, command: str, params: dict | None = None) -> dict:
    status, ctype, raw = http("POST", f"{base}/cmd", {"command": command, "params": params or {}})
    text = raw.decode("utf-8", "replace")
    record = {"http_status": status, "content_type": ctype}
    if text.startswith("data: ") and text.endswith("\n\n"):
        record["framing"] = "data: <JSON>\\n\\n"
        record["payload"] = json.loads(text[len("data: "):-2])
    else:
        record["framing"] = "unframed"
        record["body"] = text[:500]
    return record


def elide(value, limit: int = 256):
    """Replace long strings (image payloads) with their length, recursively."""
    if isinstance(value, str) and len(value) > limit:
        return f"<{len(value)} chars elided>"
    if isinstance(value, dict):
        return {k: elide(v, limit) for k, v in value.items()}
    if isinstance(value, list):
        return [elide(v, limit) for v in value]
    return value


def find_keys(value, needle: str, path: str = "") -> list[str]:
    """Every key path whose name contains needle (case-insensitive)."""
    hits = []
    if isinstance(value, dict):
        for k, v in value.items():
            p = f"{path}.{k}" if path else k
            if needle in k.lower():
                hits.append(p)
            hits += find_keys(v, needle, p)
    elif isinstance(value, list):
        for i, v in enumerate(value):
            hits += find_keys(v, needle, f"{path}[{i}]")
    return hits


def decode_png(png: bytes):
    """Minimal 8-bit RGB/RGBA non-interlaced PNG decoder -> (w, h, bpp, rows)."""
    assert png[:8] == b"\x89PNG\r\n\x1a\n", "not a PNG"
    pos, idat, w = 8, b"", None
    while pos < len(png):
        (length,) = struct.unpack(">I", png[pos:pos + 4])
        kind = png[pos + 4:pos + 8]
        chunk = png[pos + 8:pos + 8 + length]
        pos += 12 + length
        if kind == b"IHDR":
            w, h, depth, ctype, _, _, interlace = struct.unpack(">IIBBBBB", chunk)
            if depth != 8 or ctype not in (2, 6) or interlace:
                return w, h, None, None
            bpp = 3 if ctype == 2 else 4
        elif kind == b"IDAT":
            idat += chunk
        elif kind == b"IEND":
            break
    raw = zlib.decompress(idat)
    stride = w * bpp
    rows, prev, i = [], bytearray(stride), 0
    for _ in range(h):
        ftype, line = raw[i], bytearray(raw[i + 1:i + 1 + stride])
        i += 1 + stride
        for x in range(stride):
            a = line[x - bpp] if x >= bpp else 0
            b = prev[x]
            c = prev[x - bpp] if x >= bpp else 0
            if ftype == 1:
                line[x] = (line[x] + a) & 0xFF
            elif ftype == 2:
                line[x] = (line[x] + b) & 0xFF
            elif ftype == 3:
                line[x] = (line[x] + ((a + b) >> 1)) & 0xFF
            elif ftype == 4:
                p = a + b - c
                pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                pr = a if pa <= pb and pa <= pc else (b if pb <= pc else c)
                line[x] = (line[x] + pr) & 0xFF
        rows.append(bytes(line))
        prev = line
    return w, h, bpp, rows


def pixel(rows, bpp, x, y) -> str:
    r, g, b = rows[y][x * bpp:x * bpp + 3]
    return f"#{r:02x}{g:02x}{b:02x}"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", required=True)
    ap.add_argument("--label", required=True, help="backend/variant label for the record")
    ap.add_argument("--out-dir")
    ap.add_argument("--marker-size", type=int, default=40)
    args = ap.parse_args()
    base = args.base_url.rstrip("/")
    if not base.startswith("http://127.0.0.1:"):
        print("refusing: probe only talks to the loopback end of the SSH forward", file=sys.stderr)
        return 2

    ev: dict = {"label": args.label}
    status, ctype, raw = http("GET", f"{base}/status")
    ev["status"] = {"http_status": status, "body": json.loads(raw) if status == 200 else raw.decode()[:300]}
    status, ctype, raw = http("GET", f"{base}/commands")
    ev["commands_http_status"] = status
    if status == 200:
        listing = json.loads(raw)
        cmds = listing["commands"]
        ev["commands"] = sorted(cmds)
        ev["command_count"] = len(cmds)
        ev["aliases"] = listing.get("aliases", {})
        ev["params"] = {
            n: cmds[n]["params"] for n in READ_ONLY_COMMANDS + OPTIONAL_READ_ONLY if n in cmds
        }
        ev["param_names_mentioning_scale"] = find_keys(
            {n: {p["name"]: 1 for p in v["params"]} for n, v in cmds.items()}, "scale")
        ev["param_names_mentioning_display"] = find_keys(
            {n: {p["name"]: 1 for p in v["params"]} for n, v in cmds.items()}, "display")
    else:
        ev["commands_body"] = raw.decode("utf-8", "replace")[:300]
        print(json.dumps(ev, indent=2, sort_keys=True))
        return 0

    results = {}
    for name in READ_ONLY_COMMANDS:
        if name not in cmds:
            results[name] = {"advertised": False}
            continue
        results[name] = cmd(base, name)
    shot = results.get("screenshot", {})
    payload = shot.get("payload", {})
    if payload.get("success") and payload.get("image_data"):
        png = base64.b64decode(payload.pop("image_data"))
        payload["image_data"] = f"<{len(png)} bytes elided>"
        w, h, bpp, rows = decode_png(png)
        info = {"png_width": w, "png_height": h, "png_bytes": len(png)}
        if rows is not None:
            m = args.marker_size // 2
            info["pixels"] = {
                "top_left": pixel(rows, bpp, m, m),
                "top_right": pixel(rows, bpp, w - 1 - m, m),
                "bottom_left": pixel(rows, bpp, m, h - 1 - m),
                "bottom_right": pixel(rows, bpp, w - 1 - m, h - 1 - m),
                # Offset from the exact centre: a VNC capture draws the pointer there.
                "centre": pixel(rows, bpp, w // 2 - 10, h // 2 - 10),
            }
        ev["screenshot_image"] = info
        if args.out_dir:
            Path(args.out_dir).mkdir(parents=True, exist_ok=True)
            (Path(args.out_dir) / f"screenshot-{args.label}.png").write_bytes(png)
    for name in OPTIONAL_READ_ONLY:
        if name in cmds:
            results[name] = elide(cmd(base, name))
    ev["results"] = results
    ev["result_keys_mentioning_scale"] = find_keys(results, "scale")
    print(json.dumps(ev, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
