#!/usr/bin/env python3
"""Tiny synthetic web app for the local demo (task row M6-C128).

Listens on 127.0.0.1 only. It is the device-side backend of the demo's HTTP
forward: the relay's http-forward profiles are MCP and ACP, so the app speaks
MCP Streamable HTTP (protocol 2026-07-28, stateless) at POST /mcp and serves
one fixed synthetic page through it:

  server/discover  -> server info and capabilities
  tools/list       -> one tool, `demo_page`
  tools/call       -> `demo_page` returns the page
  resources/read   -> `demo://page` returns the page
  ping             -> {}

GET / serves the same page directly, for the presenter's pre-flight check
that the app is up on the device side. Every page carries a request counter,
so the consumer can see the answer came from this process. It holds no data,
reads no files and logs method and status only, never bodies.

Usage: demo-web-app.py PORT
"""
import json
import os
import socketserver
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PROTOCOL = "2026-07-28"
MARKER = "agentuplink-demo-page-v1"
SERVER_INFO = {"name": "agentuplink-demo-web-app", "version": "1.0.0"}
CAPABILITIES = {"tools": {}, "resources": {}}
TOOL = {
    "name": "demo_page",
    "description": "Return the synthetic demo page",
    "inputSchema": {"type": "object", "properties": {}},
}
_lock = threading.Lock()
_served = 0


def page():
    global _served
    with _lock:
        _served += 1
        n = _served
    return (
        "<!doctype html><html><head><title>Agent Uplink demo</title></head>"
        "<body><h1>Hello from the demo Mac</h1>"
        "<p>This synthetic page was served by a loopback-only web app on the "
        "device and reached the caller through the Agent Uplink relay.</p>"
        f"<p>marker: {MARKER}</p><p>served: {n} by pid {os.getpid()}</p></body></html>"
    )


def result_for(method, params):
    if method == "server/discover":
        return {"supportedVersions": [PROTOCOL], "capabilities": CAPABILITIES, "serverInfo": SERVER_INFO}
    if method == "ping":
        return {}
    if method == "tools/list":
        return {"tools": [TOOL]}
    if method == "tools/call" and params.get("name") == "demo_page":
        return {"content": [{"type": "text", "text": page()}], "isError": False}
    if method == "resources/list":
        return {"resources": [{"uri": "demo://page", "name": "demo page", "mimeType": "text/html"}]}
    if method == "resources/read" and params.get("uri") == "demo://page":
        return {"contents": [{"uri": "demo://page", "mimeType": "text/html", "text": page()}]}
    return None


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "demo-web-app"
    sys_version = ""

    def log_message(self, fmt, *args):
        sys.stderr.write("demo-web-app %s %s\n" % (self.command, args[1] if len(args) > 1 else "-"))

    def reply(self, status, body=None, content_type="application/json"):
        if body is None:
            data = b""
        elif isinstance(body, str):
            data = body.encode()
        else:
            data = json.dumps(body, separators=(",", ":")).encode()
        self.send_response(status)
        if data:
            self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/":
            self.reply(200, page(), "text/html; charset=utf-8")
        else:
            self.reply(405, {"jsonrpc": "2.0", "error": {"code": -32000, "message": "method not allowed"}})

    def do_DELETE(self):
        self.reply(405, {"jsonrpc": "2.0", "error": {"code": -32000, "message": "method not allowed"}})

    def do_POST(self):
        if self.path != "/mcp":
            self.reply(404, {"jsonrpc": "2.0", "error": {"code": -32000, "message": "not found"}})
            return
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > 1 << 20:
            self.reply(400, {"jsonrpc": "2.0", "error": {"code": -32600, "message": "bad length"}})
            return
        try:
            message = json.loads(self.rfile.read(length))
        except ValueError:
            self.reply(400, {"jsonrpc": "2.0", "error": {"code": -32700, "message": "parse error"}})
            return
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
            self.reply(400, {"jsonrpc": "2.0", "error": {"code": -32600, "message": "invalid request"}})
            return
        if "id" not in message:
            self.reply(202)
            return
        params = message.get("params") or {}
        result = result_for(message.get("method"), params if isinstance(params, dict) else {})
        if result is None:
            body = {"jsonrpc": "2.0", "id": message["id"], "error": {"code": -32601, "message": "method not found"}}
        else:
            body = {"jsonrpc": "2.0", "id": message["id"], "result": result}
        self.reply(200, body)


class Server(ThreadingHTTPServer):
    daemon_threads = True

    def server_bind(self):
        # Skip HTTPServer's reverse DNS lookup, which can stall on macOS.
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = "127.0.0.1", self.server_address[1]


def main():
    port = int(sys.argv[1])
    server = Server(("127.0.0.1", port), Handler)
    sys.stderr.write("demo-web-app listening on 127.0.0.1:%d\n" % port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
