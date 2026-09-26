"""The official MCP Python SDK (`mcp`, pinned in requirements.txt) as an
off-the-shelf Streamable HTTP client, driven through a real local relay by
scripts/m3-sdk-conformance.sh (task row M3-17).

    python py_client.py reference <auto|legacy> <url>
    python py_client.py fixture <auto|legacy> <url> <device-workspace>
    python py_client.py known-m3-47 <auto|legacy> <url>

`reference` expects a server with the conformance reference server's tool,
resource and prompt names (the harness uses ts-sdk-server.mjs); `fixture` the
repository's rmcp fixture; `known-m3-47` the conformance reference server
itself, whose refusal of this SDK's `initialize` (task row M3-47) must still
arrive, forwarded unchanged, as JSON-RPC error -32020 -- if it stops, the row
must be re-examined, so that case then fails.

`auto` is the SDK's default connect mode (probe `server/discover`, fall back
to `initialize`); `legacy` forces the 2025-11-25 `initialize` handshake. The
bearer token comes from AGENTUPLINK_TOKEN and the relay's synthetic CA from
AGENTUPLINK_CA. Each case prints one payload-free line
`sdk=python mode=<mode> case=<name> result=pass|fail ...`; the exit status is
1 if any case failed.
"""

from __future__ import annotations

import json
import os
import ssl
import sys
import time
from pathlib import Path
from typing import Any, Awaitable, Callable

import anyio
import httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

FAILURES = 0


def report(sdk_mode: str, name: str, ok: bool, detail: str = "") -> None:
    global FAILURES
    if not ok:
        FAILURES += 1
    suffix = f" {detail}" if detail else ""
    print(f"sdk=python mode={sdk_mode} case={name} result={'pass' if ok else 'fail'}{suffix}", flush=True)


async def check(sdk_mode: str, name: str, body: Callable[[], Awaitable[str | None]]) -> None:
    try:
        detail = await body()
        report(sdk_mode, name, True, detail or "")
    except Exception as error:  # noqa: BLE001 - every failure is a reported case
        # SDK errors carry status codes and JSON-RPC messages, never bodies or the token.
        message = describe(error)[:400]
        report(sdk_mode, name, False, f"error={json.dumps(message)}")


def describe(error: BaseException) -> str:
    """Name the leaf exceptions of an ExceptionGroup, which anyio raises."""
    if isinstance(error, BaseExceptionGroup):
        return "; ".join(describe(inner) for inner in error.exceptions)
    return f"{type(error).__name__}: {error}"


def error_codes(error: BaseException) -> set[int]:
    """The JSON-RPC error codes inside an (ExceptionGroup of) MCPError."""
    if isinstance(error, BaseExceptionGroup):
        return set().union(*(error_codes(inner) for inner in error.exceptions))
    code = getattr(error, "code", None)
    return {code} if isinstance(code, int) else set()


def expect(condition: Any, what: str) -> None:
    if not condition:
        raise AssertionError(f"expected {what}")


async def wait_for(what: str, seconds: float, probe: Callable[[], bool]) -> None:
    deadline = time.monotonic() + seconds
    while not probe():
        if time.monotonic() > deadline:
            raise TimeoutError(f"timed out waiting for {what}")
        await anyio.sleep(0.025)


async def main() -> int:
    args = sys.argv[1:]
    token = os.environ.get("AGENTUPLINK_TOKEN")
    ca = os.environ.get("AGENTUPLINK_CA")
    if (
        len(args) < 3
        or args[0] not in ("reference", "fixture", "known-m3-47")
        or args[1] not in ("auto", "legacy")
        or (args[0] == "fixture" and len(args) != 4)
        or not token
        or not ca
    ):
        print("usage: AGENTUPLINK_TOKEN=... AGENTUPLINK_CA=... py_client.py reference|fixture auto|legacy <url> [workspace]", file=sys.stderr)
        return 2
    scenario, sdk_mode, url = args[0], args[1], args[2]
    workspace = Path(args[3]) if scenario == "fixture" else None

    tls = ssl.create_default_context(cafile=ca)
    logs: list[str] = []

    async def on_log(params: Any) -> None:
        logs.append(str(params.data))

    # M3-48's signature, observed on the wire: a POST answered 502 only
    # after this client sent its session DELETE.  Only methods and statuses
    # are recorded, never bodies or headers.
    wire = {"delete_sent": False, "late_post_502": 0}

    async def on_request(request: httpx2.Request) -> None:
        if request.method == "DELETE":
            wire["delete_sent"] = True

    async def on_response(response: httpx2.Response) -> None:
        if response.request.method == "POST" and response.status_code == 502 and wire["delete_sent"]:
            wire["late_post_502"] += 1

    def connect() -> tuple[httpx2.AsyncClient, Client]:
        wire["delete_sent"] = False
        wire["late_post_502"] = 0
        http = httpx2.AsyncClient(
            headers={"Authorization": f"Bearer {token}"},
            verify=tls,
            timeout=httpx2.Timeout(30.0, read=300.0),
            event_hooks={"request": [on_request], "response": [on_response]},
        )
        client = Client(streamable_http_client(url, http_client=http), mode=sdk_mode, logging_callback=on_log)
        return http, client

    if scenario == "known-m3-47":
        http, client = connect()

        async def refused() -> str:
            try:
                await client.__aenter__()
            except BaseException as error:  # noqa: BLE001
                codes = error_codes(error)
                expect(-32020 in codes, f"JSON-RPC error -32020 from the backend, got {describe(error)[:200]}")
                return "backend_error=-32020 upstream_row=M3-47"
            finally:
                await http.aclose()
            raise AssertionError("initialize succeeded: M3-47 no longer reproduces; re-examine and close the row")

        await check(sdk_mode, "initialize-known-m3-47", refused)
        return 0 if FAILURES == 0 else 1

    async def session(suffix: str, body: Callable[[Client], Awaitable[None]], known_close_row: str | None = None) -> None:
        http, client = connect()
        entered = False

        async def initialize() -> str:
            nonlocal entered
            await client.__aenter__()
            entered = True
            version = client.session.protocol_version
            expect(version == "2025-11-25", f"negotiated 2025-11-25, got {version}")
            return f"protocol={version}"

        await check(sdk_mode, "initialize" + suffix, initialize)
        if not entered:
            await http.aclose()
            return
        try:
            await body(client)
        finally:
            try:
                await client.__aexit__(None, None, None)
                report(sdk_mode, "close" + suffix, True, "closed=true")
            except Exception as error:  # noqa: BLE001
                leaves = describe(error).split("; ")
                if (
                    known_close_row
                    and leaves
                    and all(leaf.startswith("ClosedResourceError") for leaf in leaves)
                    and wire["late_post_502"] >= 1
                ):
                    # Not counted as a pass or a failure: only the exact
                    # signature -- the SDK raising ClosedResourceError and
                    # nothing else, with a POST answered 502 after the session
                    # DELETE on the wire -- is M3-48.  Anything else fails.
                    print(f"sdk=python mode={sdk_mode} case=close{suffix} result=known row={known_close_row} "
                          f"late_post_502={wire['late_post_502']}", flush=True)
                else:
                    report(sdk_mode, "close" + suffix, False, f"error={json.dumps(describe(error)[:400])}")
            await http.aclose()

    if scenario == "reference":
        await session("", lambda client: run_reference(sdk_mode, client, logs))
    else:
        assert workspace is not None
        await session("", lambda client: run_fixture(sdk_mode, client, workspace))
        # Cancellation in a session of its own, whose close may meet M3-48.
        await session("-cancel", lambda client: run_cancel(sdk_mode, client, workspace), known_close_row="M3-48")
    return 0 if FAILURES == 0 else 1


async def run_reference(sdk_mode: str, client: Client, logs: list[str]) -> None:
    async def tools_list() -> str:
        result = await client.list_tools()
        names = {tool.name for tool in result.tools}
        for name in ("test_simple_text", "test_tool_with_progress", "test_tool_with_logging"):
            expect(name in names, f"tool {name}")
        return f"tools={len(result.tools)}"

    async def tools_call() -> str:
        result = await client.call_tool("test_simple_text", {})
        first = result.content[0]
        expect(first.type == "text" and first.text == "This is a simple text response for testing.", "the reference text block")
        return "content=text"

    async def tools_call_image() -> str:
        result = await client.call_tool("test_image_content", {})
        first = result.content[0]
        expect(first.type == "image" and first.mime_type == "image/png" and first.data, "an image/png block")
        return f"image_b64_len={len(first.data)}"

    async def tools_call_error() -> str:
        result = await client.call_tool("test_error_handling", {})
        expect(result.is_error is True, "isError: true")
        return "isError=true"

    async def resources_list() -> str:
        result = await client.list_resources()
        expect(any(str(r.uri) == "test://static-text" for r in result.resources), "test://static-text")
        return f"resources={len(result.resources)}"

    async def resources_read() -> str:
        text = await client.read_resource("test://static-text")
        expect(getattr(text.contents[0], "text", None) is not None, "a text resource")
        blob = await client.read_resource("test://static-binary")
        expect(getattr(blob.contents[0], "blob", None), "a binary resource")
        return "text=1 blob=1"

    async def prompts_list() -> str:
        result = await client.list_prompts()
        names = {prompt.name for prompt in result.prompts}
        expect("test_simple_prompt" in names and "test_prompt_with_arguments" in names, "both reference prompts")
        return f"prompts={len(result.prompts)}"

    async def prompts_get() -> str:
        simple = await client.get_prompt("test_simple_prompt")
        expect(len(simple.messages) > 0, "a message")
        with_args = await client.get_prompt("test_prompt_with_arguments", {"arg1": "synthetic-a", "arg2": "synthetic-b"})
        text = json.dumps([m.model_dump(mode="json") for m in with_args.messages])
        expect("synthetic-a" in text and "synthetic-b" in text, "both arguments substituted")
        return f"messages={len(simple.messages)}+{len(with_args.messages)}"

    async def progress() -> str:
        seen: list[float] = []

        async def on_progress(value: float, total: float | None, message: str | None) -> None:
            seen.append(value)

        await client.call_tool("test_tool_with_progress", {}, progress_callback=on_progress)
        expect(seen == [0, 50, 100], f"progress 0,50,100 in order, got {seen}")
        return "progress=0,50,100"

    async def logging() -> str:
        await client.set_logging_level("debug")
        logs.clear()
        await client.call_tool("test_tool_with_logging", {})
        # The reference server also logs the level change; count only the
        # tool's three messages. Notifications reach the callback
        # concurrently with the result, so wait briefly for the third.
        expected = ["Tool execution started", "Tool processing data", "Tool execution completed"]
        tool = lambda: [data for data in logs if data.startswith("Tool ")]  # noqa: E731
        await wait_for("the tool's 3 log notifications", 2.0, lambda: len(tool()) >= 3)
        expect(tool() == expected, f"the tool's 3 log notifications in order, got {len(tool())}")
        return f"logs={len(tool())}"

    await check(sdk_mode, "tools/list", tools_list)
    await check(sdk_mode, "tools/call", tools_call)
    await check(sdk_mode, "tools/call-image", tools_call_image)
    await check(sdk_mode, "tools/call-error", tools_call_error)
    await check(sdk_mode, "resources/list", resources_list)
    await check(sdk_mode, "resources/read", resources_read)
    await check(sdk_mode, "prompts/list", prompts_list)
    await check(sdk_mode, "prompts/get", prompts_get)
    await check(sdk_mode, "notifications/progress", progress)
    await check(sdk_mode, "notifications/message", logging)


async def run_fixture(sdk_mode: str, client: Client, workspace: Path) -> None:
    async def tools_list() -> str:
        result = await client.list_tools()
        names = {tool.name for tool in result.tools}
        expect({"echo", "sleep", "progress"} <= names, "echo, sleep, progress")
        return f"tools={len(result.tools)}"

    async def tools_call() -> str:
        result = await client.call_tool("echo", {"value": "synthetic-py"}, meta={"example.test/marker": "synthetic-meta"})
        echoed = json.loads(result.content[0].text)
        expect(echoed.get("arguments", {}).get("value") == "synthetic-py", "arguments echoed")
        expect((echoed.get("meta") or {}).get("example.test/marker") == "synthetic-meta", "_meta preserved")
        expect(any(block.type == "image" for block in result.content), "the image block")
        return "arguments=preserved meta=preserved"

    async def progress() -> str:
        seen: list[float] = []

        async def on_progress(value: float, total: float | None, message: str | None) -> None:
            seen.append(value)

        await client.call_tool("progress", {"steps": 5}, progress_callback=on_progress)
        expect(seen == [1, 2, 3, 4, 5], f"5 ordered progress notifications, got {seen}")
        return "progress=5"

    await check(sdk_mode, "tools/list", tools_list)
    await check(sdk_mode, "tools/call", tools_call)
    await check(sdk_mode, "notifications/progress", progress)


async def run_cancel(sdk_mode: str, client: Client, workspace: Path) -> None:
    invocations = workspace / "invocations.log"

    def sleep_count() -> int:
        if not invocations.exists():
            return 0
        return sum(1 for line in invocations.read_text().splitlines() if line == "sleep")

    async def cancellation() -> str:
        label = f"py{os.getpid()}"
        marker = workspace / f"cancelled-{label}"
        before = sleep_count()
        outcome = "resolved"
        async with anyio.create_task_group() as group:
            scope = anyio.CancelScope()

            async def call() -> None:
                nonlocal outcome
                with scope:
                    await client.call_tool("sleep", {"label": label})
                    return
                outcome = "cancelled"

            group.start_soon(call)
            # Cancel only once the device's server has the call, so the
            # cancel provably crosses the relay after dispatch.
            await wait_for("the sleep call to reach the device server", 15.0, lambda: sleep_count() > before)
            scope.cancel()
        await wait_for("the server to record the cancellation", 15.0, marker.exists)
        return f"client_outcome={outcome} server_marker=cancelled"

    async def after_cancel() -> str:
        result = await client.call_tool("echo", {"value": "after"})
        expect(not result.is_error, "a successful call")
        return "session=usable"

    await check(sdk_mode, "cancellation", cancellation)
    await check(sdk_mode, "after-cancel", after_cancel)


if __name__ == "__main__":
    sys.exit(anyio.run(main))
