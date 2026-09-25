"""The official MCP Python SDK (`mcp`, pinned in requirements.txt) as an
off-the-shelf Streamable HTTP client, driven through a real local relay by
scripts/m3-sdk-conformance.sh (task row M3-17).

    python py_client.py reference <auto|legacy> <url>
    python py_client.py fixture <auto|legacy> <url> <device-workspace>

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
        message = f"{type(error).__name__}: {error}"[:300]
        report(sdk_mode, name, False, f"error={json.dumps(message)}")


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
        or args[0] not in ("reference", "fixture")
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
    http = httpx2.AsyncClient(
        headers={"Authorization": f"Bearer {token}"},
        verify=tls,
        timeout=httpx2.Timeout(30.0, read=300.0),
    )
    logs: list[str] = []

    async def on_log(params: Any) -> None:
        logs.append(str(params.level))

    client = Client(
        streamable_http_client(url, http_client=http),
        mode=sdk_mode,
        logging_callback=on_log,
    )

    entered = False

    async def initialize() -> str:
        nonlocal entered
        await client.__aenter__()
        entered = True
        version = client.session.protocol_version
        expect(version == "2025-11-25", f"negotiated 2025-11-25, got {version}")
        return f"protocol={version}"

    await check(sdk_mode, "initialize", initialize)
    if not entered:
        await http.aclose()
        return 1

    try:
        if scenario == "reference":
            await run_reference(sdk_mode, client, logs)
        else:
            assert workspace is not None
            await run_fixture(sdk_mode, client, workspace)
    finally:

        async def close() -> str:
            await client.__aexit__(None, None, None)
            await http.aclose()
            return "closed=true"

        await check(sdk_mode, "close", close)
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
        logs.clear()
        await client.set_logging_level("debug")
        await client.call_tool("test_tool_with_logging", {})
        # Notifications are dispatched to the callback concurrently with the result.
        await wait_for("3 log notifications", 2.0, lambda: len(logs) >= 3)
        expect(len(logs) == 3, f"3 log notifications, got {len(logs)}")
        return f"logs={len(logs)}"

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
    invocations = workspace / "invocations.log"

    def sleep_count() -> int:
        if not invocations.exists():
            return 0
        return sum(1 for line in invocations.read_text().splitlines() if line == "sleep")

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

    await check(sdk_mode, "tools/list", tools_list)
    await check(sdk_mode, "tools/call", tools_call)
    await check(sdk_mode, "notifications/progress", progress)
    await check(sdk_mode, "cancellation", cancellation)
    await check(sdk_mode, "after-cancel", after_cancel)


if __name__ == "__main__":
    sys.exit(anyio.run(main))
