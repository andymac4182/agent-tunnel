// The official MCP TypeScript SDK (@modelcontextprotocol/sdk, pinned in
// package.json) as an off-the-shelf Streamable HTTP client, driven through a
// real local relay by scripts/m3-sdk-conformance.sh (task row M3-17).
//
//   node ts-client.ts reference <url>
//   node ts-client.ts fixture <url> <device-workspace>
//
// `reference` expects the MCP conformance suite's reference everything-server
// behind the device export; `fixture` expects the repository's rmcp fixture
// (`tunnel-mcp-fixture stdio`).  The bearer token comes from
// AGENTUPLINK_TOKEN and the relay's synthetic CA from NODE_EXTRA_CA_CERTS.
// Each case prints one payload-free line `sdk=typescript case=<name>
// result=pass|fail ...`; the exit status is 1 if any case failed.
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { LoggingMessageNotificationSchema } from '@modelcontextprotocol/sdk/types.js';

const [mode, rawUrl, workspace] = process.argv.slice(2);
const token = process.env.AGENTUPLINK_TOKEN;
if (!rawUrl || !token || (mode !== 'reference' && mode !== 'fixture') ||
    (mode === 'fixture' && !workspace)) {
  console.error('usage: AGENTUPLINK_TOKEN=... node ts-client.ts reference|fixture <url> [workspace]');
  process.exit(2);
}

let failures = 0;
function report(name: string, ok: boolean, detail = ''): void {
  if (!ok) failures += 1;
  console.log(`sdk=typescript case=${name} result=${ok ? 'pass' : 'fail'}${detail ? ' ' + detail : ''}`);
}
async function check(name: string, body: () => Promise<string | void>): Promise<void> {
  try {
    const detail = await body();
    report(name, true, detail ?? '');
  } catch (error) {
    // Error messages from the SDK carry status codes and JSON-RPC error
    // messages, never request bodies or the token.
    const message = error instanceof Error ? error.message : String(error);
    report(name, false, `error=${JSON.stringify(message.slice(0, 300))}`);
  }
}
function assert(condition: unknown, what: string): asserts condition {
  if (!condition) throw new Error(`expected ${what}`);
}
const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
async function waitFor(what: string, ms: number, probe: () => boolean): Promise<void> {
  const deadline = Date.now() + ms;
  while (!probe()) {
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await delay(25);
  }
}

const transport = new StreamableHTTPClientTransport(new URL(rawUrl), {
  requestInit: { headers: { Authorization: `Bearer ${token}` } },
});
const client = new Client({ name: 'm3-17-typescript-sdk', version: '0.0.0' });
const logs: string[] = [];
client.setNotificationHandler(LoggingMessageNotificationSchema, (notification) => {
  logs.push(String(notification.params.level));
});

await check('initialize', async () => {
  await client.connect(transport);
  const version = transport.protocolVersion;
  assert(version === '2025-11-25', `negotiated 2025-11-25, got ${version}`);
  assert(transport.sessionId, 'an Mcp-Session-Id from the backend');
  return `protocol=${version} server=${client.getServerVersion()?.name ?? 'unknown'}`;
});

if (mode === 'reference') {
  await check('tools/list', async () => {
    const { tools } = await client.listTools();
    const names = tools.map((tool) => tool.name);
    for (const name of ['test_simple_text', 'test_tool_with_progress', 'test_tool_with_logging']) {
      assert(names.includes(name), `tool ${name}`);
    }
    return `tools=${tools.length}`;
  });
  await check('tools/call', async () => {
    const result = await client.callTool({ name: 'test_simple_text', arguments: {} });
    const content = result.content as Array<{ type: string; text?: string }>;
    assert(content[0]?.type === 'text' && content[0].text === 'This is a simple text response for testing.',
      'the reference text block');
    return 'content=text';
  });
  await check('tools/call-image', async () => {
    const result = await client.callTool({ name: 'test_image_content', arguments: {} });
    const content = result.content as Array<{ type: string; mimeType?: string; data?: string }>;
    assert(content[0]?.type === 'image' && content[0].mimeType === 'image/png' && content[0].data,
      'an image/png block');
    return `image_b64_len=${content[0].data!.length}`;
  });
  await check('tools/call-error', async () => {
    const result = await client.callTool({ name: 'test_error_handling', arguments: {} });
    assert(result.isError === true, 'isError: true');
    return 'isError=true';
  });
  await check('resources/list', async () => {
    const { resources } = await client.listResources();
    assert(resources.some((r) => r.uri === 'test://static-text'), 'test://static-text');
    return `resources=${resources.length}`;
  });
  await check('resources/read', async () => {
    const { contents } = await client.readResource({ uri: 'test://static-text' });
    const first = contents[0] as { uri: string; text?: string };
    assert(first?.uri === 'test://static-text' && typeof first.text === 'string', 'a text resource');
    const binary = await client.readResource({ uri: 'test://static-binary' });
    const blob = binary.contents[0] as { blob?: string };
    assert(typeof blob?.blob === 'string' && blob.blob.length > 0, 'a binary resource');
    return 'text=1 blob=1';
  });
  await check('prompts/list', async () => {
    const { prompts } = await client.listPrompts();
    assert(prompts.some((p) => p.name === 'test_simple_prompt'), 'test_simple_prompt');
    assert(prompts.some((p) => p.name === 'test_prompt_with_arguments'), 'test_prompt_with_arguments');
    return `prompts=${prompts.length}`;
  });
  await check('prompts/get', async () => {
    const simple = await client.getPrompt({ name: 'test_simple_prompt' });
    assert(simple.messages.length > 0, 'a message');
    const withArgs = await client.getPrompt({
      name: 'test_prompt_with_arguments',
      arguments: { arg1: 'synthetic-a', arg2: 'synthetic-b' },
    });
    const text = JSON.stringify(withArgs.messages);
    assert(text.includes('synthetic-a') && text.includes('synthetic-b'), 'both arguments substituted');
    return `messages=${simple.messages.length}+${withArgs.messages.length}`;
  });
  await check('notifications/progress', async () => {
    const seen: number[] = [];
    await client.callTool({ name: 'test_tool_with_progress', arguments: {} }, undefined, {
      onprogress: (progress) => { seen.push(progress.progress); },
    });
    assert(seen.length === 3 && seen.join(',') === '0,50,100', `progress 0,50,100 in order, got ${seen.join(',')}`);
    return `progress=${seen.join(',')}`;
  });
  await check('notifications/message', async () => {
    logs.length = 0;
    await client.setLoggingLevel('debug');
    await client.callTool({ name: 'test_tool_with_logging', arguments: {} });
    assert(logs.length === 3, `3 log notifications, got ${logs.length}`);
    return `logs=${logs.length}`;
  });
} else {
  const invocations = join(workspace!, 'invocations.log');
  const sleepCount = () =>
    existsSync(invocations)
      ? readFileSync(invocations, 'utf8').split('\n').filter((line) => line === 'sleep').length
      : 0;
  await check('tools/list', async () => {
    const { tools } = await client.listTools();
    const names = tools.map((tool) => tool.name);
    assert(names.includes('echo') && names.includes('sleep') && names.includes('progress'), 'echo, sleep, progress');
    return `tools=${tools.length}`;
  });
  await check('tools/call', async () => {
    const result = await client.callTool({
      name: 'echo',
      arguments: { value: 'synthetic-ts' },
      _meta: { 'example.test/marker': 'synthetic-meta' },
    });
    const content = result.content as Array<{ type: string; text?: string }>;
    const echoed = JSON.parse(content[0]!.text!);
    assert(echoed.arguments?.value === 'synthetic-ts', 'arguments echoed');
    assert(echoed.meta?.['example.test/marker'] === 'synthetic-meta', '_meta preserved');
    assert(content.some((block) => block.type === 'image'), 'the image block');
    return 'arguments=preserved meta=preserved';
  });
  await check('notifications/progress', async () => {
    const seen: number[] = [];
    await client.callTool({ name: 'progress', arguments: { steps: 5 } }, undefined, {
      onprogress: (progress) => { seen.push(progress.progress); },
    });
    const ordered = seen.every((value, index) => index === 0 || value > seen[index - 1]!);
    assert(seen.length === 5 && ordered, `5 ordered progress notifications, got ${seen.length}`);
    return `progress=${seen.length}`;
  });
  await check('cancellation', async () => {
    const label = `ts${process.pid}`;
    const marker = join(workspace!, `cancelled-${label}`);
    const before = sleepCount();
    const controller = new AbortController();
    const call = client.callTool({ name: 'sleep', arguments: { label } }, undefined, {
      signal: controller.signal,
      timeout: 60_000,
    });
    // Abort only once the device's server has the call, so the cancel
    // provably crosses the relay after dispatch.
    await waitFor('the sleep call to reach the device server', 15_000, () => sleepCount() > before);
    controller.abort('m3-17 synthetic cancel');
    const outcome = await call.then(() => 'resolved', (error: unknown) =>
      error instanceof Error ? error.name : 'rejected');
    await waitFor('the server to record the cancellation', 15_000, () => existsSync(marker));
    return `client_outcome=${outcome} server_marker=cancelled`;
  });
  await check('after-cancel', async () => {
    // The session stays usable after a cancelled call.
    const result = await client.callTool({ name: 'echo', arguments: { value: 'after' } });
    assert(!result.isError, 'a successful call');
    return 'session=usable';
  });
}

await check('close', async () => {
  await transport.terminateSession();
  await client.close();
  return 'session=deleted';
});

process.exit(failures === 0 ? 0 : 1);
