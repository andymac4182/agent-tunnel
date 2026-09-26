// A plain MCP server built on the pinned official TypeScript SDK
// (@modelcontextprotocol/sdk 1.30.1: McpServer + StreamableHTTPServerTransport,
// stateful, 2025-11-25), used by scripts/m3-sdk-conformance.sh (task row
// M3-17) as the device-exported backend for the Python SDK's tools, resources,
// prompts and notification cases.
//
// Why not the conformance suite's reference server: that server refuses the
// Python SDK 2.2.0's `initialize` (task row M3-47), so it cannot carry those
// cases.  The tool, resource and prompt names and contents mirror the
// reference server's, so one client script serves both.
//
//   PORT=<port> node ts-sdk-server.mjs     (binds 127.0.0.1 only)
import http from 'node:http';
import { randomUUID } from 'node:crypto';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { z } from 'zod';

// A 1x1 transparent PNG, synthetic.
const PNG = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==';
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function buildServer() {
  const server = new McpServer(
    { name: 'm3-17-ts-sdk-server', version: '0.0.0' },
    { capabilities: { logging: {} } },
  );
  server.registerTool('test_simple_text', { description: 'simple text' }, async () => ({
    content: [{ type: 'text', text: 'This is a simple text response for testing.' }],
  }));
  server.registerTool('test_image_content', { description: 'image' }, async () => ({
    content: [{ type: 'image', data: PNG, mimeType: 'image/png' }],
  }));
  server.registerTool('test_error_handling', { description: 'error' }, async () => {
    throw new Error('This tool intentionally returns an error for testing');
  });
  server.registerTool('test_tool_with_progress', { description: 'progress', inputSchema: {} },
    async (_args, { sendNotification, _meta }) => {
      const progressToken = _meta?.progressToken ?? 0;
      for (const progress of [0, 50, 100]) {
        await sendNotification({
          method: 'notifications/progress',
          params: { progressToken, progress, total: 100 },
        });
        await sleep(20);
      }
      return { content: [{ type: 'text', text: 'progress done' }] };
    });
  server.registerTool('test_tool_with_logging', { description: 'logging', inputSchema: {} },
    async (_args, { sendNotification }) => {
      for (const data of ['Tool execution started', 'Tool processing data', 'Tool execution completed']) {
        await sendNotification({ method: 'notifications/message', params: { level: 'info', data } });
        await sleep(20);
      }
      return { content: [{ type: 'text', text: 'Tool with logging executed successfully' }] };
    });
  server.registerResource('static-text', 'test://static-text', { mimeType: 'text/plain' },
    async (uri) => ({ contents: [{ uri: uri.href, mimeType: 'text/plain', text: 'Synthetic static text.' }] }));
  server.registerResource('static-binary', 'test://static-binary', { mimeType: 'image/png' },
    async (uri) => ({ contents: [{ uri: uri.href, mimeType: 'image/png', blob: PNG }] }));
  server.registerPrompt('test_simple_prompt', { description: 'simple prompt' }, async () => ({
    messages: [{ role: 'user', content: { type: 'text', text: 'This is a simple prompt for testing.' } }],
  }));
  server.registerPrompt('test_prompt_with_arguments',
    { description: 'prompt with arguments', argsSchema: { arg1: z.string(), arg2: z.string() } },
    async ({ arg1, arg2 }) => ({
      messages: [{ role: 'user', content: { type: 'text', text: `Prompt with arguments: arg1='${arg1}', arg2='${arg2}'` } }],
    }));
  return server;
}

const transports = new Map();

async function readJson(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const text = Buffer.concat(chunks).toString('utf8');
  return text ? JSON.parse(text) : undefined;
}

const httpServer = http.createServer(async (req, res) => {
  try {
    if (new URL(req.url, 'http://127.0.0.1').pathname !== '/mcp') {
      res.writeHead(404).end();
      return;
    }
    const sessionId = req.headers['mcp-session-id'];
    const body = req.method === 'POST' ? await readJson(req) : undefined;
    let transport = sessionId ? transports.get(sessionId) : undefined;
    if (!transport) {
      if (sessionId || req.method !== 'POST' || body?.method !== 'initialize') {
        res.writeHead(sessionId ? 404 : 400, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32000, message: 'no session' } }));
        return;
      }
      transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
        onsessioninitialized: (id) => transports.set(id, transport),
      });
      transport.onclose = () => {
        if (transport.sessionId) transports.delete(transport.sessionId);
      };
      await buildServer().connect(transport);
    }
    await transport.handleRequest(req, res, body);
  } catch {
    if (!res.headersSent) res.writeHead(500).end();
  }
});

httpServer.listen(Number(process.env.PORT ?? 0), '127.0.0.1', () => {
  console.log(`ts-sdk-server running on 127.0.0.1:${httpServer.address().port}`);
});
