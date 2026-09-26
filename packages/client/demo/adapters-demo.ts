/**
 * The four-adapter demo's consumer (docs/demo/adapters.md, task rows M4-63 to
 * M4-69).
 *
 * A device exports a synthetic directory through a local relay with a
 * read/write/list/delete grant; this script is the other end. It makes **one**
 * connection with the shared client and lends it to all four native adapters,
 * each driven through its own framework's real public API:
 *
 * 1. **Files SDK** — `new Files({ adapter: createFilesAdapter(...) })`: list,
 *    head, download (hashed), upload, exists, delete.
 * 2. **just-bash** — a real `Bash` over `TunnelJustBashFilesystem`: `ls`,
 *    `find | xargs md5sum`, a pipeline, `grep -c`, and a redirect that writes a
 *    file on the device.
 * 3. **Mastra** — a real `Agent` with a `Workspace` over
 *    `TunnelMastraFilesystem`; a scripted model (no LLM, no key) calls the
 *    workspace's own `list_files`, `read_file` and `write_file` tools.
 * 4. **AI SDK** — the real `generateText` tool loop over
 *    `createFilesystemTools`, with the same kind of scripted model calling
 *    `list_directory`, `read_file` (bounded, truncated), `stat` and
 *    `write_file`; then `FilesV4` via the real `ai.uploadFile`, with metadata
 *    and download on the provider instance.
 *
 * Inputs come from the environment, so no token is in a process listing:
 * `DEMO_ENDPOINT`, `DEMO_TOKEN_FILE`, and `NODE_EXTRA_CA_CERTS` for the relay
 * listener's CA. TLS verification is never disabled.
 *
 * Output is a human-readable transcript; the last line is `DEMO-RESULT <json>`,
 * which `scripts/adapters-demo.sh` checks against the exported host directory.
 * All content is synthetic; the token is never printed.
 */

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

import { Files, FilesError } from 'files-sdk';
import { Agent } from '@mastra/core/agent';
import * as workspaceModule from '@mastra/core/workspace';
import { Workspace } from '@mastra/core/workspace';
import { Bash } from 'just-bash';
import type { SecurityViolationType } from 'just-bash';
import { generateText, stepCountIs, uploadFile } from 'ai';

import { connectFilesystem, type RemoteFilesystem } from '../src/index.ts';
import { createFilesAdapter } from '../src/adapters/files-sdk.ts';
import { REQUIRED_DEFENSE_EXCLUSIONS, TunnelJustBashFilesystem } from '../src/adapters/just-bash.ts';
import { TunnelMastraFilesystem } from '../src/adapters/mastra.ts';
import { createFilesApi, createFilesystemTools, PROVIDER_KEY } from '../src/adapters/ai-sdk.ts';
import { scriptedModel } from './scripted-model.ts';

function requireEnv(name: string): string {
  const value = process.env[name];
  if (value === undefined || value === '') {
    throw new Error(`${name} is required`);
  }
  return value;
}

const sha256 = (bytes: Uint8Array): string => createHash('sha256').update(bytes).digest('hex');
const heading = (text: string): void => console.log(`\n== ${text}`);
const show = (label: string, value: unknown): void =>
  console.log(`  ${label}: ${typeof value === 'string' ? value : JSON.stringify(value)}`);
const clip = (text: string, max = 240): string => (text.length > max ? `${text.slice(0, max)}…` : text);

/* ---------------------------------------------------------------------- *
 * 1. Files SDK
 * ---------------------------------------------------------------------- */

async function filesSdk(remote: RemoteFilesystem): Promise<Record<string, unknown>> {
  heading('Files SDK 2.4.0: new Files({ adapter: createFilesAdapter({ remote, FilesError }) })');
  const files = new Files({ adapter: createFilesAdapter({ remote, FilesError }), retries: 0 });

  const keys: string[] = [];
  let cursor: string | undefined;
  do {
    const page = await files.list(cursor === undefined ? { limit: 100 } : { limit: 100, cursor });
    keys.push(...page.items.map((item) => item.key));
    cursor = page.cursor ?? undefined;
  } while (cursor !== undefined);
  keys.sort();
  show('files.list() keys', keys);

  const head = await files.head('docs/notes.txt');
  show('files.head("docs/notes.txt").size', head.size);

  const blob = new Uint8Array(await (await files.download('data/blob.bin')).arrayBuffer());
  const blobSha256 = sha256(blob);
  show('files.download("data/blob.bin")', `${blob.byteLength} bytes, sha256 ${blobSha256}`);

  const uploadedText = 'Uploaded through Files SDK.\n';
  await files.upload('outbox/files-sdk.txt', uploadedText);
  show('files.upload("outbox/files-sdk.txt")', 'ok');
  const uploadedExists = await files.exists('outbox/files-sdk.txt');
  show('files.exists("outbox/files-sdk.txt")', uploadedExists);

  await files.upload('outbox/scratch.txt', 'temporary');
  await files.delete('outbox/scratch.txt');
  const scratchExists = await files.exists('outbox/scratch.txt');
  show('files.delete("outbox/scratch.txt") then exists', scratchExists);

  return { keys, headSize: head.size, blobBytes: blob.byteLength, blobSha256, uploadedText, uploadedExists, scratchExists };
}

/* ---------------------------------------------------------------------- *
 * 2. just-bash
 * ---------------------------------------------------------------------- */

async function justBash(remote: RemoteFilesystem): Promise<Record<string, unknown>> {
  heading('just-bash 3.4.2: new Bash({ fs: new TunnelJustBashFilesystem({ remote }) })');
  const fs = new TunnelJustBashFilesystem({ remote });
  const excluded: SecurityViolationType[] = [...REQUIRED_DEFENSE_EXCLUSIONS];
  const bash = new Bash({ fs, cwd: '/', defenseInDepth: { excludeViolationTypes: excluded } });
  const commands = [
    'ls /docs',
    'find /docs /data -type f | sort | xargs md5sum',
    'cat /docs/notes.txt | wc -l',
    'grep -c "," /data/numbers.csv',
    'echo "written by just-bash" > /outbox/just-bash.txt && cat /outbox/just-bash.txt',
  ];
  const results: { command: string; exitCode: number; stdout: string; stderr: string }[] = [];
  for (const command of commands) {
    const result = await bash.exec(command);
    results.push({ command, exitCode: result.exitCode, stdout: result.stdout, stderr: result.stderr });
    console.log(`  $ ${command}`);
    for (const line of result.stdout.trimEnd().split('\n')) {
      console.log(`    ${line}`);
    }
    if (result.exitCode !== 0) {
      console.log(`    (exit ${result.exitCode}) ${clip(result.stderr.trim())}`);
    }
  }
  const drained = fs.drainOperationFailures();
  show('drainOperationFailures()', { entries: drained.entries.length, dropped: drained.dropped });
  return { commands: results, operationFailures: drained.entries.length };
}

/* ---------------------------------------------------------------------- *
 * 3. Mastra
 * ---------------------------------------------------------------------- */

async function mastra(remote: RemoteFilesystem): Promise<Record<string, unknown>> {
  heading('Mastra 1.65.0: an Agent with a Workspace over TunnelMastraFilesystem, scripted model');
  const filesystem = new TunnelMastraFilesystem({ remote, errors: workspaceModule });
  const workspace = new Workspace({ filesystem });
  const writtenText = 'Written by a Mastra agent tool call.\n';
  const { model, offered } = scriptedModel([
    { toolName: 'mastra_workspace_list_files', input: { path: '/docs' } },
    { toolName: 'mastra_workspace_read_file', input: { path: '/docs/notes.txt' } },
    { toolName: 'mastra_workspace_write_file', input: { path: '/outbox/mastra.txt', content: writtenText } },
  ]);
  const agent = new Agent({
    id: 'adapters-demo-mastra',
    name: 'adapters-demo-mastra',
    instructions: 'Inspect the workspace with its tools.',
    model,
    workspace,
  });
  const result = await agent.generate('List /docs, read the notes and leave a note in /outbox.', { maxSteps: 5 });
  const calls = result.steps.flatMap((step) =>
    step.toolResults.map((part) => ({
      toolName: part.payload.toolName,
      args: part.payload.args,
      result: String(part.payload.result),
    })),
  );
  show('tools offered on step 1', offered[0]?.filter((name) => name.startsWith('mastra_workspace_')) ?? []);
  for (const call of calls) {
    console.log(`  tool ${call.toolName}(${JSON.stringify(call.args)})`);
    for (const line of clip(call.result, 400).split('\n')) {
      console.log(`    ${line}`);
    }
  }
  show('agent text', result.text);
  return { calls, text: result.text, writtenText, offered: offered[0] ?? [] };
}

/* ---------------------------------------------------------------------- *
 * 4. AI SDK
 * ---------------------------------------------------------------------- */

async function aiSdk(remote: RemoteFilesystem): Promise<Record<string, unknown>> {
  heading('AI SDK 7.0.94: generateText over createFilesystemTools, scripted model');
  const tools = createFilesystemTools({ remote, maxReadBytes: 4096 });
  const writtenText = 'Written by an AI SDK tool call.\n';
  const { model, offered } = scriptedModel([
    { toolName: 'list_directory', input: { path: '/data' } },
    { toolName: 'read_file', input: { path: '/data/numbers.csv', maxBytes: 64 } },
    { toolName: 'stat', input: { path: '/data/blob.bin' } },
    { toolName: 'write_file', input: { path: '/outbox/ai-sdk.txt', content: writtenText } },
    { toolName: 'write_file', input: { path: '/outbox/ai-sdk.txt', content: 'second attempt' } },
  ]);
  const result = await generateText({
    model,
    tools,
    prompt: 'Inspect /data, sample numbers.csv, check blob.bin, and leave a note in /outbox.',
    stopWhen: stepCountIs(8),
  });
  const calls = result.steps.flatMap((step) =>
    step.toolResults.map((part) => ({ toolName: part.toolName, input: part.input, output: part.output })),
  );
  show('tools offered on step 1', offered[0] ?? []);
  for (const call of calls) {
    console.log(`  tool ${call.toolName}(${JSON.stringify(call.input)})`);
    console.log(`    -> ${clip(JSON.stringify(call.output), 400)}`);
  }
  show('model text', result.text);

  heading('AI SDK 7.0.94: FilesV4 via ai.uploadFile({ api: createFilesApi(...) })');
  const api = createFilesApi({ remote, uploadDirectory: '/uploads' });
  const uploadBytes = new TextEncoder().encode('A managed upload through FilesV4.\n');
  const uploaded = await uploadFile({ api, data: uploadBytes, mediaType: 'text/plain', filename: 'managed.txt' });
  const reference = uploaded.providerReference[PROVIDER_KEY];
  show('uploadFile providerReference key', PROVIDER_KEY);
  const metadata = await api.getFileMetadata?.({ file: uploaded.providerReference });
  show('getFileMetadata', { byteSize: metadata?.byteSize, mediaType: metadata?.mediaType, filename: metadata?.filename });
  const download = await api.downloadFile?.({ file: uploaded.providerReference });
  let downloaded = new Uint8Array();
  if (download?.content instanceof ReadableStream) {
    downloaded = new Uint8Array(await new Response(download.content).arrayBuffer());
  }
  show('downloadFile', `${downloaded.byteLength} bytes, sha256 ${sha256(downloaded)}`);
  api.close();

  return {
    calls,
    text: result.text,
    writtenText,
    offered: offered[0] ?? [],
    filesV4: {
      referenceIsOpaque: typeof reference === 'string' && !reference.includes('/'),
      byteSize: metadata?.byteSize,
      uploadSha256: sha256(uploadBytes),
      downloadSha256: sha256(downloaded),
    },
  };
}

/* ---------------------------------------------------------------------- *
 * Main
 * ---------------------------------------------------------------------- */

if (process.env['NODE_TLS_REJECT_UNAUTHORIZED'] === '0') {
  throw new Error('refusing to run with TLS verification disabled');
}
const endpoint = requireEnv('DEMO_ENDPOINT');
const tokenFile = requireEnv('DEMO_TOKEN_FILE');

heading('connect: one shared client, borrowed by all four adapters');
const remote = await connectFilesystem({
  endpoint,
  token: () => readFileSync(tokenFile, 'utf8').trim(),
});
const descriptor = remote.descriptor;
show('descriptor', {
  schemaVersion: descriptor.schemaVersion,
  readOnly: descriptor.root.readOnly,
  operations: [...descriptor.operations].sort(),
});
show('negotiated msize', remote.msize);

const result: Record<string, unknown> = { descriptor: { readOnly: descriptor.root.readOnly, operations: descriptor.operations } };
try {
  result['filesSdk'] = await filesSdk(remote);
  result['justBash'] = await justBash(remote);
  result['mastra'] = await mastra(remote);
  result['aiSdk'] = await aiSdk(remote);
} finally {
  await remote.close();
}
console.log(`\nDEMO-RESULT ${JSON.stringify(result)}`);
