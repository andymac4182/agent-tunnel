/**
 * The filesystem demo's consumer (docs/demo/filesystem.md, task row M4-54).
 *
 * A device exports a synthetic directory through a local relay; this script is
 * the other end. It connects with the shared client, `connectFilesystem`, over
 * the relay's real TLS listener with a real bearer token, and then reads the
 * same export three ways:
 *
 * 1. **The shared client** — lists, stats, reads and walks the whole tree,
 *    hashing every file it reads.
 * 2. **just-bash** — the real `Bash` interpreter from `just-bash` 3.4.2 over
 *    `TunnelJustBashFilesystem`, running `find`, `ls`, `cat`, `wc` and
 *    `md5sum` against the remote export.
 * 3. **Mastra** — the real `Workspace` from `@mastra/core` 1.65.0 over
 *    `TunnelMastraFilesystem`, with `@mastra/core`'s own error classes.
 * 4. **Files SDK** — the real `Files` from `files-sdk` 2.4.0 over
 *    `createFilesAdapter`: `list`, `head` and `download`.
 *
 * With `DEMO_SIGNAL_DIR` set it then holds the session open, writes
 * `ready` there, waits for the script to revoke the grant and write
 * `revoked`, and reports how the live session ended (task row M4-06's
 * "revocation under a live shared TypeScript client").
 *
 * It then shows the export refusing what the grant does not allow: a write,
 * a path that climbs out of the export, and a symlink that points outside it.
 *
 * Inputs, all from the environment so no token is ever in a process listing:
 *
 * * `DEMO_ENDPOINT` — the `https://…/v1/devices/<device>/services/<service>/fs`
 *   endpoint.
 * * `DEMO_TOKEN_FILE` — a file holding one bearer token.
 * * `NODE_EXTRA_CA_CERTS` — the relay listener's CA. Verification is never
 *   turned off: the script refuses to run with `NODE_TLS_REJECT_UNAUTHORIZED=0`.
 *
 * Output is human-readable, and the last line is `DEMO-RESULT <json>`, which
 * `scripts/fs-demo.sh` compares against the host directory it exported. The
 * content is synthetic by construction; the token is never printed.
 */

import { createHash } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import * as workspaceModule from '@mastra/core/workspace';
import { Workspace } from '@mastra/core/workspace';
import { Files, FilesError } from 'files-sdk';
import { Bash } from 'just-bash';
import type { SecurityViolationType } from 'just-bash';

import {
  FilesystemError,
  PathRefusal,
  connectFilesystem,
  type RemoteFilesystem,
} from '../src/index.ts';
import { createFilesAdapter } from '../src/adapters/files-sdk.ts';
import { TunnelJustBashFilesystem } from '../src/adapters/just-bash.ts';
import { TunnelMastraFilesystem } from '../src/adapters/mastra.ts';

interface TreeEntry {
  path: string;
  kind: 'file' | 'directory' | 'symlink';
  size: number;
  sha256?: string;
}

interface Refusal {
  attempt: string;
  refused: boolean;
  code: string;
  outcome?: string;
}

function requireEnv(name: string): string {
  const value = process.env[name];
  if (value === undefined || value === '') {
    throw new Error(`${name} is required`);
  }
  return value;
}

function sha256(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

function heading(text: string): void {
  console.log(`\n== ${text}`);
}

function codeOf(error: unknown): { code: string; outcome?: string } {
  if (error instanceof FilesystemError) {
    return { code: error.code, outcome: error.outcome };
  }
  if (error instanceof PathRefusal) {
    return { code: `PathRefusal:${error.rule}` };
  }
  if (error instanceof Error) {
    // Mastra's error classes carry a `code`; anything else is named by class.
    const code = (error as Error & { code?: unknown }).code;
    return { code: typeof code === 'string' ? code : `${error.name}: ${error.message.slice(0, 80)}` };
  }
  return { code: 'unknown' };
}

/** Walk the tree with the shared client: list, stat and read every entry. */
async function walk(remote: RemoteFilesystem): Promise<TreeEntry[]> {
  const out: TreeEntry[] = [];
  const visit = async (dir: string): Promise<void> => {
    const children: string[] = [];
    const listed = new Map<string, TreeEntry['kind']>();
    for await (const entry of remote.readDirectory(dir)) {
      children.push(entry.name);
      listed.set(entry.name, entry.kind);
    }
    children.sort();
    for (const name of children) {
      const path = dir === '/' ? `/${name}` : `${dir}/${name}`;
      if (listed.get(name) === 'symlink') {
        // Listed as a link and never followed: this export does not enable
        // the `symlinks` feature, so the device refuses to resolve through it.
        out.push({ path, kind: 'symlink', size: 0 });
        continue;
      }
      const stat = await remote.stat(path);
      if (stat.kind === 'directory') {
        out.push({ path, kind: 'directory', size: 0 });
        await visit(path);
      } else if (stat.kind === 'file') {
        const bytes = await remote.readFile(path);
        out.push({ path, kind: 'file', size: Number(stat.size), sha256: sha256(bytes) });
      } else {
        // Listed and stat-ed as a link, never followed by this walk.
        out.push({ path, kind: 'symlink', size: Number(stat.size) });
      }
    }
  };
  await visit('/');
  return out;
}

async function main(): Promise<void> {
  if (process.env.NODE_TLS_REJECT_UNAUTHORIZED === '0') {
    throw new Error('refusing to run with NODE_TLS_REJECT_UNAUTHORIZED=0: the demo verifies the relay');
  }
  const endpoint = requireEnv('DEMO_ENDPOINT');
  const tokenFile = requireEnv('DEMO_TOKEN_FILE');
  const token = (): string => readFileSync(tokenFile, 'utf8').trim();

  heading('1. shared client: connectFilesystem through the relay');
  const remote = await connectFilesystem({ endpoint, token });
  const descriptor = remote.descriptor;
  console.log(`connected: msize=${remote.msize} availability=${descriptor.availability}`);
  console.log(`root.readOnly=${descriptor.root.readOnly} caseSensitivity=${descriptor.root.caseSensitivity}`);
  console.log(`operations=${[...descriptor.operations].sort().join(',')}`);

  heading('2. shared client: list, stat, read and walk');
  const top: string[] = [];
  for await (const entry of remote.readDirectory('/')) {
    top.push(`${entry.kind === 'directory' ? 'd' : entry.kind === 'symlink' ? 'l' : '-'} ${entry.name}`);
  }
  top.sort((a, b) => a.slice(2).localeCompare(b.slice(2)));
  console.log(`ls /\n  ${top.join('\n  ')}`);
  const readme = new TextDecoder().decode(await remote.readFile('/README.md'));
  console.log(`cat /README.md\n  ${readme.trimEnd().split('\n').join('\n  ')}`);
  const tree = await walk(remote);
  for (const entry of tree) {
    const detail = entry.kind === 'file' ? `${entry.size} bytes sha256=${entry.sha256?.slice(0, 16)}…` : entry.kind;
    console.log(`  ${entry.path}  ${detail}`);
  }
  console.log(`walked ${tree.length} entries (${tree.filter((e) => e.kind === 'file').length} files)`);

  heading('3. just-bash: a real Bash over the remote export');
  const excludeViolationTypes: SecurityViolationType[] = ['setTimeout'];
  const bashFs = new TunnelJustBashFilesystem({ remote });
  const bash = new Bash({ fs: bashFs, cwd: '/', defenseInDepth: { excludeViolationTypes } });
  const script = [
    'ls /',
    'find / -type f | sort',
    'cat /docs/notes.txt | wc -l',
    'find / -type f | sort | xargs md5sum',
  ];
  const bashResults: { command: string; exitCode: number; stdout: string }[] = [];
  for (const command of script) {
    const result = await bash.exec(command);
    bashResults.push({ command, exitCode: result.exitCode, stdout: result.stdout });
    console.log(`$ ${command}   (exit ${result.exitCode})`);
    const body = result.stdout.trimEnd();
    if (body !== '') {
      console.log(`  ${body.split('\n').join('\n  ')}`);
    }
    if (result.stderr.trim() !== '') {
      console.log(`  stderr: ${result.stderr.trim().split('\n').join(' | ')}`);
    }
  }
  const failures = bashFs.drainOperationFailures();

  heading('4. Mastra: Workspace over TunnelMastraFilesystem');
  const workspace = new Workspace({
    filesystem: new TunnelMastraFilesystem({ remote, errors: workspaceModule }),
  });
  await workspace.init();
  const mastraFs = workspace.filesystem;
  if (mastraFs === undefined) {
    throw new Error('the Mastra workspace has no filesystem');
  }
  const mastraEntries = (await mastraFs.readdir('/', { recursive: true }))
    .map((entry) => `${entry.type === 'directory' ? 'd' : '-'} ${entry.name}`)
    .sort((a, b) => a.slice(2).localeCompare(b.slice(2)));
  console.log(`readdir / recursive: ${mastraEntries.length} entries`);
  console.log(`  ${mastraEntries.join('\n  ')}`);
  const mastraStat = await mastraFs.stat('/data/numbers.csv');
  console.log(`stat /data/numbers.csv: type=${mastraStat.type} size=${mastraStat.size}`);
  const mastraCsv = await mastraFs.readFile('/data/numbers.csv', { encoding: 'utf8' });
  const mastraCsvSha = sha256(new TextEncoder().encode(String(mastraCsv)));
  console.log(`readFile /data/numbers.csv: sha256=${mastraCsvSha.slice(0, 16)}…`);
  console.log(`exists /missing.txt: ${await mastraFs.exists('/missing.txt')}`);

  heading('5. Files SDK: new Files({ adapter }) over createFilesAdapter');
  const files = new Files({ adapter: createFilesAdapter({ remote, FilesError }), retries: 0 });
  const listed = await files.list();
  const filesKeys = listed.items.map((item) => item.key).sort();
  console.log(`list: ${filesKeys.length} keys`);
  console.log(`  ${filesKeys.join('\n  ')}`);
  const head = await files.head('data/blob.bin');
  const blob = new Uint8Array(await (await files.download('data/blob.bin')).arrayBuffer());
  const filesBlobSha = sha256(blob);
  console.log(`head data/blob.bin: size=${head.size}; download sha256=${filesBlobSha.slice(0, 16)}…`);

  heading('6. what the export refuses');
  const refusals: Refusal[] = [];
  const attempt = async (label: string, run: () => Promise<unknown>): Promise<void> => {
    try {
      await run();
      refusals.push({ attempt: label, refused: false, code: 'none' });
      console.log(`${label}: NOT refused`);
    } catch (error) {
      const { code, outcome } = codeOf(error);
      refusals.push({ attempt: label, refused: true, code, ...(outcome === undefined ? {} : { outcome }) });
      console.log(`${label}: refused ${code}${outcome === undefined ? '' : ` outcome=${outcome}`}`);
    }
  };
  await attempt('write /new.txt (read-only grant)', async () =>
    await remote.writeFile('/new.txt', new TextEncoder().encode('synthetic')));
  await attempt('read /../outside.txt (climbs out of the export)', async () =>
    await remote.readFile('/../outside.txt'));
  await attempt('read /escape-link (symlink to a file outside the export)', async () =>
    await remote.readFile('/escape-link'));
  await attempt('mastra writeFile /new.txt', async () => await mastraFs.writeFile('/new.txt', 'synthetic'));
  await attempt('files-sdk upload new.txt', async () => await files.upload('new.txt', 'synthetic'));
  await attempt('bash: echo synthetic > /new.txt', async () => {
    // A redirection the export refuses either fails the command or, as
    // just-bash 3.4.2 does for a filesystem error, rejects `exec` itself.
    const result = await bash.exec('echo synthetic > /new.txt');
    if (result.exitCode !== 0) {
      throw new Error(`exit ${result.exitCode}`);
    }
  });

  await workspace.destroy();

  let revocation: Record<string, unknown> | undefined;
  const signalDir = process.env.DEMO_SIGNAL_DIR;
  if (signalDir !== undefined && signalDir !== '') {
    heading('7. revocation under a live session');
    // Prove the session is live first, so the failure below is the revocation.
    await remote.stat('/README.md');
    writeFileSync(join(signalDir, 'ready'), 'ready\n');
    console.log('session live; waiting for the operator to revoke the grant');
    const waitStarted = Date.now();
    while (!existsSync(join(signalDir, 'revoked'))) {
      if (Date.now() - waitStarted > 60_000) {
        throw new Error('the grant was never revoked');
      }
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    const revokedAt = Date.now();
    let code = 'none';
    let attempts = 0;
    while (Date.now() - revokedAt < 30_000) {
      attempts += 1;
      try {
        await remote.stat('/README.md');
        await new Promise((resolve) => setTimeout(resolve, 100));
      } catch (error) {
        code = codeOf(error).code;
        break;
      }
    }
    const closed = remote.closedWith;
    revocation = {
      code,
      attempts,
      elapsedMs: Date.now() - revokedAt,
      closeCode: closed?.code ?? null,
      closeLocal: closed?.local ?? null,
      state: remote.state,
    };
    console.log(
      `after revoke-grant: operation refused ${code} after ${String(revocation.elapsedMs)} ms; ` +
        `socket closed ${String(revocation.closeCode)} by ${closed?.local === true ? 'this client' : 'the relay'}; state=${remote.state}`,
    );
  }
  if (remote.state !== 'closed') {
    await remote.close();
  }
  console.log('\nclosed the session');

  console.log(
    `DEMO-RESULT ${JSON.stringify({
      descriptor: {
        readOnly: descriptor.root.readOnly,
        operations: [...descriptor.operations].sort(),
      },
      tree,
      bash: bashResults,
      bashFailuresRecorded: failures.entries.length,
      mastra: { entries: mastraEntries, csvSize: mastraStat.size, csvSha256: mastraCsvSha },
      files: { keys: filesKeys, blobSize: head.size, blobSha256: filesBlobSha },
      refusals,
      revocation: revocation ?? null,
    })}`,
  );
}

main().catch((error: unknown) => {
  const { code } = codeOf(error);
  console.error(`filesystem-demo: failed: ${code}${error instanceof Error ? `: ${error.message}` : ''}`);
  process.exitCode = 1;
});
