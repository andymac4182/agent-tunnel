/**
 * `npm run lint`: the package's own invariants, checked mechanically.
 *
 * These are the rules this package's README and `docs/filesystem-adapters.md`
 * state in prose — "no `any`, no assertion onto an upstream type and no
 * suppressed error", "each depends on its framework **by type only**", "zero
 * runtime dependencies", exact pins with a committed lockfile — so a change
 * that breaks one fails here instead of silently falsifying the docs. It needs
 * no install: it reads files, and it is deliberately not a general style
 * linter (`tsc --strict` with `noUnused*` already carries most of that).
 *
 * Every rule reports `file:line rule` and the script exits 1 if any fired. A
 * rule that scanned nothing is itself a failure, so a moved directory cannot
 * turn this green by accident.
 */

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const FRAMEWORKS = ['files-sdk', '@mastra/core', 'just-bash', 'ai', '@ai-sdk/provider', '@ai-sdk/provider-utils'];

interface Finding {
  where: string;
  rule: string;
}
const findings: Finding[] = [];
const scanned = new Map<string, number>();

function files(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) {
      out.push(...files(full));
    } else if (name.endsWith('.ts')) {
      out.push(full);
    }
  }
  return out;
}

function lineRule(rule: string, paths: string[], pattern: RegExp, skipComments = true): void {
  scanned.set(rule, (scanned.get(rule) ?? 0) + paths.length);
  for (const path of paths) {
    const lines = readFileSync(path, 'utf8').split('\n');
    lines.forEach((line, index) => {
      const code = skipComments ? stripComment(line) : line;
      if (pattern.test(code)) {
        findings.push({ where: `${relative(root, path)}:${index + 1}`, rule });
      }
    });
  }
}

/** Drop a `//` comment and a line that is part of a block comment. */
function stripComment(line: string): string {
  const trimmed = line.trimStart();
  if (trimmed.startsWith('*') || trimmed.startsWith('/*') || trimmed.startsWith('//')) {
    return '';
  }
  const at = line.indexOf(' // ');
  return at === -1 ? line : line.slice(0, at);
}

const src = files(join(root, 'src'));
const adapters = src.filter((path) => path.includes('/adapters/'));
const everything = [...src, ...files(join(root, 'test')), ...files(join(root, 'demo')), ...files(join(root, 'e2e'))];

// "no `any`" — in the shipped source.
lineRule('no-explicit-any', src, /(:\s*any\b|<any>|\bas any\b|\bany\[\])/u);
// "no suppressed error" — anywhere, tests included. A directive is a comment
// that starts with it; prose that merely names one is not a directive.
lineRule('no-ts-suppression', everything, /^\s*(\/\/|\/\*+)\s*@ts-(ignore|expect-error|nocheck)\b/u, false);
// "by type only": a value import of a framework would load it at run time.
const frameworkValueImport = new RegExp(
  `^\\s*import\\s+(?!type\\b)[^;]*from\\s+'(${FRAMEWORKS.map((name) => name.replace('/', '\\/')).join('|')})(\\/[^']*)?'`,
  'u',
);
lineRule('framework-import-type-only', src, frameworkValueImport);
lineRule('no-dynamic-framework-import', src, new RegExp(`import\\(\\s*'(${FRAMEWORKS.join('|')})`, 'u'));
// "no assertion onto an upstream type".
lineRule(
  'no-upstream-type-assertion',
  adapters,
  /\bas\s+(Adapter|WorkspaceFilesystem|IFileSystem|FilesV4|Tool|ToolSet|FlexibleSchema)\b/u,
);
// Diagnostics are payload-free and belong to the caller: no console in src.
lineRule('no-console-in-src', src, /\bconsole\.(log|error|warn|info|debug)\b/u);

// Package manifest: zero runtime dependencies, exact pins, committed lockfile.
const manifest = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')) as {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
};
scanned.set('package-manifest', 1);
if (Object.keys(manifest.dependencies ?? {}).length !== 0) {
  findings.push({ where: 'package.json', rule: 'zero-runtime-dependencies' });
}
const exact = /^\d+\.\d+\.\d+$/u;
for (const block of ['devDependencies', 'peerDependencies'] as const) {
  for (const [name, version] of Object.entries(manifest[block] ?? {})) {
    if (!exact.test(version)) {
      findings.push({ where: `package.json ${block}.${name}`, rule: 'exact-version-pin' });
    }
  }
}
for (const [name, version] of Object.entries(manifest.peerDependencies ?? {})) {
  if (manifest.devDependencies?.[name] !== version) {
    findings.push({ where: `package.json peerDependencies.${name}`, rule: 'peer-equals-dev-pin' });
  }
}
const lock = JSON.parse(readFileSync(join(root, 'package-lock.json'), 'utf8')) as {
  lockfileVersion: number;
  packages: Record<string, { version?: string; devDependencies?: Record<string, string> }>;
};
for (const [name, version] of Object.entries(manifest.devDependencies ?? {})) {
  if (lock.packages['']?.devDependencies?.[name] !== version) {
    findings.push({ where: `package-lock.json root devDependencies.${name}`, rule: 'lockfile-matches-manifest' });
  }
  if (lock.packages[`node_modules/${name}`]?.version !== version) {
    findings.push({ where: `package-lock.json node_modules/${name}`, rule: 'lockfile-resolves-exact-pin' });
  }
}

for (const [rule, count] of scanned) {
  if (count === 0) {
    findings.push({ where: '(nothing scanned)', rule });
  }
}

if (findings.length > 0) {
  for (const finding of findings) {
    console.error(`${finding.where} ${finding.rule}`);
  }
  console.error(`lint: ${findings.length} finding(s)`);
  process.exit(1);
}
console.log(
  `lint: clean — ${[...scanned].map(([rule, count]) => `${rule}(${count})`).join(', ')}`,
);
