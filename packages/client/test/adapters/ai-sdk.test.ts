/**
 * The AI SDK `FilesV4` adapter: managed references over an explicitly
 * configured upload directory, and the one field an ambiguous mutation must not
 * be flattened into.
 */

import { strict as assert } from 'node:assert';
import { after, describe, it } from 'node:test';

import {
  createFilesApi,
  decodeBase64Strict,
  MAX_REFERENCES,
  PROVIDER_KEY,
  type TunnelFilesApi,
} from '../../src/adapters/ai-sdk.ts';
import { FilesystemError } from '../../src/errors.ts';
import { descriptorFixture } from '../harness/descriptor.ts';
import { closeAll, waitFor, wire, type Wired } from './wiring.ts';
import type { FakeProvider } from '../harness/provider.ts';

after(closeAll);

async function api(
  seed: Record<string, string | Uint8Array> = {},
  overrides = {},
  configure?: (provider: FakeProvider) => void,
  maxReferences?: number,
): Promise<{ files: TunnelFilesApi; wired: Wired }> {
  const wired = await wire({ 'uploads/.keep': '', ...seed }, overrides, configure ?? (() => {}));
  return {
    files: createFilesApi({
      remote: wired.remote,
      uploadDirectory: '/uploads',
      ...(maxReferences === undefined ? {} : { maxReferences }),
    }),
    wired,
  };
}

const raised = async (run: () => Promise<unknown>): Promise<unknown> => {
  try {
    await run();
  } catch (error) {
    return error;
  }
  throw new Error('expected a rejection');
};

const bytes = (text: string): Uint8Array => new TextEncoder().encode(text);

describe('it is a FilesV4, and it is not a directory API', () => {
  it('declares the version and provider the interface requires', async () => {
    const { files } = await api();
    assert.equal(files.specificationVersion, 'v4');
    assert.equal(files.provider, 'agent-tunnel.files');
    // Every optional method is present, which is how a FilesV4 signals support.
    assert.equal(typeof files.getFileMetadata, 'function');
    assert.equal(typeof files.downloadFile, 'function');
    assert.equal(typeof files.deleteFile, 'function');
  });

  it('refuses to exist over a read-only export rather than advertising a useless upload', async () => {
    const wired = await wire(
      {},
      { root: { ...descriptorFixture().root, readOnly: true } },
    );
    assert.throws(
      () => createFilesApi({ remote: wired.remote, uploadDirectory: '/uploads' }),
      (error: FilesystemError) => error.code === 'EROFS',
    );
  });

  it('requires an upload directory that this namespace accepts', async () => {
    const wired = await wire();
    assert.throws(() => createFilesApi({ remote: wired.remote, uploadDirectory: '../escape' }));
  });
});

describe('uploads', () => {
  it('accepts bytes and mints a reference only after the write completed', async () => {
    const { files, wired } = await api();
    const result = await files.uploadFile({
      data: { type: 'data', data: bytes('payload') },
      mediaType: 'text/plain',
      filename: 'notes.txt',
    });
    const id = result.providerReference[PROVIDER_KEY];
    assert.ok(typeof id === 'string' && id.length === 32, 'an unpredictable id');
    assert.equal(result.byteSize, 7);
    assert.equal(result.mediaType, 'text/plain');
    assert.equal(result.filename, 'notes.txt');
    // The file is an ordinary file in the configured directory, and `filename`
    // did not choose its name: it is bounded display metadata.
    assert.equal(wired.provider.has(`/uploads/${id}`), true);
    assert.equal(wired.provider.has('/uploads/notes.txt'), false);
    assert.equal(files.incompleteUploads().length, 0);
    // The one warning every call carries, so a caller is told what a reference
    // is before it assumes object identity.
    assert.ok(result.warnings.some((warning) => warning.type === 'compatibility'));
  });

  it('accepts text and strictly decoded base64, and refuses base64 that is not', async () => {
    const { files, wired } = await api();
    const text = await files.uploadFile({ data: { type: 'text', text: 'hello' }, mediaType: 'text/plain' });
    assert.equal(
      new TextDecoder().decode(wired.provider.read(`/uploads/${text.providerReference[PROVIDER_KEY] as string}`)),
      'hello',
    );
    const encoded = await files.uploadFile({
      data: { type: 'data', data: Buffer.from('hello').toString('base64') },
      mediaType: 'application/octet-stream',
    });
    assert.equal(encoded.byteSize, 5);

    // `Buffer.from(text, 'base64')` silently ignores characters outside the
    // alphabet and accepts truncated input, so a corrupted string would become
    // a shorter file rather than an error.
    for (const bad of ['aGVsbG8', 'aGV$bG8=', 'aGVsbG8==']) {
      assert.throws(() => decodeBase64Strict(bad), (error: FilesystemError) => error.code === 'EINVAL');
    }
    assert.deepEqual(decodeBase64Strict('aGVsbG8='), bytes('hello'));
  });

  it('accepts a stream, bounded by the client rather than buffered whole here', async () => {
    const { files, wired } = await api();
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(bytes('one'));
        controller.enqueue(bytes('two'));
        controller.close();
      },
    });
    const result = await files.uploadFile({ data: { type: 'stream', stream }, mediaType: 'text/plain' });
    assert.equal(result.byteSize, 6);
    assert.equal(
      new TextDecoder().decode(wired.provider.read(`/uploads/${result.providerReference[PROVIDER_KEY] as string}`)),
      'onetwo',
    );
  });

  it('bounds display metadata rather than taking any string', async () => {
    const { files } = await api();
    const error = await raised(async () =>
      files.uploadFile({
        data: { type: 'text', text: 'x' },
        mediaType: 'text/plain',
        filename: 'x'.repeat(500),
      }),
    );
    assert.ok(error instanceof FilesystemError);
    assert.equal(error.code, 'EINVAL');
  });

  it('rejects at the reference bound before creating a file, and evicts nothing', async () => {
    const { files, wired } = await api({}, {}, undefined, 2);
    await files.uploadFile({ data: { type: 'text', text: 'a' }, mediaType: 'text/plain' });
    const second = await files.uploadFile({ data: { type: 'text', text: 'b' }, mediaType: 'text/plain' });
    const before = wired.connection.received.filter((message) => message.kind === 'Tlcreate').length;

    const error = await raised(async () =>
      files.uploadFile({ data: { type: 'text', text: 'c' }, mediaType: 'text/plain' }),
    );
    assert.ok(error instanceof FilesystemError);
    assert.equal(error.code, 'RESOURCE_EXHAUSTED');
    // Nothing was created and nothing older was deleted to make room.
    assert.equal(
      wired.connection.received.filter((message) => message.kind === 'Tlcreate').length,
      before,
    );
    assert.equal(wired.provider.has(`/uploads/${second.providerReference[PROVIDER_KEY] as string}`), true);
  });

  it('bounds at the documented 256 by default', () => {
    assert.equal(MAX_REFERENCES, 256);
  });
});

describe('references are this adapter’s and nobody else’s', () => {
  it('reads metadata and bytes back through its own reference', async () => {
    const { files } = await api();
    const uploaded = await files.uploadFile({
      data: { type: 'text', text: 'hello' },
      mediaType: 'text/plain',
      filename: 'notes.txt',
    });
    const metadata = await files.getFileMetadata?.({ file: uploaded.providerReference });
    assert.ok(metadata !== undefined);
    assert.equal(metadata.byteSize, 5);
    assert.equal(metadata.filename, 'notes.txt');
    // Advisory, and labelled as such: the values came from the upload and are
    // not stored on the file.
    assert.ok(
      metadata.warnings.some(
        (warning) => warning.type === 'compatibility' && warning.feature === 'display-metadata',
      ),
    );

    const download = await files.downloadFile?.({ file: uploaded.providerReference });
    assert.ok(download !== undefined);
    const chunks: Uint8Array[] = [];
    const reader = download.content.getReader();
    for (;;) {
      const next = await reader.read();
      if (next.done === true) {
        break;
      }
      chunks.push(next.value);
    }
    assert.equal(new TextDecoder().decode(Buffer.concat(chunks)), 'hello');
  });

  it('refuses a foreign provider key and an unknown id', async () => {
    const { files } = await api();
    const foreign = await raised(async () =>
      files.getFileMetadata?.({ file: { openai: 'file-abc123' } }),
    );
    assert.ok(foreign instanceof FilesystemError);
    assert.equal(foreign.code, 'EINVAL');

    const unknown = await raised(async () =>
      files.getFileMetadata?.({ file: { [PROVIDER_KEY]: 'not-one-of-ours' } }),
    );
    assert.ok(unknown instanceof FilesystemError);
    assert.equal(unknown.code, 'ENOENT');
  });

  it('refuses a nonempty per-call header override', async () => {
    const { files } = await api();
    const uploaded = await files.uploadFile({ data: { type: 'text', text: 'x' }, mediaType: 'text/plain' });
    const error = await raised(async () =>
      files.downloadFile?.({ file: uploaded.providerReference, headers: { authorization: 'Bearer x' } }),
    );
    assert.ok(error instanceof FilesystemError);
    assert.equal(error.code, 'ENOTSUP');
  });

  it('closing expires the references and deletes none of the files', async () => {
    const { files, wired } = await api();
    const uploaded = await files.uploadFile({ data: { type: 'text', text: 'x' }, mediaType: 'text/plain' });
    const id = uploaded.providerReference[PROVIDER_KEY] as string;
    files.close();
    const error = await raised(async () => files.getFileMetadata?.({ file: uploaded.providerReference }));
    assert.ok(error instanceof FilesystemError);
    assert.equal(error.code, 'ENOENT');
    // "Closing an adapter does not silently delete them." They are ordinary
    // files in the configured directory and the application owns their cleanup.
    assert.equal(wired.provider.has(`/uploads/${id}`), true);
  });

  it('a reference is an alias for a path, so a replacement is what it resolves to', async () => {
    const { files, wired } = await api();
    const uploaded = await files.uploadFile({ data: { type: 'text', text: 'first' }, mediaType: 'text/plain' });
    const id = uploaded.providerReference[PROVIDER_KEY] as string;
    // Another authorized writer replaces the path through the ordinary VFS.
    await wired.remote.writeFile(`/uploads/${id}`, bytes('second-and-longer'));
    const metadata = await files.getFileMetadata?.({ file: uploaded.providerReference });
    // The current occupant, not the uploaded object: there is no immutable
    // identity here and none is implied.
    assert.equal(metadata?.byteSize, 17);
    // The upload's display metadata is now stale, and is still returned — which
    // is why it is labelled advisory.
    assert.equal(metadata?.mediaType, 'text/plain');
  });

  it('deletes the current occupant and forgets the reference', async () => {
    const { files, wired } = await api();
    const uploaded = await files.uploadFile({ data: { type: 'text', text: 'x' }, mediaType: 'text/plain' });
    const id = uploaded.providerReference[PROVIDER_KEY] as string;
    const result = await files.deleteFile?.({ file: uploaded.providerReference });
    assert.equal(result?.deleted, true);
    assert.equal(wired.provider.has(`/uploads/${id}`), false);
    const after = await raised(async () => files.deleteFile?.({ file: uploaded.providerReference }));
    assert.ok(after instanceof FilesystemError);
    assert.equal(after.code, 'ENOENT');
  });
});

describe('outcomes, and what FilesV4 has no field for', () => {
  it('an unknown upload mints no reference and stays listed for cleanup', async () => {
    const { files, wired } = await api({}, {}, (provider) => {
      provider.swallow.add('Twrite');
    });
    const pending = files.uploadFile({ data: { type: 'text', text: 'abc' }, mediaType: 'text/plain' });
    await waitFor(() => wired.connection.received.some((message) => message.kind === 'Twrite'));
    wired.connection.close(1011, 'synthetic');
    const error = await raised(async () => pending);

    // `uploadFile` has no failure shape of its own, so the client's error is
    // what a caller gets — and `outcome` survives on it because nothing here
    // replaced it with something the interface would prefer.
    assert.ok(error instanceof FilesystemError);
    assert.equal(error.outcome, 'unknown');
    assert.equal(error.retryable, false);

    // "A reference is returned only after confirmed completion", and the path
    // it was writing is the application's to clean up: "failure is not success
    // just because a file exists".
    assert.equal(files.incompleteUploads().length, 1);
    assert.match(files.incompleteUploads()[0] as string, /^\/uploads\/[0-9a-f]{32}$/u);
  });

  it('a failure that provably did nothing leaves no path to clean up', async () => {
    const { files } = await api();
    await raised(async () =>
      files.uploadFile({
        data: { type: 'data', data: 'not base64!' },
        mediaType: 'application/octet-stream',
      }),
    );
    assert.deepEqual(files.incompleteUploads(), []);
  });

  it('an ambiguous delete throws rather than answering deleted:false', async () => {
    const { files, wired } = await api();
    const uploaded = await files.uploadFile({ data: { type: 'text', text: 'x' }, mediaType: 'text/plain' });
    wired.provider.swallow.add('Tunlinkat');
    const pending = files.deleteFile?.({ file: uploaded.providerReference });
    await waitFor(() => wired.connection.received.some((message) => message.kind === 'Tunlinkat'));
    wired.connection.close(1011, 'synthetic');
    const error = await raised(async () => pending);

    assert.ok(error instanceof FilesystemError);
    assert.equal(error.outcome, 'unknown');
    // `FilesV4DeleteFileResult.deleted` is the one place this could have been
    // flattened into a claim: `false` says the provider did not delete it, and
    // after an `unknown` nobody knows that. `true` would be worse. There is no
    // third value, so the only honest answer is to throw.
  });
});
