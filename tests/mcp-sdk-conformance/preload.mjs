// A Node `--import` preload for scripts/m3-sdk-conformance.sh (task row M3-17).
//
// * AGENTUPLINK_LOOPBACK_ONLY=1 binds a listener that names only a port to
//   127.0.0.1.  The conformance suite's reference server calls
//   `app.listen(PORT)`, which would otherwise listen on every interface.
// * AGENTUPLINK_RELAY_ORIGIN plus AGENTUPLINK_TOKEN add
//   `Authorization: Bearer <token>` to every global `fetch` aimed at that
//   origin.  The conformance suite (0.2.0-alpha.11) has no option to send a
//   credential, and the relay's consumer listener requires one.  Requests to
//   any other origin, and requests that already carry Authorization, are
//   left untouched.  The token is never printed.
import net from 'node:net';

if (process.env.AGENTUPLINK_LOOPBACK_ONLY === '1') {
  const listen = net.Server.prototype.listen;
  net.Server.prototype.listen = function patchedListen(...args) {
    const [first, second] = args;
    const portOnly = typeof first === 'number' || (typeof first === 'string' && /^\d+$/.test(first));
    if (portOnly && typeof second !== 'string') {
      args.splice(1, 0, '127.0.0.1');
    }
    return listen.apply(this, args);
  };
}

const origin = process.env.AGENTUPLINK_RELAY_ORIGIN;
const token = process.env.AGENTUPLINK_TOKEN;
if (origin && token) {
  const inner = globalThis.fetch;
  globalThis.fetch = function fetchWithBearer(input, init) {
    const url = new URL(input instanceof Request ? input.url : String(input));
    if (url.origin !== origin) return inner(input, init);
    const headers = new Headers(input instanceof Request ? input.headers : undefined);
    new Headers(init?.headers).forEach((value, name) => headers.set(name, value));
    if (!headers.has('authorization')) headers.set('authorization', `Bearer ${token}`);
    return inner(input, { ...init, headers });
  };
}
