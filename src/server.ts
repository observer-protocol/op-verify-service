// The hosted surface: POST /v1/verify, bearer-authenticated, rate-limited,
// fail-closed. One network call in, one signed JSON response out. Binds
// localhost by default — public exposure is the tunnel's job.
//
// Env (all required unless noted):
//   OP_VERIFY_SIGNING_KEY_PATH   PKCS8 PEM, Ed25519 (e.g. /etc/observer-protocol/keys/key-3.pem)
//   OP_VERIFY_SIGNING_VM         e.g. did:web:observerprotocol.org#key-3
//   OP_VERIFY_ISSUER_ALLOWLIST   comma-separated issuer DIDs accepted for mandates
//   OP_VERIFY_SCHEMA_ALLOWLIST   comma-separated credentialSchema ids (frozen URLs)
//   OP_VERIFY_BEARER_TOKENS      comma-separated partner tokens (issued manually)
//   OP_VERIFY_CACHE_DIR          cache dir (DID docs, status lists) — public material only
//   PORT                         default 8091
//   HOST                         default 127.0.0.1

import { createServer, type Server } from 'node:http';
import { timingSafeEqual } from 'node:crypto';
import { createRequire } from 'node:module';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { runVerification, type VerifyRequest } from './verify-core.js';
import { createResponseSigner, type ResponseSigner } from './signer.js';

/**
 * The engine floor this service may serve authenticated traffic on.
 *
 * THE INTERLOCK. "No bearer token is minted until the pin moves" was a note,
 * and a note is not a control. This makes it mechanical: with tokens present
 * and the bundled engine below this floor, the service refuses to start.
 *
 * Below 0.3.0 the engine lacks fixes this service's verdicts depend on. A
 * deployment that mints a partner token against an older engine would answer
 * real callers using it, and nothing else in the pipeline would notice.
 */
const MIN_ENGINE_VERSION = '0.3.0';

/** Numeric semver compare, majors/minors/patches only. -1 | 0 | 1. */
function cmpVersion(a: string, b: string): number {
  const pa = a.split('.').map((n) => parseInt(n, 10) || 0);
  const pb = b.split('.').map((n) => parseInt(n, 10) || 0);
  for (let i = 0; i < 3; i++) {
    if ((pa[i] ?? 0) !== (pb[i] ?? 0)) return (pa[i] ?? 0) > (pb[i] ?? 0) ? 1 : -1;
  }
  return 0;
}

/**
 * Installed version of the bundled engine, or null if it cannot be determined.
 *
 * Read off disk rather than imported: the engine's exports map does not expose
 * package.json, and this file builds to both ESM and CJS so import.meta is not
 * portable here. Resolution is anchored on cwd, which systemd sets via
 * WorkingDirectory.
 */
function installedEngineVersion(): string | null {
  try {
    const req = createRequire(join(process.cwd(), 'noop.js'));
    let dir = dirname(req.resolve('@observer-protocol/policy-engine'));
    for (let i = 0; i < 8; i++) {
      const p = join(dir, 'package.json');
      if (existsSync(p)) {
        const pkg = JSON.parse(readFileSync(p, 'utf8')) as { name?: string; version?: string };
        if (pkg.name === '@observer-protocol/policy-engine') return pkg.version ?? null;
      }
      const up = dirname(dir);
      if (up === dir) break;
      dir = up;
    }
  } catch {
    // fall through to null: unresolvable is indistinguishable from wrong
  }
  return null;
}

/**
 * Refuse to serve authenticated traffic on an engine below the floor.
 *
 * No tokens configured is fine at any engine version: the service answers 401
 * to everyone, which is the correct fail-closed state. The gate only bites when
 * a token exists, because that is the moment a real caller can get a verdict.
 *
 * An UNDETERMINABLE version is treated as below the floor. Unknown is a failure
 * state, not a pass — serving on an engine we cannot identify is the thing this
 * interlock exists to prevent.
 */
function assertEngineFloor(tokenCount: number): void {
  if (tokenCount === 0) return;
  const found = installedEngineVersion();
  if (found === null) {
    throw new Error(
      `${tokenCount} bearer token(s) configured but the bundled ` +
      `@observer-protocol/policy-engine version could not be determined. ` +
      `Refusing to serve authenticated traffic on an unidentified engine. ` +
      `Run from the service's install directory, or clear OP_VERIFY_BEARER_TOKENS.`,
    );
  }
  if (cmpVersion(found, MIN_ENGINE_VERSION) < 0) {
    throw new Error(
      `${tokenCount} bearer token(s) configured but @observer-protocol/policy-engine ` +
      `is ${found}, below the ${MIN_ENGINE_VERSION} floor this service requires. ` +
      `Move the pin first, then mint the token — not the other way round. ` +
      `Clearing OP_VERIFY_BEARER_TOKENS returns the service to its fail-closed 401 state.`,
    );
  }
}

const env = (k: string): string => {
  const v = process.env[k];
  if (!v) throw new Error(`missing required env ${k} — refusing to start`);
  return v;
};

const MAX_BODY = 256 * 1024; // a mandate is a few KB; anything huge is abuse
const MAX_CONTEXT = 4 * 1024; // opaque correlation echo: a trace id, not a payload
const RATE_WINDOW_MS = 60_000;
const RATE_MAX = 120; // per token per minute

function tokenOk(header: string | undefined, tokens: string[]): boolean {
  if (!header?.startsWith('Bearer ')) return false;
  const presented = Buffer.from(header.slice(7));
  return tokens.some((t) => {
    const expected = Buffer.from(t);
    return expected.length === presented.length && timingSafeEqual(expected, presented);
  });
}

export async function main(): Promise<Server> {
  const signer: ResponseSigner = await createResponseSigner({
    keyPath: env('OP_VERIFY_SIGNING_KEY_PATH'),
    verificationMethod: env('OP_VERIFY_SIGNING_VM'),
    cacheDir: env('OP_VERIFY_CACHE_DIR'),
    ...(process.env.OP_VERIFY_OFFLINE_DIDDOC ? { offlineDidDocumentPath: process.env.OP_VERIFY_OFFLINE_DIDDOC } : {}),
  });
  const coreCfg = {
    issuerAllowlist: env('OP_VERIFY_ISSUER_ALLOWLIST').split(',').map((s) => s.trim()).filter(Boolean),
    schemaAllowlist: env('OP_VERIFY_SCHEMA_ALLOWLIST').split(',').map((s) => s.trim()).filter(Boolean),
    cacheDir: env('OP_VERIFY_CACHE_DIR'),
    ...(process.env.OP_VERIFY_OFFLINE_DIDDOC ? { offlineDidDocumentPath: process.env.OP_VERIFY_OFFLINE_DIDDOC } : {}),
  };
  // Deliberately optional and allowed-empty: a deployment with no partner
  // tokens yet answers 401 to everyone, which is the correct fail-closed
  // state until a token is minted. Never a boot failure.
  //
  // MINT SITE. Setting OP_VERIFY_BEARER_TOKENS is what turns this service from
  // "denies everyone" into "answers a real partner". Its precondition is the
  // engine pin: see MIN_ENGINE_VERSION above. assertEngineFloor enforces that
  // mechanically on the next line, so a token added here against an old engine
  // stops the service rather than serving verdicts from it.
  const tokens = (process.env.OP_VERIFY_BEARER_TOKENS ?? '').split(',').map((s) => s.trim()).filter(Boolean);
  assertEngineFloor(tokens.length);
  const rate = new Map<string, { count: number; windowStart: number }>();

  const server = createServer((req, res) => {
    const reply = (code: number, body: unknown): void => {
      res.writeHead(code, { 'content-type': 'application/json' });
      res.end(JSON.stringify(body));
    };
    if (req.method === 'GET' && req.url === '/health') return void reply(200, { status: 'ok', signingVm: signer.verificationMethod });
    if (req.method !== 'POST' || req.url !== '/v1/verify') return void reply(404, { error: 'POST /v1/verify' });

    const auth = req.headers.authorization;
    if (!tokenOk(auth, tokens)) return void reply(401, { error: 'missing or invalid bearer token' });
    const bucketKey = (auth as string).slice(7, 27);
    const now = Date.now();
    const bucket = rate.get(bucketKey);
    if (!bucket || now - bucket.windowStart > RATE_WINDOW_MS) rate.set(bucketKey, { count: 1, windowStart: now });
    else if (++bucket.count > RATE_MAX) return void reply(429, { error: 'rate limit exceeded' });

    let size = 0;
    let data = '';
    req.on('data', (c: Buffer) => {
      size += c.length;
      if (size > MAX_BODY) {
        reply(413, { error: 'body too large' });
        req.destroy();
        return;
      }
      data += c;
    });
    req.on('end', () => {
      void (async () => {
        let body: VerifyRequest;
        try {
          body = JSON.parse(data) as VerifyRequest;
        } catch {
          return reply(400, { error: 'body is not JSON' });
        }
        if (typeof body?.agentDid !== 'string' || typeof body?.mandate !== 'object' || body.mandate === null) {
          return reply(400, { error: 'body must carry agentDid (string) and mandate (object)' });
        }
        // Optional opaque correlation context: a plain JSON object, size-capped.
        // Echoed verbatim into the signed response; never interpreted.
        if (body.context !== undefined) {
          if (typeof body.context !== 'object' || body.context === null || Array.isArray(body.context)) {
            return reply(400, { error: 'context, if present, must be a JSON object' });
          }
          if (JSON.stringify(body.context).length > MAX_CONTEXT) {
            return reply(400, { error: `context must serialize to <= ${MAX_CONTEXT} bytes` });
          }
        }
        try {
          const outcome = await runVerification(coreCfg, body);
          return reply(200, signer.sign(outcome as unknown as Record<string, unknown>));
        } catch (err) {
          // Fail-closed shape even on internal error: everything invalid, named.
          return reply(200, signer.sign({
            agentDid: body.agentDid,
            identity: { valid: false, reason: `internal error, failing closed: ${(err as Error).message}` },
            mandate: { valid: false, reason: 'not evaluated (internal error, fail closed)' },
            verifiedAt: new Date().toISOString(),
            ...(body.context !== undefined ? { context: body.context } : {}),
          }));
        }
      })();
    });
  });

  const port = Number(process.env.PORT ?? 8091);
  const host = process.env.HOST ?? '127.0.0.1';
  await new Promise<void>((resolve) => server.listen(port, host, resolve));
  console.log(`op-verify-service on ${host}:${port} signing as ${signer.verificationMethod}`);
  if (tokens.length === 0) {
    // Loud on purpose: a deployment with no tokens is healthy and fail-closed,
    // but it denies every real caller. Without this line a lost/absent env file
    // looks like a partner-side 401 while /health stays green. Announce it here.
    console.warn(
      'WARNING: no bearer tokens configured (OP_VERIFY_BEARER_TOKENS empty) — ' +
      'ALL /v1/verify requests will 401. This is fail-closed, not an outage; ' +
      '/health stays green. If a partner is provisioned, the env file is missing.',
    );
  }
  return server;
}

const isMain = process.argv[1]?.endsWith('server.js') || process.argv[1]?.endsWith('server.cjs');
if (isMain) {
  main().catch((err) => {
    console.error(`refusing to start: ${(err as Error).message}`);
    process.exit(1);
  });
}
