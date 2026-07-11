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
//   OP_VERIFY_CACHE_DIR          cache dir (DID docs, status lists)
//   OP_VERIFY_AUDIT_LOG          decisions JSONL path
//   PORT                         default 8091
//   HOST                         default 127.0.0.1

import { createServer, type Server } from 'node:http';
import { timingSafeEqual } from 'node:crypto';
import { runVerification, type VerifyRequest } from './verify-core.js';
import { createResponseSigner, type ResponseSigner } from './signer.js';

const env = (k: string): string => {
  const v = process.env[k];
  if (!v) throw new Error(`missing required env ${k} — refusing to start`);
  return v;
};

const MAX_BODY = 256 * 1024; // a mandate is a few KB; anything huge is abuse
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
    auditLog: env('OP_VERIFY_AUDIT_LOG'),
    ...(process.env.OP_VERIFY_OFFLINE_DIDDOC ? { offlineDidDocumentPath: process.env.OP_VERIFY_OFFLINE_DIDDOC } : {}),
  };
  const tokens = env('OP_VERIFY_BEARER_TOKENS').split(',').map((s) => s.trim()).filter(Boolean);
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
          }));
        }
      })();
    });
  });

  const port = Number(process.env.PORT ?? 8091);
  const host = process.env.HOST ?? '127.0.0.1';
  await new Promise<void>((resolve) => server.listen(port, host, resolve));
  console.log(`op-verify-service on ${host}:${port} signing as ${signer.verificationMethod}`);
  return server;
}

const isMain = process.argv[1]?.endsWith('server.js') || process.argv[1]?.endsWith('server.cjs');
if (isMain) {
  main().catch((err) => {
    console.error(`refusing to start: ${(err as Error).message}`);
    process.exit(1);
  });
}
