// The hosted surface: POST /v1/verify, OPEN (no authentication), rate-limited,
// fail-closed. One network call in, one signed JSON response out. Binds
// localhost by default — public exposure is the tunnel's job.
//
// It read "bearer-authenticated" until 2026-08-09, six days after the bearer gate was removed.
//
// Env (all required unless noted):
//   OP_VERIFY_SIGNING_KEY_PATH   PKCS8 PEM, Ed25519 (e.g. /etc/observer-protocol/keys/key-3.pem)
//   OP_VERIFY_SIGNING_VM         e.g. did:web:observerprotocol.org#key-3
//   OP_VERIFY_ISSUER_ALLOWLIST   comma-separated issuer DIDs accepted for mandates
//   OP_VERIFY_SCHEMA_ALLOWLIST   comma-separated credentialSchema ids (frozen URLs)
//   OP_VERIFY_BEARER_TOKENS      UNREAD. Nothing authenticates with it; parsed only to warn at
//                                boot that a value left here gates nothing.
//   OP_VERIFY_CACHE_DIR          cache dir (DID docs, status lists) — public material only
//   PORT                         default 8091
//   HOST                         default 127.0.0.1

import { createServer, type Server } from 'node:http';
import { createRequire } from 'node:module';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { runVerification, type VerifyRequest } from './verify-core.js';
import { assessReadiness } from './readiness.js';
import { createResponseSigner, type ResponseSigner } from './signer.js';
// Namespace import so a missing export is `undefined` rather than a load error:
// this file must keep working against an engine that predates compareCoreVersion.
import * as engineExports from '@observer-protocol/policy-engine';

/**
 * The engine floor this service may serve on. (It read "serve AUTHENTICATED traffic on" until
 * 2026-08-09; there is no authenticated traffic, there is only traffic.)
 *
 * THE INTERLOCK. "No bearer token is minted until the pin moves" was a note, and a note is not a
 * control. This makes it mechanical: below this floor, the service refuses to start. The original
 * form was conditional on a token existing, which would have disarmed it permanently once the
 * endpoint opened — see assertEngineFloor.
 *
 * THE FLOOR IS NOT THE PIN. The dependency is pinned at ^1.0.0-rc.10 (npm
 * `latest`); this gate is set at 0.3.0, the BEHAVIOUR boundary.
 * 0.3.0 is where both relevant changes landed: e64b8ef "read + enforce
 * delegation.scope.spending_limits.per_rail" and 7337f61 "fail closed on
 * unrecognized mandate shape", both 2026-07-15, both recorded under 0.3.0 in
 * the engine CHANGELOG. Everything from 0.3.1 to 0.3.3 is cross-rail LEDGER
 * work, and this service is stateless and holds no counters, so that path never
 * executes here.
 *
 * Keeping them distinct is deliberate: a future patch-level rollback within
 * 0.3.x must not trip a gate it has no business tripping. A floor set to the
 * pin would do exactly that.
 *
 * ─── DO NOT RAISE THIS TO A 1.0.0-rc.x VALUE. IT WOULD DISARM THE GATE. ────────────────────
 *
 * The pin moved 0.3.3 -> 1.0.0-rc.10 on 2026-08-09, and the obvious next move is to raise this
 * floor to match. It must not be raised to any prerelease value, because cmpVersion prefers the
 * engine's own compareCoreVersion and that function cannot compare prerelease identifiers.
 * Measured against 1.0.0-rc.10 on 2026-08-09:
 *
 *     compareCoreVersion('1.0.0-rc.10', '0.3.0')       =  1    <- the only one that discriminates
 *     compareCoreVersion('1.0.0-rc.2',  '1.0.0-rc.10') =  0
 *     compareCoreVersion('1.0.0-rc.10', '1.0.0')       =  0
 *
 * With the floor at a 1.0.0-rc.x value every engine in the rc line compares EQUAL to it, and
 * `cmpVersion(found, MIN) < 0` is never true. The gate would run, return, and refuse nothing —
 * including an rc.2 that predates the outbound-fetch guard this upgrade exists to acquire.
 *
 * The floor stays at 0.3.0 because 0.3.0 is still the behaviour boundary it was set for, and
 * because it is a release value the comparator can actually order. If a behaviour boundary ever
 * lands inside the 1.0.0-rc line, the comparator must be fixed in the engine BEFORE this constant
 * moves — the local fallback below has the same defect, since it parses '0-rc' as 0.
 *
 * The test `engine floor: the comparator can order the configured floor` pins this: it fails if
 * MIN_ENGINE_VERSION is set to a value the comparator cannot discriminate.
 *
 * Do NOT reuse LEDGER_SAFE_FLOOR ('0.3.2'). It is a different floor for a
 * different property.
 *
 * The defect this contains: engine 0.2.0 does not read
 * credentialSubject.delegation.scope.spending_limits.per_rail, which is where
 * /sovereign/delegate, /sovereign/claim and the enterprise issue-delegation
 * modal put EVERY cap. Against a mandate capped at 100, 0.2.0 returns a SIGNED
 * inScope:true for a payment of 1,000,000. That was reachable by minting a bearer token when this
 * was written; since 2026-08-09 it is reachable by anyone, which is why the gate is unconditional.
 */
export const MIN_ENGINE_VERSION = '0.3.0';

/**
 * Compare two versions, preferring the engine's own exported comparator.
 *
 * compareCoreVersion ships in 0.3.3+. This gate must also run when the engine
 * is OLD — that is its entire purpose — and an old engine does not export it.
 * So the local fallback is not a hand-rolled duplicate of a shipped function,
 * it is the path taken precisely when the shipped function cannot exist.
 */
export function cmpVersion(a: string, b: string): number {
  const engineCmp = (engineExports as { compareCoreVersion?: (x: string, y: string) => number })
    ?.compareCoreVersion;
  if (typeof engineCmp === 'function') return engineCmp(a, b);
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
 * Refuse to serve on an engine below the floor.
 *
 * The paragraph that stood here described a token gate: "no tokens configured is fine at any engine
 * version: the service answers 401 to everyone... the gate only bites when a token exists." That was
 * true until 3 August 2026 and has been wrong since. There is no 401 and no token check; every
 * request is served, so the floor is checked unconditionally. The body below says so at the point it
 * happens.
 *
 * An UNDETERMINABLE version is treated as below the floor. Unknown is a failure
 * state, not a pass — serving on an engine we cannot identify is the thing this
 * interlock exists to prevent.
 */
function assertEngineFloor(): void {
  // ─── UNCONDITIONAL NOW, AND THAT IS FORCED BY OPENING THE ENDPOINT ──────────────────────────
  //
  // This read `if (tokenCount === 0) return;` and its own comment gave the reason: the gate "only
  // bites when a token exists, because that is the moment a real caller can get a verdict."
  //
  // VERIFICATION IS OPEN, SO EVERY MOMENT IS THAT MOMENT. Leaving the token condition in place would
  // have left the interlock permanently disarmed — tokenCount is now always 0 — and a service on an
  // engine below the floor would serve verdicts to the internet while the check that exists to stop
  // it returned early. A control that stops running because its input stopped arriving is the defect
  // this estate keeps finding, and this is the shape it would have taken here.
  const found = installedEngineVersion();
  if (found === null) {
    throw new Error(
      `The bundled @observer-protocol/policy-engine version could not be determined. Refusing to ` +
      `serve verification on an unidentified engine: a verdict is only worth what the evaluator ` +
      `behind it is, and an unknown version is a failure state rather than a pass. Run from the ` +
      `service's install directory.`,
    );
  }
  if (cmpVersion(found, MIN_ENGINE_VERSION) < 0) {
    throw new Error(
      `@observer-protocol/policy-engine is ${found}, below the ${MIN_ENGINE_VERSION} floor this ` +
      `service requires. Refusing to start. Move the pin first — the endpoint is open, so there is ` +
      `no token to withhold and no fail-closed state to fall back to.`,
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

// ─── ABUSE CONTROL, NOT ACCESS CONTROL ────────────────────────────────────────────────────────
//
// Verification is OPEN: POST /v1/verify takes an artifact as input, it does not retrieve one. There
// is no lookup by identifier and no query surface, so an open verifier with nothing to verify
// returns nothing — a caller can only check a credential they already hold. And a verifier that
// needs a token WE issue makes a skeptic's ability to check our work depend on our permission,
// which puts the vendor back in the trust path the product exists to remove.
//
// So these limits protect the BOX, not the data. Two of them, because they stop different things:
//
//   PER CALLER, 60/min — one client cannot monopolise the process. Verification is CPU-bound
//   (Ed25519 verify, JSON-schema validation, and a DID fetch on a cache miss), and 60/min is
//   generous for a human checking credentials or a CI job while being cheap to serve.
//
//   GLOBAL, 600/min — the per-caller limit does nothing against a distributed flood, and this is a
//   single Node process. The ceiling means no traffic pattern can take the box down; at worst it
//   makes verification slow for everyone, which is a better failure than making it absent.
//
// A 429 IS NOT A REFUSAL TO VERIFY. It says come back, not no.
const RATE_MAX = 60;          // per caller per minute
const RATE_MAX_GLOBAL = 600;  // whole service per minute

/** WHO IS CALLING, for rate limiting only. Never for authorisation — nothing here is authorised.
 *
 * ─── WHY THE SOCKET ADDRESS IS USELESS HERE ───────────────────────────────────────────────────
 *
 * This service binds 127.0.0.1 and is not reachable from the internet; the only path in is the
 * cloudflared tunnel. So `req.socket.remoteAddress` is 127.0.0.1 for EVERY caller, and keying on it
 * would make one shared bucket that the first busy client empties for everybody.
 *
 * ─── AND WHY THE HEADER IS TRUSTWORTHY, WHICH IT USUALLY IS NOT ───────────────────────────────
 *
 * `CF-Connecting-IP` is normally forgeable and normally must not be trusted. It is trustworthy HERE
 * for a specific, checkable reason: cloudflared sets it, and there is no direct route to port 8091
 * for anyone to set it themselves — verified, the listener is loopback-only and the port is closed
 * from outside. IF THAT EVER CHANGES — if this binds 0.0.0.0, or a second ingress appears — this
 * assumption is false and an attacker rotates the header to get an unlimited number of buckets.
 * The global ceiling is what bounds the damage in that case, which is half of why it exists.
 */
/** WHAT THIS DEPLOYMENT ACCEPTS, AND WHERE THAT CAME FROM.
 *
 * The list alone answers "what" and not "who decided". Both allowlists are ENVIRONMENT, set in a file
 * on the box that is in NO REPOSITORY — so nothing reproduces them, nothing reviews a change to them,
 * and until now `/health` printing the list was the only way to see what it was. The v2.2 entry was
 * added by hand with sudo on 2026-08-03 and that change exists nowhere but a shell history.
 *
 * NAMING THE SOURCE IS NOT FIXING IT. `inRepo: false` is a true statement about a gap, reported so a
 * reader knows the list they are looking at has no provenance behind it. See the README for what
 * moving it into a repo would take.
 */
function allowlistReport(cfg: { schemaAllowlist: string[]; issuerAllowlist: string[] }) {
  return {
    accepts: {
      schemas: cfg.schemaAllowlist,
      issuers: cfg.issuerAllowlist,
      source: {
        schemas: 'env:OP_VERIFY_SCHEMA_ALLOWLIST',
        issuers: 'env:OP_VERIFY_ISSUER_ALLOWLIST',
        inRepo: false,
        note:
          'Both lists are deployment environment, not code. They are set in an env file on the host ' +
          'that no repository contains, so a change to either leaves no reviewable record. This ' +
          'endpoint reports them so the question is answerable without shell access; it does not ' +
          'make them reproducible.',
      },
    },
  };
}

/** Whether a forwarded-client-IP header may be believed, decided by WHERE WE LISTEN.
 *
 * The comment above states the condition that makes `CF-Connecting-IP` trustworthy: cloudflared sets
 * it and "there is no direct route to port 8091 for anyone to set it themselves — verified, the
 * listener is loopback-only". It then names the exact event that falsifies it: "IF THAT EVER CHANGES
 * — if this binds 0.0.0.0, or a second ingress appears".
 *
 * That change has now happened. The self-hosted container binds 0.0.0.0 so a published port can
 * reach it, and a caller on that port can send any header it likes — including one naming a
 * different client on every request, which is an unlimited number of rate-limit buckets.
 *
 * So the invariant is enforced instead of asserted. Bound to loopback, the only writer that can
 * reach us is a local reverse proxy and the headers are believed. Bound anywhere else, they are
 * ignored and the bucket key is the socket address, which no caller can forge.
 *
 * Narrowing, not loosening: the hosted deployment leaves HOST unset, keeps its loopback bind, and
 * behaves exactly as before.
 */
const TRUST_FORWARDED_FOR: boolean = (() => {
  const h = process.env.HOST ?? '127.0.0.1';
  return h === '127.0.0.1' || h === 'localhost' || h === '::1';
})();

function callerKey(req: { headers: Record<string, string | string[] | undefined>; socket: { remoteAddress?: string | undefined } }): string {
  if (TRUST_FORWARDED_FOR) {
    const cf = req.headers['cf-connecting-ip'];
    if (typeof cf === 'string' && cf.length > 0) return `cf:${cf}`;
    const xff = req.headers['x-forwarded-for'];
    const first = (Array.isArray(xff) ? xff[0] : xff)?.split(',')[0]?.trim();
    if (first) return `xff:${first}`;
  }
  // DEGRADED, AND NAMED AS SUCH. Reaching here means neither header arrived, so every caller shares
  // one bucket. The prefix makes that visible to anyone reading the map rather than leaving a global
  // limit looking like a per-caller one.
  return `sock:${req.socket.remoteAddress ?? 'unknown'}`;
}

// ─── `tokenOk` WAS HERE, AND IT WAS DELETED FOR WHAT IT WAS PROPPING UP ───────────────────────
//
// It compared a Bearer header against OP_VERIFY_BEARER_TOKENS in constant time. It was correct, and
// it had been CALLED ZERO TIMES since verification was opened on 3 August 2026.
//
// DO NOT RESTORE IT AS DEAD-BUT-HARMLESS. It was not harmless. The README claimed "unauthenticated
// requests write nothing at all — the body is never read or parsed before the 401", which stopped
// being true when the 401 stopped existing. The verification any careful reader performs for that
// sentence is "is there a token check in this service?" — and this function answered yes. The claim
// was false and confirmed by exactly the check that should have caught it.
//
// A surviving artifact of removed behaviour does not merely fail to disprove a stale claim; it
// supplies evidence FOR it. If a token gate is ever wanted again, the endpoint's posture is the
// decision and this function is the last part of it, not the first.

let globalWindow: { count: number; windowStart: number } | undefined;

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
  // READ ONLY SO IT CAN BE WARNED ABOUT. Nothing authenticates with these.
  //
  // This described a MINT SITE: setting OP_VERIFY_BEARER_TOKENS was "what turns this service from
  // denies-everyone into answers-a-real-partner". That has been false since 3 August 2026. The value
  // is parsed for exactly one purpose — the startup warning below, which tells an operator that a
  // token still sitting in their env file gates nothing.
  const tokens = (process.env.OP_VERIFY_BEARER_TOKENS ?? '').split(',').map((s) => s.trim()).filter(Boolean);
  assertEngineFloor();
  const rate = new Map<string, { count: number; windowStart: number }>();

  const server = createServer((req, res) => {
    const reply = (code: number, body: unknown): void => {
      res.writeHead(code, { 'content-type': 'application/json' });
      res.end(JSON.stringify(body));
    };
    // /health REPORTS WHAT IT LOADED, not merely that it is up.
    //
    // The schema and issuer allowlists are deployment state: a code change does not touch them, a
    // stale deploy keeps them, and establishing the live value previously required ssh to the host.
    // On a ceremony day the question is "did the restart take effect", and that should be answerable
    // with a curl rather than by going to look.
    //
    // NEITHER LIST IS A SECRET. Both are frozen public URLs and public DIDs, and a caller learning
    // what this deployment accepts learns nothing it could not learn by presenting a credential and
    // reading the refusal, which already names the allowlist.
    if (req.method === 'GET' && req.url === '/health') {
      return void reply(200, {
        status: 'ok',
        // LIVENESS, STATED RATHER THAN IMPLIED. This endpoint answers "is the process up" and
        // deliberately opens no socket to anyone else, so a third party's outage never presents
        // as ours and this never suggests a restart that would fix nothing.
        liveness: {
          ok: true,
          means: 'this process is up and answering; no network reachability is implied or tested here',
        },
        // THE POINTER IS NOT A SECOND VERDICT. Readiness is computed in exactly one place and
        // served by exactly one endpoint. If this block restated it, /health and /ready could
        // disagree and a reader would have two answers to one question.
        readiness: {
          endpoint: '/ready',
          means: 'whether this deployment can currently resolve the issuer DIDs it is pinned to',
          warning:
            'A 200 here does NOT mean this deployment can verify anything. A cold cache behind a ' +
            'blocked proxy is live and refuses every credential. Check /ready before concluding ' +
            'that a refusal is a problem with your credential.',
        },
        signingVm: signer.verificationMethod,
        schemaAllowlist: coreCfg.schemaAllowlist,
        issuerAllowlist: coreCfg.issuerAllowlist,
        // THE SAME BLOCK AS /version, from the same function. Two endpoints computing this
        // separately is two answers to "what does this deployment accept".
        ...allowlistReport(coreCfg),
        build: { commit: __BUILD_COMMIT__, dirty: __BUILD_DIRTY__ },
      });
    }
    // READINESS: 200 only when every pinned issuer DID resolves, 503 otherwise. The status code is
    // the signal an orchestrator and a container healthcheck both read; the body is what a human
    // curling it needs in order to know WHICH issuer failed and why.
    if (req.method === 'GET' && req.url === '/ready') {
      return void assessReadiness(coreCfg).then(
        (r) => reply(r.ready ? 200 : 503, r),
        // A PROBE THAT THROWS IS NOT READY. Never let an unexpected failure inside the probe
        // present as a ready deployment.
        (e) => reply(503, {
          ready: false,
          degraded: true,
          checkedAt: new Date().toISOString(),
          reason: `readiness probe failed: ${e instanceof Error ? e.message : String(e)}`,
          issuers: [],
        }),
      );
    }
    if (req.method === 'GET' && req.url === '/version') {
      // ─── WHAT IS RUNNING, ANSWERABLE WITHOUT SHELL ACCESS ─────────────────────────────────
      //
      // Before this, answering it meant sshing to the box, hashing dist files, and comparing them
      // against release directories — and on this service that comparison matched NOTHING: the
      // running bundle existed in exactly one place, no preserved copy, and the PROVENANCE file
      // named a commit three days older than the bytes.
      //
      // The stamp is embedded at BUILD time, so it travels with the artifact rather than describing
      // it from beside it.
      return void reply(200, {
        service: '@observer-protocol/op-verify-service',
        build: {
          commit: __BUILD_COMMIT__,
          branch: __BUILD_BRANCH__,
          // TRUE MEANS THE BYTES DO NOT MATCH THE COMMIT. A hash alone says which commit was checked
          // out, not that the tree was clean when it was built.
          dirty: __BUILD_DIRTY__,
          builtAt: __BUILT_AT__,
        },
        engine: {
          // BUILT AGAINST vs RUNNING AGAINST, and they can differ: a dist copied onto a box whose
          // node_modules moved underneath it. Reporting one would make that invisible.
          builtAgainst: __BUILD_ENGINE__,
          running: installedEngineVersion() ?? 'unknown',
          agree: (installedEngineVersion() ?? 'unknown') === __BUILD_ENGINE__,
        },
        verification: {
          open: true,
          rateLimitPerCallerPerMin: RATE_MAX,
          rateLimitGlobalPerMin: RATE_MAX_GLOBAL,
        },
        ...allowlistReport(coreCfg),
      });
    }
    if (req.method !== 'POST' || req.url !== '/v1/verify') return void reply(404, { error: 'GET /health, GET /ready, GET /version, POST /v1/verify' });

    // NO AUTHENTICATION. See RATE_MAX above for why, and note what is NOT here: there is no
    // identifier to look a credential up by, so an unauthenticated caller cannot ask this service
    // for anything it does not already hold.
    const now = Date.now();

    if (!globalWindow || now - globalWindow.windowStart > RATE_WINDOW_MS) {
      globalWindow = { count: 1, windowStart: now };
    } else if (++globalWindow.count > RATE_MAX_GLOBAL) {
      return void reply(429, { error: 'service rate limit exceeded', retryAfterMs: RATE_WINDOW_MS - (now - globalWindow.windowStart) });
    }

    const bucketKey = callerKey(req);
    const bucket = rate.get(bucketKey);
    if (!bucket || now - bucket.windowStart > RATE_WINDOW_MS) rate.set(bucketKey, { count: 1, windowStart: now });
    else if (++bucket.count > RATE_MAX) {
      return void reply(429, { error: 'rate limit exceeded', retryAfterMs: RATE_WINDOW_MS - (now - bucket.windowStart) });
    }

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
  // WHAT IS TRUE OF THIS ENDPOINT NOW, announced at startup because it is a posture rather than a
  // setting. The previous line warned that an empty token list meant every request would 401; that
  // was accurate and is now the opposite of the design.
  console.log(
    `POST /v1/verify is OPEN — no bearer token. Verification takes an artifact as input and ` +
    `retrieves nothing: there is no lookup by identifier, so a caller can only check a credential ` +
    `it already holds. Rate limited to ${RATE_MAX}/min per caller and ${RATE_MAX_GLOBAL}/min ` +
    `overall — abuse control, not access control.`,
  );
  if (tokens.length > 0) {
    // A LEFTOVER TOKEN IS NOT AN ERROR AND IS NOT A CONTROL EITHER. Nothing reads it any more, so
    // an operator who believes the endpoint is gated because the env file still lists one should
    // read this instead of discovering it from traffic.
    console.warn(
      `WARNING: ${tokens.length} bearer token(s) are configured and NOTHING READS THEM. ` +
      'The endpoint is open by ruling; these tokens gate nothing. Remove OP_VERIFY_BEARER_TOKENS ' +
      'so the env file does not imply a control that does not exist.',
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
