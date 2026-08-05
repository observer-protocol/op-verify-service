// READINESS: the split that closes "reports healthy while refusing every credential".
//
// THE FIXTURE IS UNDER TEST BEFORE THE ASSERTION IS. A readiness suite that can only ever observe
// one answer proves nothing: "not ready" asserted against a probe that is not ready under any
// condition is indistinguishable from a probe that is hard-wired to fail. So the first test here
// establishes that BOTH answers are reachable in this harness, and everything after it is allowed
// to lean on that.
//
// Every case runs OFFLINE by construction — an unresolvable .invalid host for the failure side, an
// offline DID-document override for the success side. Neither depends on the network being present
// or absent, which is the property that lets this suite fail honestly on a laptop and in CI.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateKeyPairSync } from 'node:crypto';
import { assessReadiness, resetReadinessCache } from '../dist/index.js';

const tmp = (p) => mkdtempSync(join(tmpdir(), p));

// .invalid is reserved by RFC 2606 and can never resolve, so this is unreachable by specification
// rather than by a hostname that might one day be registered.
const UNREACHABLE = 'did:web:cold-cache.invalid';

// A REAL did:key, by the same recipe the service test uses. A hand-made string with the right
// prefix would be a fixture that proves the prefix check and nothing about derivation.
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const b58 = (buf) => {
  let x = 0n;
  for (const b of buf) x = x * 256n + BigInt(b);
  let o = '';
  while (x > 0n) { o = B58[Number(x % 58n)] + o; x /= 58n; }
  for (const b of buf) { if (b === 0) o = '1' + o; else break; }
  return o;
};
function didKey() {
  const kp = generateKeyPairSync('ed25519');
  const pub = Buffer.from(kp.publicKey.export({ format: 'jwk' }).x, 'base64url');
  return 'did:key:z' + b58(Buffer.concat([Buffer.from([0xed, 0x01]), pub]));
}

function offlineDoc() {
  const dir = tmp('opverify-ready-offline-');
  const path = join(dir, 'did.json');
  writeFileSync(path, JSON.stringify({
    id: 'did:web:observerprotocol.org',
    verificationMethod: [{ id: 'did:web:observerprotocol.org#key-3', type: 'Ed25519VerificationKey2020', controller: 'did:web:observerprotocol.org', publicKeyMultibase: 'z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK' }],
    assertionMethod: ['did:web:observerprotocol.org#key-3'],
  }));
  return path;
}

// ─── 0. THE HARNESS CAN SAY BOTH WORDS ──────────────────────────────────────────────────────────
test('the fixture can produce ready:true AND ready:false, so later assertions mean something', async () => {
  resetReadinessCache();
  const bad = await assessReadiness(
    { issuerAllowlist: [UNREACHABLE], cacheDir: tmp('opverify-ready-a-') },
    { force: true },
  );
  resetReadinessCache();
  const good = await assessReadiness(
    { issuerAllowlist: ['did:web:observerprotocol.org'], cacheDir: tmp('opverify-ready-b-'), offlineDidDocumentPath: offlineDoc() },
    { force: true },
  );
  assert.equal(bad.ready, false, 'an unreachable pinned issuer must not be ready');
  assert.equal(good.ready, true, 'a resolvable pinned issuer must be ready');
  assert.notEqual(bad.ready, good.ready, 'the probe must be able to distinguish the two states');
});

// ─── 1. THE EXACT CASE COMPOSE.md PARKED ────────────────────────────────────────────────────────
//
// Cold cache, issuer unreachable. Before the split this container reported healthy. It must now
// report not-ready, and it must name which issuer and why rather than saying so generically.
test('cold cache behind a blocked proxy is visibly NOT ready, and names the issuer', async () => {
  resetReadinessCache();
  const r = await assessReadiness(
    { issuerAllowlist: [UNREACHABLE], cacheDir: tmp('opverify-ready-cold-') },
    { force: true },
  );
  assert.equal(r.ready, false);
  assert.equal(r.issuers.length, 1);
  assert.equal(r.issuers[0].state, 'unreachable');
  assert.equal(r.issuers[0].resolvable, false);
  assert.match(r.reason, /unresolvable/i);
  assert.ok(r.reason.includes(UNREACHABLE), 'the reason must name the issuer that failed');
  // THE UNDERLYING FAILURE SURVIVES TO THE BODY. "not ready" without the cause sends the reader
  // back to guessing between DNS, TLS, proxy and timeout.
  assert.ok(typeof r.issuers[0].error === 'string' && r.issuers[0].error.length > 0,
    'an unreachable issuer must carry the thrown failure, not just a state name');
});

// ─── 2. ONE BROKEN ISSUER IS ENOUGH ─────────────────────────────────────────────────────────────
//
// Partial reach is the case where an averaging probe quietly passes: one of two issuers resolves,
// so "mostly fine". Credentials from the other issuer are refused every time.
//
// The resolvable half is a did:key, NOT an offline override. Writing this with an offline document
// is what the first draft did, and it could not fail: the engine's offlinePath serves ONE document
// for EVERY did:web it is asked about, so the unreachable issuer resolved from it too and the case
// reported ready. The impossible fixture, not the assertion, was the bug.
test('one unresolvable issuer among several is not ready', async () => {
  resetReadinessCache();
  const r = await assessReadiness(
    {
      issuerAllowlist: [didKey(), UNREACHABLE],
      cacheDir: tmp('opverify-ready-mixed-'),
    },
    { force: true },
  );
  assert.equal(r.ready, false, 'a partially reachable deployment is not ready');
  assert.ok(r.reason.includes(UNREACHABLE));
  assert.ok(r.issuers.some((i) => i.resolvable), 'the fixture must contain a resolvable issuer too, or this proves nothing');
});

// The offline-override mode cannot detect an unreachable issuer at all. That is a property of the
// engine's single-document override, and a reader of a green /ready in that mode must not take it
// for evidence of reach.
test('with an offline override no did:web can be reported unreachable, and the report says degraded', async () => {
  resetReadinessCache();
  const r = await assessReadiness(
    {
      issuerAllowlist: ['did:web:observerprotocol.org', UNREACHABLE],
      cacheDir: tmp('opverify-ready-offmode-'),
      offlineDidDocumentPath: offlineDoc(),
    },
    { force: true },
  );
  assert.equal(r.ready, true, 'documents the engine behaviour: the override answers for every did:web');
  assert.ok(r.issuers.every((i) => i.state === 'offline-override'));
  assert.equal(r.degraded, true, 'resolvable by configuration must never read as reachable');
});

// ─── 3. did:key CANNOT BE EVIDENCE OF REACH ─────────────────────────────────────────────────────
//
// did:key resolves in memory from the DID string. Counting it as a live fetch would let an
// allowlist of did:key issuers report a fully ready deployment on a machine with no network.
test('a did:key issuer is ready but reports no network proof, and marks the deployment degraded', async () => {
  resetReadinessCache();
  const r = await assessReadiness(
    { issuerAllowlist: [didKey()], cacheDir: tmp('opverify-ready-key-') },
    { force: true },
  );
  assert.equal(r.issuers[0].state, 'no-network-proof');
  assert.equal(r.ready, true, 'a did:key issuer is resolvable, so it does not block readiness');
  assert.equal(r.degraded, true, 'but it is not evidence of reach, so ready must not read as fully fine');
});

// A did:key is only resolvable if it actually derives. Accepting the prefix would report ready on
// an issuer typed wrong in an env file, whose every credential is refused — the cold-cache defect
// reached by a typo instead of by a proxy.
test('a malformed did:key is not resolvable, and is not counted as ready', async () => {
  resetReadinessCache();
  const r = await assessReadiness(
    { issuerAllowlist: ['did:key:z6MkNOT-REAL-KEY-MATERIAL'], cacheDir: tmp('opverify-ready-badkey-') },
    { force: true },
  );
  assert.equal(r.ready, false, 'a did:key that derives to nothing must not pass as an accepted issuer');
  assert.equal(r.issuers[0].state, 'unreachable');
  assert.match(r.issuers[0].error, /malformed did:key/);
});

// ─── 4. AN EMPTY ALLOWLIST ACCEPTS NOTHING ──────────────────────────────────────────────────────
test('an empty issuer allowlist is not ready: it accepts no issuer, so nothing can verify', async () => {
  resetReadinessCache();
  const r = await assessReadiness({ issuerAllowlist: [], cacheDir: tmp('opverify-ready-empty-') }, { force: true });
  assert.equal(r.ready, false);
  assert.match(r.reason, /empty/i);
});

// ─── 5. READY IS NOT THE SAME AS FINE ───────────────────────────────────────────────────────────
test('an offline override is ready, degraded, and says it proves nothing about the network', async () => {
  resetReadinessCache();
  const r = await assessReadiness(
    { issuerAllowlist: ['did:web:observerprotocol.org'], cacheDir: tmp('opverify-ready-off-'), offlineDidDocumentPath: offlineDoc() },
    { force: true },
  );
  assert.equal(r.ready, true);
  assert.equal(r.issuers[0].state, 'offline-override');
  assert.equal(r.degraded, true, 'resolvable by construction is not the same as reachable');
});

// ─── 6. THE PROBE PRINTS WHAT IT DOES NOT COVER, EVERY RUN ──────────────────────────────────────
//
// The limits of a check belong with the check, not in a document beside it that a reader of the
// JSON never opens.
test('every report carries its own limits and the list of what it does not cover', async () => {
  resetReadinessCache();
  const r = await assessReadiness(
    { issuerAllowlist: [UNREACHABLE], cacheDir: tmp('opverify-ready-limits-') },
    { force: true },
  );
  assert.equal(r.limits.maxStalenessHours, 24, 'must match the verification path, or /ready can pass where verification refuses');
  assert.ok(Array.isArray(r.limits.notCovered) && r.limits.notCovered.length >= 3);
  assert.ok(r.limits.notCovered.some((s) => /agent DID/i.test(s)), 'must disclose that the agent DID is never probed');
  assert.ok(r.limits.notCovered.some((s) => /revocation/i.test(s)), 'must disclose that revocation is not probed');
});

// ─── 7. THE MEMO MUST NOT OUTLIVE A RECOVERY ────────────────────────────────────────────────────
//
// A cached failure that sticks is a deployment that came back and still reports broken. Failure is
// held for a shorter window than success precisely so recovery is visible; assert the asymmetry
// rather than trusting the constants.
test('a failing probe is re-checked sooner than a passing one', async () => {
  resetReadinessCache();
  const cold = { issuerAllowlist: [UNREACHABLE], cacheDir: tmp('opverify-ready-memo-') };
  const t0 = 1_000_000_000_000;
  const first = await assessReadiness(cold, { nowMs: t0 });
  assert.equal(first.ready, false);

  // Inside the failure window: served from memo, same timestamp.
  const memoised = await assessReadiness(cold, { nowMs: t0 + 5_000 });
  assert.equal(memoised.checkedAt, first.checkedAt, 'inside the failure TTL the probe must be memoised');

  // Past the failure window but WELL inside the success window: a failure must have been re-probed
  // by now. If failure were held for the success TTL this assertion is the one that catches it.
  const reprobed = await assessReadiness(cold, { nowMs: t0 + 30_000 });
  assert.notEqual(reprobed.checkedAt, first.checkedAt,
    'a failed probe held for the success TTL would hide a recovered deployment');
});

// ─── 8. /health MUST NOT GROW A READINESS VERDICT ───────────────────────────────────────────────
//
// One question, one place that answers it. If /health computed readiness too, the two could
// disagree and a reader would have two answers. It carries a POINTER and a warning, never a verdict.
test('/health points at /ready and does not compute a second readiness answer', () => {
  const src = readFileSync(new URL('../src/server.ts', import.meta.url), 'utf8');
  const start = src.indexOf("req.url === '/health'");
  const health = src.slice(start, src.indexOf("req.url === '/ready'", start));

  assert.ok(health.includes("endpoint: '/ready'"), '/health must point at the readiness endpoint');
  assert.ok(/warning:/.test(health), '/health must warn that live does not imply able to verify');
  assert.ok(!health.includes('assessReadiness'),
    '/health must not compute readiness: liveness has to answer without opening a socket');
  assert.ok(!/ready:\s*(true|false)/.test(health),
    '/health must not state a readiness verdict of its own');
});
