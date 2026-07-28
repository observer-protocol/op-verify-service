// Acceptance for the hosted verify service: the full pipeline (identity ->
// mandate -> scope) against real signed credentials, pass AND fail sides, and
// the HTTP surface end to end (auth, signed responses that verify against
// the signer's DID document).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync, readdirSync } from "node:fs";
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateKeyPairSync, sign as edSign, createHash, verify as edVerify } from 'node:crypto';
import { runVerification } from '../dist/index.js';
import { resolveDidKeyDocument, decodeEd25519Multibase, jcsBytes } from '@observer-protocol/policy-engine';

// ---- did:key + eddsa-jcs-2022 test signer (the sanctioned fixture recipe) ----
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const b58 = (buf) => {
  let x = 0n;
  for (const b of buf) x = x * 256n + BigInt(b);
  let o = '';
  while (x > 0n) { o = B58[Number(x % 58n)] + o; x /= 58n; }
  for (const b of buf) { if (b === 0) o = '1' + o; else break; }
  return o;
};
const sha = (b) => createHash('sha256').update(b).digest();
function makeAgent() {
  const kp = generateKeyPairSync('ed25519');
  const pub = Buffer.from(kp.publicKey.export({ format: 'jwk' }).x, 'base64url');
  const did = 'did:key:z' + b58(Buffer.concat([Buffer.from([0xed, 0x01]), pub]));
  return { did, privateKey: kp.privateKey, vm: did + '#' + did.slice('did:key:'.length) };
}
function signCred(doc, priv, vm) {
  const po = { '@context': doc['@context'], type: 'DataIntegrityProof', cryptosuite: 'eddsa-jcs-2022', created: '2026-06-15T00:00:00Z', verificationMethod: vm, proofPurpose: 'assertionMethod' };
  const hashData = Buffer.concat([sha(jcsBytes(po)), sha(jcsBytes(doc))]);
  return { ...doc, proof: { ...po, proofValue: 'z' + b58(edSign(null, hashData, priv)) } };
}

const SCHEMA = 'https://observerprotocol.org/schemas/delegation/v2.3.json';
function makeMandate(principal, agentDid, { validUntil = '2030-01-01T00:00:00Z', ceiling = '50', allow = ['merchant-1'] } = {}) {
  return signCred({
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    id: 'urn:uuid:arbis-demo-1',
    type: ['VerifiableCredential', 'ObserverDelegationCredential'],
    issuer: principal.did,
    validFrom: '2026-01-01T00:00:00Z',
    validUntil,
    credentialSchema: { id: SCHEMA, type: 'JsonSchema' },
    credentialSubject: {
      id: agentDid,
      authorizationLevel: 'policy',
      authorizationConfig: { policy: { policy_id: 'arbis-demo', rail_preference: ['hosted-verify'] } },
      actionScope: { per_transaction_ceiling: { amount: ceiling, currency: 'USD' } },
      delegationScope: { may_delegate_further: false },
      enforcementMode: 'pre_transaction_check',
      tradingMandate: { counterparty: { allowList: allow } },
    },
  }, principal.privateKey, principal.vm);
}

function coreCfg(principal, extra = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'opverify-test-'));
  return {
    issuerAllowlist: [principal.did],
    schemaAllowlist: [SCHEMA],
    cacheDir: join(dir, 'cache'),
    nowMs: Date.parse('2026-07-10T12:00:00Z'),
    ...extra,
  };
}

test('identity + mandate valid; no proposal -> no scope block', async () => {
  const principal = makeAgent();
  const agent = makeAgent();
  const out = await runVerification(coreCfg(principal), { agentDid: agent.did, mandate: makeMandate(principal, agent.did) });
  assert.equal(out.identity.valid, true, out.identity.reason);
  assert.equal(out.mandate.valid, true, out.mandate.reason);
  assert.equal(out.scope, undefined);
});

test('scope: in-scope allow, over-ceiling deny, wrong-counterparty deny', async () => {
  const principal = makeAgent();
  const agent = makeAgent();
  const mandate = makeMandate(principal, agent.did);
  const cfg = coreCfg(principal);
  const ok = await runVerification(cfg, { agentDid: agent.did, mandate, proposal: { counterparty: 'merchant-1', amount: '20.00', currency: 'USD' } });
  assert.equal(ok.scope?.inScope, true, ok.scope?.reason);
  const over = await runVerification(cfg, { agentDid: agent.did, mandate, proposal: { counterparty: 'merchant-1', amount: '60', currency: 'USD' } });
  assert.equal(over.scope?.inScope, false);
  assert.match(over.scope.reason, /ceiling/);
  const wrong = await runVerification(cfg, { agentDid: agent.did, mandate, proposal: { counterparty: 'mallory', amount: '20', currency: 'USD' } });
  assert.equal(wrong.scope?.inScope, false);
});

test('fail-closed: expired mandate, unlisted issuer, tampered credential, legacy suite, wrong binding, unknown currency', async () => {
  const principal = makeAgent();
  const agent = makeAgent();
  const cfg = coreCfg(principal);

  const expired = await runVerification(cfg, { agentDid: agent.did, mandate: makeMandate(principal, agent.did, { validUntil: '2026-06-26T00:00:00Z' }) });
  assert.equal(expired.mandate.valid, false);

  const stranger = makeAgent();
  const unlisted = await runVerification(cfg, { agentDid: agent.did, mandate: makeMandate(stranger, agent.did) });
  assert.equal(unlisted.mandate.valid, false);
  assert.match(unlisted.mandate.reason, /issuer allowlist/);

  const tampered = makeMandate(principal, agent.did);
  tampered.credentialSubject.actionScope.per_transaction_ceiling.amount = '999999';
  const t = await runVerification(cfg, { agentDid: agent.did, mandate: tampered });
  assert.equal(t.mandate.valid, false);

  const legacy = makeMandate(principal, agent.did);
  legacy.proof.type = 'Ed25519Signature2026';
  delete legacy.proof.cryptosuite;
  const l = await runVerification(cfg, { agentDid: agent.did, mandate: legacy });
  assert.equal(l.mandate.valid, false);

  const otherAgent = makeAgent();
  const misbound = await runVerification(cfg, { agentDid: otherAgent.did, mandate: makeMandate(principal, agent.did) });
  assert.equal(misbound.identity.valid, false);
  assert.match(misbound.identity.reason, /not bound/);

  const badCur = await runVerification(cfg, { agentDid: agent.did, mandate: makeMandate(principal, agent.did), proposal: { counterparty: 'merchant-1', amount: '20', currency: 'DOGE' } });
  assert.equal(badCur.scope?.inScope, false);
  assert.match(badCur.scope.reason, /minor-unit exponent/);
});

test('context: opaque correlation echoed verbatim onto allow AND deny outcomes', async () => {
  const principal = makeAgent();
  const agent = makeAgent();
  const cfg = coreCfg(principal);
  const ctx = { correlationId: 'arbis_run_abc123', fingerprint: 'structural:deadbeef' };

  const allow = await runVerification(cfg, { agentDid: agent.did, mandate: makeMandate(principal, agent.did), proposal: { counterparty: 'merchant-1', amount: '20', currency: 'USD' }, context: ctx });
  assert.deepEqual(allow.context, ctx, 'context echoed on a valid, in-scope outcome');

  const deny = await runVerification(cfg, { agentDid: agent.did, mandate: makeMandate(principal, agent.did), proposal: { counterparty: 'merchant-1', amount: '60', currency: 'USD' }, context: ctx });
  assert.equal(deny.scope?.inScope, false);
  assert.deepEqual(deny.context, ctx, 'context echoed even on a fail-closed deny');

  const none = await runVerification(cfg, { agentDid: agent.did, mandate: makeMandate(principal, agent.did) });
  assert.equal(none.context, undefined, 'absent when the caller sends no context');
});

test('fail-closed default: empty token list denies all AND announces itself at boot', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'opverify-noauth-'));
  const skp = generateKeyPairSync('ed25519');
  const sPub = Buffer.from(skp.publicKey.export({ format: 'jwk' }).x, 'base64url');
  const sDid = 'did:key:z' + b58(Buffer.concat([Buffer.from([0xed, 0x01]), sPub]));
  const keyPath = join(dir, 'signing.pem');
  writeFileSync(keyPath, skp.privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });

  process.env.OP_VERIFY_SIGNING_KEY_PATH = keyPath;
  process.env.OP_VERIFY_SIGNING_VM = `${sDid}#${sDid.slice('did:key:'.length)}`;
  process.env.OP_VERIFY_ISSUER_ALLOWLIST = 'did:web:observerprotocol.org';
  process.env.OP_VERIFY_SCHEMA_ALLOWLIST = SCHEMA;
  delete process.env.OP_VERIFY_BEARER_TOKENS; // the misconfiguration we care about
  process.env.OP_VERIFY_CACHE_DIR = join(dir, 'cache');
  process.env.PORT = '18092';

  const warnings = [];
  const origWarn = console.warn;
  console.warn = (...a) => warnings.push(a.join(' '));
  let server;
  try {
    const { main } = await import('../dist/server.js');
    server = await main();
  } finally {
    console.warn = origWarn;
  }
  assert.ok(warnings.some((w) => /no bearer tokens configured/i.test(w) && /401/.test(w)), 'boot must warn loudly when no tokens are configured');

  const url = 'http://127.0.0.1:18092/v1/verify';
  const body = JSON.stringify({ agentDid: 'did:web:x', mandate: {} });
  // No configuration grants access: arbitrary token, empty bearer, no header all 401.
  for (const headers of [{ authorization: 'Bearer anything-at-all' }, { authorization: 'Bearer ' }, {}]) {
    const res = await fetch(url, { method: 'POST', body, headers });
    assert.equal(res.status, 401, `empty token list must deny (headers=${JSON.stringify(headers)})`);
  }
  server.close();
});

// The engine floor gates every authenticated path, so the tests that exercise
// one are gated on the same condition rather than bypassed. No escape hatch:
// an env var that disables the interlock for tests is an env var that ends up
// in a production unit file. When the pin moves these un-skip on their own.
const ENGINE_VERSION = JSON.parse(
  readFileSync(new URL('../node_modules/@observer-protocol/policy-engine/package.json', import.meta.url), 'utf8'),
).version;
const FLOOR = '0.3.0';
const belowFloor = ENGINE_VERSION.localeCompare(FLOOR, undefined, { numeric: true }) < 0;
const skipAuthed = belowFloor
  ? `engine ${ENGINE_VERSION} is below the ${FLOOR} floor: authenticated paths cannot be served, so they cannot be tested`
  : false;

test('interlock: satisfied above the floor, and still refuses when the engine is unidentifiable', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'opverify-floor-'));
  const kp = generateKeyPairSync('ed25519');
  const pub = Buffer.from(kp.publicKey.export({ format: 'jwk' }).x, 'base64url');
  const did = 'did:key:z' + b58(Buffer.concat([Buffer.from([0xed, 0x01]), pub]));
  const keyPath = join(dir, 'signing.pem');
  writeFileSync(keyPath, kp.privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });

  process.env.OP_VERIFY_SIGNING_KEY_PATH = keyPath;
  process.env.OP_VERIFY_SIGNING_VM = `${did}#${did.slice('did:key:'.length)}`;
  process.env.OP_VERIFY_ISSUER_ALLOWLIST = did;
  process.env.OP_VERIFY_SCHEMA_ALLOWLIST = SCHEMA;
  process.env.OP_VERIFY_CACHE_DIR = join(dir, 'cache');
  const { main } = await import('../dist/server.js');
  // Distinct port per start: close() is async, so reusing one port races EADDRINUSE.
  const closed = (srv) => new Promise((r) => srv.close(r));

  // No tokens: starts at any engine version. Fail-closed 401, not a failure.
  process.env.PORT = '18093';
  process.env.OP_VERIFY_BEARER_TOKENS = '';
  await closed(await main());

  // Tokens present, engine at or above the floor: the interlock is SATISFIED
  // rather than dormant. Before the pin move this same call refused.
  assert.ok(!belowFloor, `expected engine ${ENGINE_VERSION} to be at or above the ${FLOOR} floor`);
  process.env.PORT = '18095';
  process.env.OP_VERIFY_BEARER_TOKENS = 'a-minted-token';
  await closed(await main());

  // The refusal path must still work. Rather than fake a version, run from a cwd
  // where the engine cannot be resolved at all: installedEngineVersion() returns
  // null and "unknown refuses" fires. Same refusal branch, real code.
  const cwd = process.cwd();
  try {
    process.chdir(mkdtempSync(join(tmpdir(), 'opverify-noengine-')));
    process.env.PORT = '18094';
    await assert.rejects(
      () => main(),
      (err) => {
        assert.match(err.message, /could not be determined/);
        assert.match(err.message, /Refusing to serve authenticated traffic/);
        return true;
      },
      'an unidentifiable engine must refuse while tokens are configured',
    );
  } finally {
    process.chdir(cwd);
    process.env.OP_VERIFY_BEARER_TOKENS = '';
  }
});

test('HTTP surface: auth, signed response, proof verifies against the signer DID', { skip: skipAuthed }, async () => {
  const principal = makeAgent();
  const agent = makeAgent();
  const dir = mkdtempSync(join(tmpdir(), 'opverify-http-'));

  // response-signing key: fresh ed25519 as did:key (keystate check passes in-memory)
  const signerKp = generateKeyPairSync('ed25519');
  const signerPub = Buffer.from(signerKp.publicKey.export({ format: 'jwk' }).x, 'base64url');
  const signerDid = 'did:key:z' + b58(Buffer.concat([Buffer.from([0xed, 0x01]), signerPub]));
  const keyPath = join(dir, 'signing.pem');
  writeFileSync(keyPath, signerKp.privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });

  process.env.OP_VERIFY_SIGNING_KEY_PATH = keyPath;
  process.env.OP_VERIFY_SIGNING_VM = `${signerDid}#${signerDid.slice('did:key:'.length)}`;
  process.env.OP_VERIFY_ISSUER_ALLOWLIST = principal.did;
  process.env.OP_VERIFY_SCHEMA_ALLOWLIST = SCHEMA;
  process.env.OP_VERIFY_BEARER_TOKENS = 'arbis-test-token';
  process.env.OP_VERIFY_CACHE_DIR = join(dir, 'cache');
  process.env.PORT = '18091';
  const { main } = await import('../dist/server.js');
  const server = await main();

  const url = 'http://127.0.0.1:18091/v1/verify';
  const correlation = { correlationId: 'arbis_run_http_1', fingerprint: 'structural:cafe' };
  const body = JSON.stringify({ agentDid: agent.did, mandate: makeMandate(principal, agent.did), proposal: { counterparty: 'merchant-1', amount: '20', currency: 'USD' }, context: correlation });

  const noAuth = await fetch(url, { method: 'POST', body });
  assert.equal(noAuth.status, 401);

  // an unknown token is 401 (only the configured token works)
  const badTok = await fetch(url, { method: 'POST', body, headers: { authorization: 'Bearer not-a-real-token' } });
  assert.equal(badTok.status, 401);

  const res = await fetch(url, { method: 'POST', body, headers: { authorization: 'Bearer arbis-test-token' } });
  assert.equal(res.status, 200);
  const out = await res.json();
  assert.equal(out.identity.valid, true, out.identity.reason);
  assert.equal(out.mandate.valid, true, out.mandate.reason);
  assert.equal(out.scope.inScope, true, out.scope?.reason);
  // The opaque correlation context round-trips verbatim (and, being part of
  // the signed document below, is covered by the response proof).
  assert.deepEqual(out.context, correlation, 'context echoed in the HTTP response');

  // A request that reject-guards oversized context.
  const huge = JSON.stringify({ agentDid: agent.did, mandate: makeMandate(principal, agent.did), context: { blob: 'x'.repeat(5000) } });
  const tooBig = await fetch(url, { method: 'POST', body: huge, headers: { authorization: 'Bearer arbis-test-token' } });
  assert.equal(tooBig.status, 400);

  // A request with no context: the field is simply absent from the response.
  const bodyNoCtx = JSON.stringify({ agentDid: agent.did, mandate: makeMandate(principal, agent.did), proposal: { counterparty: 'merchant-1', amount: '20', currency: 'USD' } });
  const resNoCtx = await fetch(url, { method: 'POST', body: bodyNoCtx, headers: { authorization: 'Bearer arbis-test-token' } });
  const outNoCtx = await resNoCtx.json();
  assert.equal(outNoCtx.context, undefined, 'no context in, no context out');

  // The response proof verifies against the signer's DID document — the
  // relying party's no-trust-in-transport check, done exactly as documented.
  const { proof, ...doc } = out;
  const po = { ...proof };
  delete po.proofValue;
  const didDoc = resolveDidKeyDocument(signerDid);
  const { key: rawPub } = decodeEd25519Multibase(didDoc.verificationMethod[0].publicKeyMultibase);
  const hashData = Buffer.concat([sha(jcsBytes(po)), sha(jcsBytes(doc))]);
  const sigBytes = (() => { // b58 decode
    let x = 0n;
    for (const ch of proof.proofValue.slice(1)) x = x * 58n + BigInt(B58.indexOf(ch));
    const bytes = [];
    while (x > 0n) { bytes.unshift(Number(x % 256n)); x /= 256n; }
    return Buffer.from(bytes);
  })();
  const keyObj = (await import('node:crypto')).createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: rawPub.toString('base64url') }, format: 'jwk' });
  assert.equal(edVerify(null, hashData, keyObj, sigBytes), true, 'signed response must verify against the DID document');

  server.close();
});

// The engine-floor gate reads the version from node_modules. That is correct for
// THIS service only because it does not bundle the engine — the resolved copy is
// the running copy. The engine's own version.ts warns that under dual-presence
// the resolved copy is "the misleading one", because it upgrades on install while
// a bundled runtime stays frozen.
//
// So the gate's correctness rests on a property of the BUILD, not on the gate. If
// op-verify ever starts bundling, the gate keeps reading node_modules, keeps
// returning a number, and silently stops describing what runs. Nothing fails.
//
// This asserts the property, which converts a silent future expiry into a loud
// one. It was prose until 2026-07-28; prose is a precondition with no trigger.
test('engine-floor vantage: dist must NOT bundle the policy engine', async () => {
  const distDir = new URL('../dist/', import.meta.url);
  const files = readdirSync(distDir).filter((f) => f.endsWith('.js') || f.endsWith('.cjs'));
  assert.ok(files.length > 0, 'no dist output found — run the build first');

  let externalRefs = 0;
  let bundledMarkers = 0;
  for (const f of files) {
    const src = readFileSync(new URL(f, distDir), 'utf8');
    externalRefs += (src.match(/@observer-protocol\/policy-engine/g) ?? []).length;
    // A string only present in the engine's own rule implementations. If these
    // appear in our dist, the engine has been inlined and the gate is measuring
    // a copy that is not the one enforcing.
    bundledMarkers += (src.match(/spending_limits/g) ?? []).length;
  }

  assert.ok(
    externalRefs > 0,
    'dist has no external reference to the policy engine — either the build changed or the engine is now bundled; either way the version gate\'s vantage is no longer valid',
  );
  assert.equal(
    bundledMarkers,
    0,
    'dist contains bundled engine rule strings: the engine is being inlined, so the version read from node_modules no longer describes what runs. Fix the gate to report CORE_VERSION from the bundled copy before shipping this.',
  );
});
