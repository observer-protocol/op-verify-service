// Generate a REAL signed verdict that carries an echoed correlation context,
// using the built service with a throwaway did:key signer, and verify that the
// response proof covers the context. Demonstrates the level-2 bind end to end
// without touching the production key. Writes sample-response-with-context.json.
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateKeyPairSync, sign as edSign, verify as edVerify, createHash, createPublicKey } from 'node:crypto';
import { resolveDidKeyDocument, decodeEd25519Multibase, jcsBytes } from '@observer-protocol/policy-engine';

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const b58 = (buf) => { let x = 0n; for (const b of buf) x = x * 256n + BigInt(b); let o = ''; while (x > 0n) { o = B58[Number(x % 58n)] + o; x /= 58n; } for (const b of buf) { if (b === 0) o = '1' + o; else break; } return o; };
const sha = (b) => createHash('sha256').update(b).digest();
const agent = () => { const kp = generateKeyPairSync('ed25519'); const pub = Buffer.from(kp.publicKey.export({ format: 'jwk' }).x, 'base64url'); const did = 'did:key:z' + b58(Buffer.concat([Buffer.from([0xed, 0x01]), pub])); return { did, priv: kp.privateKey, vm: did + '#' + did.slice(8) }; };
const signCred = (doc, priv, vm) => { const po = { '@context': doc['@context'], type: 'DataIntegrityProof', cryptosuite: 'eddsa-jcs-2022', created: '2026-06-15T00:00:00Z', verificationMethod: vm, proofPurpose: 'assertionMethod' }; const hd = Buffer.concat([sha(jcsBytes(po)), sha(jcsBytes(doc))]); return { ...doc, proof: { ...po, proofValue: 'z' + b58(edSign(null, hd, priv)) } }; };

const SCHEMA = 'https://observerprotocol.org/schemas/delegation/v2.3.json';
const P = agent(), A = agent();
const mandate = signCred({ '@context': ['https://www.w3.org/ns/credentials/v2'], id: 'urn:uuid:arbis-demo-1', type: ['VerifiableCredential', 'ObserverDelegationCredential'], issuer: P.did, validFrom: '2026-01-01T00:00:00Z', validUntil: '2030-01-01T00:00:00Z', credentialSchema: { id: SCHEMA, type: 'JsonSchema' }, credentialSubject: { id: A.did, authorizationLevel: 'policy', authorizationConfig: { policy: { policy_id: 'arbis-demo', rail_preference: ['hosted-verify'] } }, actionScope: { per_transaction_ceiling: { amount: '50', currency: 'USD' } }, delegationScope: { may_delegate_further: false }, enforcementMode: 'pre_transaction_check', tradingMandate: { counterparty: { allowList: ['merchant-1'] } } } }, P.priv, P.vm);

const dir = mkdtempSync(join(tmpdir(), 'opverify-ctx-'));
const skp = generateKeyPairSync('ed25519');
const sPub = Buffer.from(skp.publicKey.export({ format: 'jwk' }).x, 'base64url');
const sDid = 'did:key:z' + b58(Buffer.concat([Buffer.from([0xed, 0x01]), sPub]));
const keyPath = join(dir, 'signing.pem');
writeFileSync(keyPath, skp.privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
Object.assign(process.env, { OP_VERIFY_SIGNING_KEY_PATH: keyPath, OP_VERIFY_SIGNING_VM: `${sDid}#${sDid.slice(8)}`, OP_VERIFY_ISSUER_ALLOWLIST: P.did, OP_VERIFY_SCHEMA_ALLOWLIST: SCHEMA, OP_VERIFY_BEARER_TOKENS: 'local-demo', OP_VERIFY_CACHE_DIR: join(dir, 'cache'), PORT: '18191' });

const { main } = await import('../dist/server.js');
const server = await main();
const context = { correlationId: 'arbis_run_9f3c2a', fingerprint: 'structural:7d1e', source: 'arbis' };
const res = await fetch('http://127.0.0.1:18191/v1/verify', { method: 'POST', headers: { authorization: 'Bearer local-demo', 'content-type': 'application/json' }, body: JSON.stringify({ agentDid: A.did, mandate, proposal: { counterparty: 'merchant-1', amount: '125.50', currency: 'USD' }, context }) });
const out = await res.json();
server.close();

// verify the proof covers the WHOLE document, context included
const { proof, ...doc } = out;
const po = { ...proof }; delete po.proofValue;
const didDoc = resolveDidKeyDocument(sDid);
const { key: rawPub } = decodeEd25519Multibase(didDoc.verificationMethod[0].publicKeyMultibase);
const hd = Buffer.concat([sha(jcsBytes(po)), sha(jcsBytes(doc))]);
let x = 0n; for (const ch of proof.proofValue.slice(1)) x = x * 58n + BigInt(B58.indexOf(ch));
const bytes = []; while (x > 0n) { bytes.unshift(Number(x % 256n)); x /= 256n; }
const keyObj = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: rawPub.toString('base64url') }, format: 'jwk' });
const sigOverContext = edVerify(null, hd, keyObj, Buffer.from(bytes));

writeFileSync(join(process.cwd(), 'scripts', 'sample-response-with-context.json'), JSON.stringify(out, null, 2) + '\n');
console.log('scope.inScope        :', out.scope?.inScope, `(${out.scope?.reason})`);
console.log('context echoed       :', JSON.stringify(out.context));
console.log('signature covers ctx :', sigOverContext);
console.log('saved                : scripts/sample-response-with-context.json');
