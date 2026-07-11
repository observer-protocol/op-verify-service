// Response signing: eddsa-jcs-2022 proof over the exact verification outcome,
// verifiable against the OP DID document — so a relying party's trust never
// rides on transport or on this endpoint's availability. Same discipline the
// production issuer now has: a boot-time fail-closed keystate check refuses
// to start unless the configured verificationMethod is listed in the LIVE
// DID document's assertionMethod and the private key derives to its
// published public key. No hardcoded issuer key, ever.
//
// Composition only: JCS, sha-256, base58 and DID resolution are the policy
// engine's own exported primitives; the only crypto call is node:crypto ed25519.

import { createHash, createPrivateKey, sign as nodeSign, type KeyObject } from 'node:crypto';
import { readFileSync } from 'node:fs';
import {
  base58Encode,
  decodeEd25519Multibase,
  findAssertionMethodKey,
  jcsBytes,
  resolveDidDocument,
  resolveDidKeyDocument,
} from '@observer-protocol/policy-engine';

const sha256 = (b: Buffer): Buffer => createHash('sha256').update(b).digest();

export interface ResponseSigner {
  verificationMethod: string;
  sign(document: Record<string, unknown>): Record<string, unknown>;
}

export interface SignerConfig {
  /** PKCS8 PEM path of the Ed25519 response-signing key (e.g. #key-3's file). */
  keyPath: string;
  /** The verificationMethod id, e.g. did:web:observerprotocol.org#key-3. */
  verificationMethod: string;
  cacheDir: string;
  /** Offline DID-document override for air-gapped tests. */
  offlineDidDocumentPath?: string;
}

/** Boot-time keystate assertion + signer construction. Throws (refuses to
 * start) on any mismatch — never falls back to an unlisted key. */
export async function createResponseSigner(cfg: SignerConfig): Promise<ResponseSigner> {
  const key: KeyObject = createPrivateKey(readFileSync(cfg.keyPath, 'utf8'));
  if (key.asymmetricKeyType !== 'ed25519') {
    throw new Error(`response signing key at ${cfg.keyPath} is ${key.asymmetricKeyType}, not ed25519 — refusing to start`);
  }
  const did = cfg.verificationMethod.split('#')[0] ?? '';
  const doc = did.startsWith('did:key:')
    ? resolveDidKeyDocument(did)
    : (
        await resolveDidDocument(did, {
          cacheDir: cfg.cacheDir,
          timeoutMs: 10_000,
          maxStalenessHours: 24,
          ...(cfg.offlineDidDocumentPath ? { offlinePath: cfg.offlineDidDocumentPath } : {}),
        })
      ).doc;
  // Throws if the VM is not assertionMethod-listed — exactly the refusal we want.
  const { entry } = findAssertionMethodKey(doc, cfg.verificationMethod);
  if (!entry.publicKeyMultibase) throw new Error(`${cfg.verificationMethod} carries no publicKeyMultibase — refusing to start`);
  const { key: published } = decodeEd25519Multibase(entry.publicKeyMultibase);
  const derived = Buffer.from((key.export({ format: 'jwk' }) as { x: string }).x, 'base64url');
  if (!published.equals(derived)) {
    throw new Error(`response signing key does not derive to the published key for ${cfg.verificationMethod} — refusing to start (keystate mismatch)`);
  }

  return {
    verificationMethod: cfg.verificationMethod,
    sign(document: Record<string, unknown>): Record<string, unknown> {
      const proofOptions: Record<string, unknown> = {
        type: 'DataIntegrityProof',
        cryptosuite: 'eddsa-jcs-2022',
        created: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
        verificationMethod: cfg.verificationMethod,
        proofPurpose: 'assertionMethod',
      };
      const hashData = Buffer.concat([sha256(jcsBytes(proofOptions)), sha256(jcsBytes(document))]);
      const sig = nodeSign(null, hashData, key);
      return { ...document, proof: { ...proofOptions, proofValue: 'z' + base58Encode(sig) } };
    },
  };
}
