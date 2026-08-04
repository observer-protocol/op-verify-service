#!/usr/bin/env node
// Generate a local Ed25519 response-signing key and its did:key verificationMethod.
//
// WHY A did:key AND NOT OBSERVER'S #key-7.
//
// This service signs every verdict, and refuses to start unless the signing key derives to a key
// listed in the assertionMethod of the DID its verificationMethod names. Observer's #key-7 private
// key lives on the hosted deployment and is confined to that service's user. It is not shipped, and
// it must not be: a container anyone can run must not be able to sign as Observer.
//
// did:key is self-describing — the DID *is* the public key — so a locally generated key satisfies
// the boot keystate check with no network call and no Observer key material. The cost is stated
// rather than hidden: a verdict from this container is signed by WHOEVER RAN IT, and is evidence
// that this operator's engine reached that verdict. It is not an Observer attestation. Anyone who
// needs an Observer-signed verdict wants verify.observerprotocol.org.
//
// Usage:  node scripts/gen-did-key.mjs <key-path>
// Writes the PKCS8 PEM to <key-path> (mode 600) and prints the verificationMethod on stdout.
// Refuses to overwrite an existing key.

import { generateKeyPairSync } from 'node:crypto';
import { writeFileSync, existsSync, chmodSync, readFileSync } from 'node:fs';
import { createPublicKey } from 'node:crypto';
import { base58Encode } from '@observer-protocol/policy-engine';

const vmFor = (pubRaw) =>
  (mb => `did:key:${mb}#${mb}`)('z' + base58Encode(Buffer.concat([Buffer.from([0xed, 0x01]), pubRaw])));

const keyPath = process.argv[2];
if (!keyPath) {
  console.error('usage: node scripts/gen-did-key.mjs <key-path>');
  process.exit(2);
}

if (existsSync(keyPath)) {
  // Idempotent by design: the container restarts, and regenerating would silently change the
  // identity every verdict is signed under. Derive the VM from the key that is already there.
  const pub = createPublicKey(readFileSync(keyPath, 'utf8'));
  if (pub.asymmetricKeyType !== 'ed25519') {
    console.error(`existing key at ${keyPath} is ${pub.asymmetricKeyType}, not ed25519 — refusing`);
    process.exit(1);
  }
  process.stdout.write(vmFor(pub.export({ format: 'der', type: 'spki' }).subarray(-32)));
  process.exit(0);
}

const { publicKey, privateKey } = generateKeyPairSync('ed25519');
writeFileSync(keyPath, privateKey.export({ format: 'pem', type: 'pkcs8' }), { mode: 0o600 });
chmodSync(keyPath, 0o600);
process.stdout.write(vmFor(publicKey.export({ format: 'der', type: 'spki' }).subarray(-32)));
