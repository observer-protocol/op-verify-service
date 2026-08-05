// @observer-protocol/op-verify-service
//
// Hosted one-call verification for relying parties: POST an agent DID, its
// signed mandate, and optionally a proposed action; get back a signed,
// fail-closed verdict on identity, mandate validity, and scope. Composed
// entirely from the public @observer-protocol/policy-engine — the hosted
// endpoint is a convenience over code a relying party can run themselves.
// Verification only: no enforcement, no issuance, no custody.

export { runVerification, decimalToRaw, ISO4217_EXPONENT } from './verify-core.js';
export type { VerifyRequest, VerifyOutcome, ComponentResult, VerifyCoreConfig } from './verify-core.js';

export { createResponseSigner } from './signer.js';
export type { ResponseSigner, SignerConfig } from './signer.js';

export { main } from './server.js';

export { assessReadiness, resetReadinessCache, READINESS_MAX_STALENESS_HOURS } from './readiness.js';
export type { ReadinessReport, IssuerReadiness, IssuerState } from './readiness.js';
