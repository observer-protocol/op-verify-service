# op-verify-service

Hosted one-call verification of an Observer-issued agent: POST an agent's DID, its signed mandate, and optionally a proposed action; get back one signed, fail-closed JSON verdict — identity valid, mandate valid, action in scope. Built for relying parties who want verification in an afternoon: one network call, one response, no SDK to compile.

**Verification only.** This service holds no funds, no payment keys, and no custody of anything. It verifies public material and signs its answers.

## Why you don't have to trust it

Three properties, each checkable:

1. **It is a thin composition of the public [`@observer-protocol/policy-engine`](https://www.npmjs.com/package/@observer-protocol/policy-engine).** The mandate check is the engine's own pipeline (pinned issuer, structure, validity window, `eddsa-jcs-2022` proof against the issuer DID document's `assertionMethod`, revocation); the scope check is the same `enforceMandate` every OP engine runs. You can run the identical code path yourself from npm.
2. **The response is signed** (`eddsa-jcs-2022`) with a key published in the OP DID document's `assertionMethod` — verify it against `did:web:observerprotocol.org`, resolved over plain public HTTPS. Trust never rides on transport or on this endpoint.
3. **Everything the endpoint checks, you can re-check with no callback to Observer**: the DID document is public, the mandate schema URLs are frozen, revocation status lists are static public files. The hosted endpoint is a convenience, not a dependency.

## API

`POST /v1/verify` — `Authorization: Bearer <partner token>`

```json
{
  "agentDid": "did:web:observerprotocol.org:agents:...",
  "mandate": { "...the agent's signed delegation credential..." },
  "proposal": { "counterparty": "merchant-1", "amount": "125.50", "currency": "USD" }
}
```

Response (signed; `proposal` optional — omit it for identity+mandate only):

```json
{
  "agentDid": "...",
  "identity": { "valid": true, "notes": ["DID resolved publicly; mandate subject binds to this DID"] },
  "mandate":  { "valid": true, "id": "...", "issuer": "...", "validUntil": "..." },
  "scope":    { "inScope": false, "reason": "[ceiling] transaction value exceeds per_transaction_ceiling of 50 USD" },
  "verifiedAt": "...",
  "proof":    { "type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "verificationMethod": "did:web:observerprotocol.org#key-3", "proofValue": "z..." }
}
```

Fail-closed inventory (each is a test): unresolvable DID · mandate not bound to the presented DID · issuer not in the deployment allowlist · expired credential · tampered credential · legacy proof suites rejected · unknown currency · internal error returns everything-invalid, never a silent pass. A stateless deployment carries no spend counters, so velocity/cross-rail-budget mandates fail closed on the scope check with a reason naming that.

## Correlation context (optional, signed)

The request may carry an optional `context` object — an opaque correlation record such as an external trace id or a run fingerprint:

```json
{ "agentDid": "...", "mandate": { ... }, "context": { "correlationId": "trace-abc", "fingerprint": "structural:..." } }
```

It is **echoed verbatim into the response and covered by the response proof**, so one signed verdict binds cryptographically to the caller's own record — the verdict provably belongs to that trace, not merely sits beside it. It is never interpreted or trusted, is size-capped (4 KB), and is absent from the response unless the caller sends it. Additive and backward-compatible: pre-existing callers see no change. Added in 0.2.0.

## What it retains

Stateless by construction, and verifiable on the box:

- **No request bodies, mandates, headers, or verdicts are written to any persistent log.** There is no decisions/audit sink: the engine's audit path is directed at a per-request temp dir removed before the response returns. The service logs one startup line and nothing per-request (no access log; raw `node:http`, no framework).
- **Unauthenticated requests write nothing at all** — the body is never read or parsed before the `401`.
- The mandate touches disk only as a `0600` file inside the service's `PrivateTmp` namespace, solely to feed the engine's file-based `verifyCredential`, and is removed in a `finally` before responding. It never persists; `PrivateTmp` wipes it on restart regardless.
- The only file the service persists is a cache of **public** DID documents / status lists under `OP_VERIFY_CACHE_DIR`.

## Access is fail-closed by default

No configuration grants access when credentials are absent. If `OP_VERIFY_BEARER_TOKENS` is empty or unset, the token list is empty and **every** `/v1/verify` request returns `401` — an arbitrary token, an empty bearer, and a missing `Authorization` header all deny. There is no code path where "no tokens configured" authenticates a caller: `tokenOk` is `tokens.some(...)`, which is `false` over an empty list. Verified in code and by live probe. A deployment with no tokens boots healthy and denies all, and emits a startup warning saying so — a lost env file is visible at boot rather than surfacing later as a partner's mystery `401` while `/health` is green.

## Identity, precisely

The identity component asserts: the DID resolves publicly and the presented mandate is cryptographically bound to it. Proof of *live key control* is the separate challenge-response flow on the main API (`/observer/challenge` + `/observer/verify-agent`); a relying party that needs it can require both.

## Run

Configuration is env-only (see `src/server.ts` header). The signer refuses to start unless its verificationMethod is listed in the **live** DID document's `assertionMethod` and the private key derives to the published public key — a mis-keyed deployment fails at boot, not at verify time.

```
npm install && npm test
```
