# Run the verifier yourself

Two commands, no account, no API key, no Observer key material.

```bash
docker compose up --build
./compose-smoke.sh
```

That works. From inside a git checkout, prefer this form, which stamps the image with the commit it
was built from — `docker compose up --build` alone leaves `GET /version` reporting `commit: unknown`,
because there is no git inside the image and nothing has told it otherwise:

```bash
OP_BUILD_COMMIT=$(git rev-parse HEAD) \
OP_BUILD_BRANCH=$(git rev-parse --abbrev-ref HEAD) \
OP_BUILD_DIRTY=$(git diff --quiet HEAD && echo clean || echo dirty) \
docker compose up --build
```

The smoke test exits non-zero if anything is wrong, so it is a gate rather than something you read
and interpret.

## What you get

A verifier you control, checking Observer Protocol delegation credentials against the **live public
schemas** — the same frozen URLs, the same issuer DID documents, the same static revocation lists
that `verify.observerprotocol.org` uses. Nothing in the loop is private, which is the point: you can
run this and get the same answer without asking us for anything.

## Verdicts are signed by YOUR key, not ours

The service signs every verdict, and refuses to start unless its signing key is listed in the
`assertionMethod` of the DID it claims. Observer's `#key-7` private key lives on the hosted
deployment and is not shipped — a container anyone can run must not be able to sign as Observer.

So the entrypoint generates a `did:key` on first run. It is self-describing, so the boot keystate
check passes with no network call and nothing from us.

**What that means for a verdict from this container:** it is evidence that *your* engine reached
that conclusion. It is not an Observer attestation. If you need a verdict a third party will accept
as Observer's, ask `verify.observerprotocol.org`, which signs with a key published in Observer's DID
document. The service prints this at every boot rather than leaving it to be discovered.

The signing identity is kept in a named volume so it survives `compose down`. Remove the volume and
the next start generates a new identity, and verdicts you kept will no longer verify against the key
the service advertises.

## Configuration

Everything is in `compose.yaml` and every value resolves publicly today.

| variable | what it decides |
|---|---|
| `OP_VERIFY_ISSUER_ALLOWLIST` | which issuers this deployment will accept a mandate from |
| `OP_VERIFY_SCHEMA_ALLOWLIST` | which credential schema versions it understands |
| `OP_VERIFY_PORT` | host port, default 8091 |

**Pin the issuers.** A verifier that accepts whoever the credential names as its issuer is not
verifying, it is agreeing. The shipped list includes `did:web:bitcoinsingularity.ai` because the
sample credential is issued by it, and it is *not* Observer Protocol — which is exactly why the
issuer is pinned rather than read out of the credential being checked.

## What it needs from the network

Measured on a running container, not inferred. After verifying both sample credentials the cache
held exactly two documents, and they are the only things it fetched:

| fetched at run time | why |
|---|---|
| `https://bitcoinsingularity.ai/.well-known/did.json` | the **issuer's** DID document, to get the key the proof names |
| `https://observerprotocol.org/agents/maxi-0001/did.json` | the **subject's** DID document, to bind the mandate to the agent |

**The schema URLs are never fetched.** `OP_VERIFY_SCHEMA_ALLOWLIST` is compared as a string, so a
blocked `observerprotocol.org/schemas/...` costs you nothing.

**Revocation status lists are fetched only when a credential carries a `credentialStatus` entry.**
Neither sample does, and the verdict says so in `notes`. A credential that does carry one adds its
status-list URL to the list above.

Build time additionally needs `registry.npmjs.org`. Nothing else, ever — no Observer API, no
telemetry, no licence check.

### Behind a proxy that blocks those hosts

Also measured, by pointing both DID hosts at a dead address:

- **The service still starts.** `GET /health` answers 200. The failure appears at verification time,
  not at boot, so "the container is up" is not evidence that it can verify.
- **Cold cache: it fails closed and says why.** `mandate.valid: false`, reason
  `[proof] unreachable (fetch failed) and no cached copy exists`. It does not guess and it does not
  pass.
- **Warm cache: it verifies, and discloses that it did so from cache.** The verdict carries
  `refresh of https://... failed (fetch failed); served from cache aged 0.0h (limit 24h)`. Past that
  24h staleness limit the cached answer stops being used — that limit is configuration, and this
  paragraph is the only claim here I have not run a clock forward to observe.

So the realistic first failure behind a corporate proxy is a **cold** container that boots healthy
and then refuses every credential. Allowlist the two DID-document hosts above and it works.

- **No issuance.** Nothing from `observer-protocol-api` or `op-mcp-payment-server` is present, so
  there is no issuance capability to disable — it was never compiled in.
- **No authentication.** `POST /v1/verify` is open. It takes an artifact as input and retrieves
  nothing: there is no lookup by identifier, so a caller can only check a credential it already
  holds. A token would gate a check anyone can already run offline from the npm package.
- **No funds, no keys but its own, no persistence of anything you send it.** Request bodies,
  mandates and verdicts are never written to a persistent log.

## What the smoke test does and does not cover

It checks a credential that **must** verify and one that **must** be refused, and fails if either
answer is wrong — a test that only proves the happy path cannot tell a working verifier from one
that says yes to everything.

Step 4 runs `examples/verify-a-credential/` from
[`op-policy-engine`](https://github.com/observer-protocol/op-policy-engine) pointed at your
container, so the endpoint you are running is checked against the engine you can audit on npm. That
step **skips loudly** if that repo is not a sibling checkout: steps 1-3 test this container only and
do not establish that it agrees with the published engine.

One limit worth knowing: that cross-check compares verdicts, not reasons. Two verifiers can both
refuse a credential for different reasons and still be reported as agreeing.

## Provenance

`GET /version` reports the commit the bundle was built from, the engine it was built against, and
the engine it is actually running. There is no git inside the image, so `compose.yaml` passes the
commit in as a build arg; build outside a checkout and it honestly reports `unknown` rather than
guessing. Git wins wherever both are available, because the env var is a claim and git is a fact.
