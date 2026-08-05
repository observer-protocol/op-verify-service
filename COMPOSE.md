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

### `healthy` and `ready` are two questions, and this container answers them separately

**Resolved 2026-08-05. Supersedes the open question recorded on 2026-08-04**, which parked this on
the grounds that changing a health contract during a demo week is how a green container starts
flapping on someone else's DNS. The demo turned out to be the argument for the split rather than
against it: the cold-cache case IS what a viewer meets on their first run, and the recording exists
to send people to run it. A container that reports healthy while refusing every credential sends
that viewer to debug their credential.

Both readings were defensible, so neither was discarded. Each got its own endpoint:

| | `GET /health` | `GET /ready` |
|---|---|---|
| **Question** | is this process up | can this deployment do its job |
| **Codes** | always `200` while answering | `200` ready, `503` not ready |
| **Touches the network** | never | resolves every pinned issuer DID |
| **Body carries** | `liveness`, the two allowlists, `signingVm`, build stamp, and a **pointer** to `/ready` | `ready`, `degraded`, per-issuer state, the failure verbatim, and the probe's own limits |
| **Restart would help** | yes, if it fails | usually no: the fault is normally someone else's network |

`/health` keeps the "process is up" reading whole. It opens no socket to anyone else, so a third
party's outage never presents as ours. It does **not** compute a readiness verdict of its own: it
carries a pointer and a warning, because one question answered in two places is two answers.

`/ready` probes the **issuer allowlist**, which is the only DID set known before a request arrives.
The agent DID comes with the request and cannot be pre-checked; a mandate's proof cannot be checked
without resolving its issuer. So "can I reach my pinned issuers" is "can I verify anything at all".

Per-issuer states, all of which appear in the body:

- `fresh` — fetched live on this probe. The only state that proves reach.
- `cached` — refresh failed, served from cache inside the 24h limit. Ready, and **degraded**, with
  the engine's own cache-age note carried verbatim.
- `unreachable` — no network and no usable cache. **Not ready**, and the thrown error is included
  so the body names DNS, TLS, proxy or timeout rather than saying "not ready".
- `offline-override` — `OP_VERIFY_OFFLINE_DIDDOC` is set. Ready and **degraded**: the engine serves
  one document for *every* `did:web` it is asked about, so in this mode no `did:web` can ever be
  reported unreachable and readiness cannot detect the failure it exists to detect.
- `no-network-proof` — `did:key`, derived in memory. Ready and **degraded**: it can never fail, so
  it is never evidence that anything else would succeed. The key material is decoded at probe time,
  because `resolveDidKeyDocument` alone accepts `did:key:zzz` and only fails later at signature
  check — measured, not assumed.

`ready: true` with `degraded: true` means *resolvable*, not *reachable*. Do not read the first
without the second.

**The `HEALTHCHECK` now points at `/ready`,** so `docker ps` shows `unhealthy` on a cold cache and
`docker inspect` carries the probe body naming the issuer. The flapping objection does not apply to
this file: Docker does not restart a standalone container for being unhealthy, and
`restart: unless-stopped` acts on the process *exiting*, which does not happen here. So the state is
surfaced and the container is left running, which is the report-without-acting behaviour the parked
note wanted and could not get from one endpoint.

**Under an orchestrator that acts on health, that reasoning does not carry.** Swarm reschedules on
unhealthy and Kubernetes kills on a failed `livenessProbe`. There, point the liveness probe at
`/health` and the readiness probe at `/ready` — the split those systems already model, and the
reason both endpoints exist.

**What `/ready` does not cover**, printed in every response rather than only here: the agent DID in
a request is never probed, revocation status lists are fetched during verification and not by this
probe, and a resolvable issuer says nothing about whether any particular credential will verify.

The probe is memoised for 60s on success and 10s on failure, so a 30s healthcheck interval does not
put a live request on someone else's DID host twice a minute, and a recovery becomes visible fast.

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
