// LIVENESS AND READINESS ARE DIFFERENT QUESTIONS, AND THIS FILE ANSWERS ONLY THE SECOND.
//
// The question COMPOSE.md parked on 2026-08-04: a cold cache behind a blocked proxy produces a
// container that reports healthy and refuses every credential. Both readings of "healthy" were
// defensible, so the note recorded the question rather than picking. Picking it now, because a
// public demo is attached to this artifact and the first thing a viewer meets on their first run
// IS the cold-cache case. A viewer who is told to run it must not be told green while every
// credential is refused.
//
// The split, and what each one promises:
//
//   LIVENESS  (GET /health)  — this process is up and answering. It touches no network, so a
//                              third party's outage never looks like ours and a restart is never
//                              suggested for something a restart cannot fix. That was the whole
//                              force of the "process is up" reading, and it is preserved intact.
//
//   READINESS (GET /ready)   — this deployment can do its job: every issuer DID it is pinned to
//                              is resolvable, so a credential from a pinned issuer can actually
//                              be verified. That was the force of the "deployment can serve"
//                              reading, and it now has somewhere to live that is not /health.
//
// WHY THE ISSUER ALLOWLIST IS THE RIGHT PROBE. It is the only DID set known before a request
// arrives. The agent DID is supplied per request and cannot be pre-checked; the issuer allowlist
// is closed deployment config, and a mandate's proof cannot be checked without resolving its
// issuer. So "can I reach my pinned issuers" is exactly "can I verify anything at all", and it
// is answerable at probe time.
//
// NOT A VERIFICATION. This resolves DID documents. It does not check a credential, and a ready
// deployment can still refuse every credential you send it for reasons that are about the
// credential. Readiness is a claim about this deployment's reach, never about your artifact.

import { resolveDidDocument, resolveDidKeyDocument, decodeEd25519Multibase } from '@observer-protocol/policy-engine';

/** Matches the verification path's own staleness limit. A document good enough to verify with is
 * good enough to be ready on; two different limits would mean /ready could pass while the very
 * next verification refused on the same document, which is the failure this split exists to end. */
export const READINESS_MAX_STALENESS_HOURS = 24;

/** Shorter than verification's 5000ms. A probe runs on a schedule and must finish inside the
 * container healthcheck's timeout with room for more than one issuer; a verification runs once
 * for a caller who is waiting and can afford longer. */
export const READINESS_TIMEOUT_MS = 3000;

/** Serve a repeated probe from memory this long. The engine's fetch is refresh-first, so without
 * this every healthcheck interval would put a live request on someone else's DID host forever.
 * Success is held longer than failure so that RECOVERY becomes visible quickly while the steady
 * state stays quiet. */
export const READINESS_TTL_OK_MS = 60_000;
export const READINESS_TTL_FAIL_MS = 10_000;

export type IssuerState =
  /** Resolved over the network on this probe. The only state that proves live reach. */
  | 'fresh'
  /** Network refresh failed; served from a cache still inside the staleness limit. Verification
   * would also succeed right now, so this is ready — and degraded, and says so. */
  | 'cached'
  /** Unreachable with no usable cache. Every credential from this issuer WILL be refused. */
  | 'unreachable'
  /** did:web served from OP_VERIFY_OFFLINE_DIDDOC. Resolvable by construction; proves nothing
   * about network reach. */
  | 'offline-override'
  /** did:key, derived in-memory from the DID string itself. No network is involved, so this
   * issuer can never fail and can never be evidence that anything else would succeed. */
  | 'no-network-proof';

export interface IssuerReadiness {
  issuer: string;
  state: IssuerState;
  /** True only for states in which a credential from this issuer could be verified now. */
  resolvable: boolean;
  /** The engine's own disclosure, verbatim — cache age, refresh failure, limit. Never rewritten:
   * a reason paraphrased at the probe is a reason that can drift from the one verification gives. */
  note?: string;
  /** Present only on 'unreachable'. The failure as thrown, so the body names DNS, TLS, proxy or
   * timeout rather than a generic "not ready". */
  error?: string;
}

export interface ReadinessReport {
  ready: boolean;
  /** Ready, but on evidence weaker than a live fetch: cache, offline override, or did:key only.
   * A caller that treats ready as "everything is fine" is told here that it is not the same thing. */
  degraded: boolean;
  checkedAt: string;
  /** Why not ready, in one line, when ready is false. */
  reason?: string;
  issuers: IssuerReadiness[];
  limits: {
    maxStalenessHours: number;
    timeoutMs: number;
    /** WHAT THIS PROBE DOES NOT COVER, printed every run rather than documented once. */
    notCovered: string[];
  };
}

interface Memo { at: number; report: ReadinessReport }
let memo: Memo | undefined;

/** Reset the memo. Tests only: without it a probe result leaks across cases and the second
 * assertion passes on the first case's answer. */
export function resetReadinessCache(): void {
  memo = undefined;
}

async function probeIssuer(
  issuer: string,
  cfg: { cacheDir: string; offlineDidDocumentPath?: string },
): Promise<IssuerReadiness> {
  // did:key carries its key material in the DID string; the engine derives the document in memory
  // and never opens a socket. Reporting it as 'fresh' would let an allowlist of did:key issuers
  // report a fully ready deployment on a machine with no network at all.
  //
  // IT IS STILL DERIVED, NOT ASSUMED. A malformed did:key resolves for nobody, and treating any
  // string with the right prefix as resolvable would report a deployment ready on an issuer whose
  // every credential is refused — the same defect as the cold cache, reached by a typo in an env
  // file instead of by a proxy.
  //
  // resolveDidKeyDocument ALONE IS NOT ENOUGH, measured: it checks the multibase `z` prefix and
  // then echoes the string into a document, so `did:key:zzz` "resolves" and only fails later when
  // the key material is decoded to check a signature. Decoding here is what moves that failure
  // from verification time to probe time, which is the entire point of a readiness check.
  if (issuer.startsWith('did:key:')) {
    try {
      resolveDidKeyDocument(issuer);
      decodeEd25519Multibase(issuer.slice('did:key:'.length));
      return { issuer, state: 'no-network-proof', resolvable: true };
    } catch (e) {
      return {
        issuer,
        state: 'unreachable',
        resolvable: false,
        error: `malformed did:key, derives to no document: ${e instanceof Error ? e.message : String(e)}`,
      };
    }
  }
  try {
    const { note } = await resolveDidDocument(issuer, {
      cacheDir: cfg.cacheDir,
      timeoutMs: READINESS_TIMEOUT_MS,
      maxStalenessHours: READINESS_MAX_STALENESS_HOURS,
      ...(cfg.offlineDidDocumentPath ? { offlinePath: cfg.offlineDidDocumentPath } : {}),
    });
    // AN OFFLINE OVERRIDE APPLIES TO EVERY did:web, NOT TO THE ONE IT WAS WRITTEN FOR. The engine
    // takes a single document path and serves it for whatever did:web it is asked to resolve, so
    // in this mode NO did:web issuer can ever be reported unreachable and readiness stops being
    // able to detect the failure it exists to detect. That is why this is a state of its own and
    // why it forces `degraded`: the answer is "resolvable by configuration", never "reachable".
    if (cfg.offlineDidDocumentPath) {
      return { issuer, state: 'offline-override', resolvable: true, ...(note ? { note } : {}) };
    }
    // The engine attaches a note when it fell back to cache. Absence of a note is the only signal
    // that the refresh itself succeeded, so 'fresh' is claimed on absence and never on parsing.
    if (note) return { issuer, state: 'cached', resolvable: true, note };
    return { issuer, state: 'fresh', resolvable: true };
  } catch (e) {
    return {
      issuer,
      state: 'unreachable',
      resolvable: false,
      error: e instanceof Error ? e.message : String(e),
    };
  }
}

export async function assessReadiness(
  cfg: { issuerAllowlist: string[]; cacheDir: string; offlineDidDocumentPath?: string },
  opts: { nowMs?: number; force?: boolean } = {},
): Promise<ReadinessReport> {
  const now = opts.nowMs ?? Date.now();
  if (!opts.force && memo) {
    const ttl = memo.report.ready ? READINESS_TTL_OK_MS : READINESS_TTL_FAIL_MS;
    if (now - memo.at < ttl) return memo.report;
  }

  const notCovered = [
    'The agent DID in a request is not known before the request and is never probed here.',
    'Revocation status lists are fetched during verification, not by this probe.',
    'A resolvable issuer says nothing about whether any particular credential will verify.',
  ];

  // AN EMPTY ALLOWLIST IS NOT READY. It boots, it answers, and it refuses every mandate that
  // exists, because no issuer is accepted. Reporting that as ready would be the same defect this
  // split closes, one layer along.
  if (cfg.issuerAllowlist.length === 0) {
    const report: ReadinessReport = {
      ready: false,
      degraded: true,
      checkedAt: new Date(now).toISOString(),
      reason: 'issuer allowlist is empty: no issuer is accepted, so no mandate can verify',
      issuers: [],
      limits: { maxStalenessHours: READINESS_MAX_STALENESS_HOURS, timeoutMs: READINESS_TIMEOUT_MS, notCovered },
    };
    memo = { at: now, report };
    return report;
  }

  // Probed concurrently: sequential probes would multiply the timeout by the allowlist length and
  // turn a slow issuer into a probe that outlives the healthcheck's own timeout, which reports
  // not-ready for a reason that is about the probe rather than the deployment.
  const issuers = await Promise.all(cfg.issuerAllowlist.map((i) => probeIssuer(i, cfg)));

  const broken = issuers.filter((i) => !i.resolvable);
  const ready = broken.length === 0;
  const degraded = issuers.some((i) => i.state !== 'fresh');

  const report: ReadinessReport = {
    ready,
    degraded,
    checkedAt: new Date(now).toISOString(),
    ...(ready
      ? {}
      : {
          reason:
            `${broken.length} of ${issuers.length} pinned issuer DID document(s) unresolvable: ` +
            broken.map((b) => b.issuer).join(', ') +
            '. Credentials from these issuers will be refused.',
        }),
    issuers,
    limits: { maxStalenessHours: READINESS_MAX_STALENESS_HOURS, timeoutMs: READINESS_TIMEOUT_MS, notCovered },
  };
  memo = { at: now, report };
  return report;
}
