// The verification pipeline: identity -> mandate -> (optional) scope, each
// component fail-closed with a named reason, composed ENTIRELY from the
// public @observer-protocol/policy-engine. This is the point of the design:
// the hosted endpoint runs exactly the code path a relying party could run
// themselves from npm — hosting is a convenience, never a trust requirement.
//
// Verification only. This service holds no funds, no payment keys, and no
// custody of anything; it verifies public material and signs its answers.

import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  enforceMandate,
  parseConfig,
  resolveDidDocument,
  verifyCredential,
} from '@observer-protocol/policy-engine';
import type { ObserverDelegationCredential, PolicyContext, ResolvedTransfer, VerifierConfig } from '@observer-protocol/policy-engine';

/**
 * The largest fraction this service will scale. A bound, not a currency opinion.
 *
 * There is no minor-unit table here any more, and its removal is the fix for a real defect rather
 * than a simplification. WHAT THE TABLE WAS: fourteen ISO-4217 currencies, with an unlisted
 * currency failing closed. Every USDC proposal therefore returned `inScope: false` regardless of
 * amount, which is a check that does not vary with the input it claims to be about.
 *
 * WHY REPLACING IT DOES NOT WIDEN ANYTHING. The exponent is a representation detail that cancels:
 * the scaled amount and the rail's `decimals` move together, and the engine compares a notional
 * against the mandate's cap. Measured 2026-08-09 against a USDC-denominated mandate capped at 10,
 * at exponents 2, 6 and 18: 1.00, 9.99 and 10.00 allow at every exponent; 10.01 and 1000000.00 deny
 * at every exponent. The exponent changed no verdict. Its only effect was which amounts were
 * REPRESENTABLE — at exponent 2, "0.000001" was rejected as over-precise and that rejection was
 * reported as `inScope: false`.
 *
 * So the table never carried authority. It decided which currencies got evaluated at all, and it
 * decided that by a list that could not be right: USDC is not ISO-4217 and never will be, and
 * USDT's decimals are chain-dependent (6 on Ethereum and Tron, 18 on BSC), so no single entry for
 * it would be correct everywhere. Deriving the exponent from the amount the caller actually wrote
 * removes the question instead of answering it wrongly.
 *
 * A proposal in a currency the MANDATE does not authorise is still refused, and by the component
 * that should refuse it: the engine's same-currency invariant, which denies a USDC transfer against
 * a USD-denominated cap because no FX conversion is performed. That refusal is the mandate talking.
 * The old one was a gap in a lookup table talking.
 */
export const MAX_AMOUNT_EXPONENT = 30;

/**
 * The number of decimal places an amount string carries, or null if it is not a plain
 * non-negative decimal. Deliberately strict: no sign, no exponent notation, no separators,
 * no whitespace beyond the trim. An amount this cannot read is not scaled to something
 * plausible, it is refused as unevaluated.
 */
export function amountExponent(amount: string): number | null {
  if (typeof amount !== 'string') return null;
  const m = /^(\d+)(?:\.(\d+))?$/.exec(amount.trim());
  if (!m) return null;
  const frac = (m[2] ?? '').length;
  return frac <= MAX_AMOUNT_EXPONENT ? frac : null;
}

export interface VerifyRequest {
  /** The agent's DID (did:web or did:key). */
  agentDid: string;
  /** The agent's signed delegation credential, as received from the agent. */
  mandate: Record<string, unknown>;
  /** Optional in-context check: is THIS action within the mandate's scope? */
  proposal?: {
    counterparty: string;
    /** Decimal string in `currency` main units, e.g. "125.50". */
    amount: string;
    currency: string;
  };
  /** Optional opaque correlation context, echoed verbatim into the signed
   * response so an external record (e.g. an observability trace id) binds
   * cryptographically into this verdict. Never interpreted or trusted; the
   * server size-caps it. Additive and backward-compatible: absent unless the
   * caller sends it. */
  context?: Record<string, unknown>;
}

export interface ComponentResult {
  valid: boolean;
  reason?: string;
  notes?: string[];
}

export interface VerifyOutcome {
  agentDid: string;
  identity: ComponentResult;
  mandate: ComponentResult & { id?: string; issuer?: string; validUntil?: string };
  /** Present only when a proposal was submitted AND the mandate verified.
   *
   * `evaluated` EXISTS BECAUSE `inScope: false` WAS CARRYING TWO DIFFERENT FACTS. It meant both
   * "the mandate's rules were applied to this proposal and it is outside them" and "this proposal
   * never reached the mandate's rules", and a caller reading the boolean could not tell which. The
   * second is not a statement about the proposal at all. Read `inScope: false` with
   * `evaluated: false` as "not evaluated", never as "out of scope".
   *
   * `evaluated` is true exactly when `enforceMandate` ran and returned a verdict. It is a claim
   * about THIS service reaching the engine, not a re-interpretation of what the engine then said:
   * when the engine declines to establish scope (its same-currency invariant, for instance) it says
   * so in `reason`, and that refusal is the mandate's answer rather than a gap in this service.
   *
   * Additive and backward-compatible: the field is new, `inScope` is unchanged, and both are
   * covered by the response proof. */
  scope?: { inScope: boolean; evaluated: boolean; reason?: string; notes?: string[] };
  verifiedAt: string;
  /** Present only when the request carried `context`: the caller's opaque
   * correlation object, echoed verbatim and covered by the response proof. */
  context?: Record<string, unknown>;
}

export interface VerifyCoreConfig {
  /** Issuer DIDs this deployment accepts mandates from. Closed list. */
  issuerAllowlist: string[];
  /** credentialSchema ids accepted (frozen schema URLs). Closed list. */
  schemaAllowlist: string[];
  cacheDir: string;
  /** Offline DID-document override for air-gapped tests. */
  offlineDidDocumentPath?: string;
  nowMs?: number;
}

/** Scale a decimal amount string to raw minor units. Null on malformed or
 * over-precise input (fail closed upstream). */
export function decimalToRaw(amount: string, exponent: number): bigint | null {
  const m = /^(\d+)(?:\.(\d+))?$/.exec(amount.trim());
  if (!m) return null;
  const frac = m[2] ?? '';
  if (frac.length > exponent) return null;
  try {
    return BigInt(m[1] ?? '0') * 10n ** BigInt(exponent) + BigInt(frac.padEnd(exponent, '0') || '0');
  } catch {
    return null;
  }
}

export async function runVerification(cfg: VerifyCoreConfig, req: VerifyRequest): Promise<VerifyOutcome> {
  const nowMs = cfg.nowMs ?? Date.now();
  const verifiedAt = new Date(nowMs).toISOString();
  const out: VerifyOutcome = {
    agentDid: req.agentDid,
    identity: { valid: false },
    mandate: { valid: false },
    verifiedAt,
  };
  // Echo the caller's opaque correlation context onto every outcome (allow or
  // deny), so the verdict the caller receives -- and its signature -- carries
  // it. Set before any early return so fail-closed verdicts carry it too.
  if (req.context !== undefined) out.context = req.context;

  // ---- 1. Identity: the DID must resolve publicly, and the mandate must be
  // bound to exactly this DID. (Key-control proof is the challenge-response
  // flow on the main API; this component is resolution + binding.)
  try {
    if (typeof req.agentDid !== 'string' || !req.agentDid.startsWith('did:')) {
      out.identity = { valid: false, reason: 'agentDid is not a DID' };
    } else {
      const { doc } = await resolveDidDocument(req.agentDid, {
        cacheDir: cfg.cacheDir,
        timeoutMs: 5000,
        maxStalenessHours: 24,
        ...(cfg.offlineDidDocumentPath ? { offlinePath: cfg.offlineDidDocumentPath } : {}),
      });
      const subject = (req.mandate?.credentialSubject as { id?: unknown } | undefined)?.id;
      if ((doc.verificationMethod ?? []).length === 0) {
        out.identity = { valid: false, reason: 'agent DID document carries no verification methods' };
      } else if (subject !== req.agentDid) {
        out.identity = { valid: false, reason: `mandate subject ${JSON.stringify(subject)} is not bound to agentDid ${req.agentDid}` };
      } else {
        out.identity = { valid: true, notes: ['DID resolved publicly; mandate subject binds to this DID'] };
      }
    }
  } catch (err) {
    out.identity = { valid: false, reason: `agent DID did not resolve: ${(err as Error).message}` };
  }

  // ---- 2. Mandate: the full engine pipeline (pinned issuer, structure,
  // validity window, eddsa-jcs-2022 proof against the issuer DID document's
  // assertionMethod, revocation). The engine reads the credential from a
  // file path, so the request body goes to a per-request 0600 temp file —
  // deliberately reusing the audited pipeline instead of re-implementing it.
  const issuer = (req.mandate as { issuer?: unknown })?.issuer;
  if (typeof issuer !== 'string' || !cfg.issuerAllowlist.includes(issuer)) {
    out.mandate = { valid: false, reason: `mandate issuer ${JSON.stringify(issuer)} is not in this deployment's issuer allowlist — refusing (fail closed)` };
    return out;
  }
  const dir = mkdtempSync(join(tmpdir(), 'opverify-'));
  let cred: ObserverDelegationCredential | undefined;
  try {
    const credPath = join(dir, 'mandate.json');
    writeFileSync(credPath, JSON.stringify(req.mandate), { mode: 0o600 });
    const config: VerifierConfig = parseConfig({
      credentialPath: credPath,
      issuerDid: issuer,
      agentDid: req.agentDid,
      schemaAllowlist: cfg.schemaAllowlist,
      cacheDir: cfg.cacheDir,
      // Point the engine's audit sink at the per-request temp dir, which is
      // removed in the finally below. There is deliberately NO persistent
      // decisions log: nothing about a caller's mandate survives the request.
      auditLog: join(dir, 'audit.jsonl'),
      rails: {},
      ...(cfg.offlineDidDocumentPath ? { offline: { didDocumentPath: cfg.offlineDidDocumentPath } } : {}),
    });
    const verdict = await verifyCredential(config, nowMs);
    if (!verdict.allow || !verdict.cred) {
      out.mandate = { valid: false, reason: verdict.reason ?? 'mandate did not verify', notes: verdict.notes };
      return out;
    }
    cred = verdict.cred;
    out.mandate = {
      valid: true,
      notes: verdict.notes,
      id: String((req.mandate as { id?: unknown }).id ?? ''),
      issuer,
      validUntil: String((req.mandate as { validUntil?: unknown }).validUntil ?? ''),
    };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }

  // ---- 3. Scope (only with a proposal, only on a valid mandate): the same
  // enforceMandate every OP engine runs. Stateless deployment note: this
  // endpoint carries no spend counters, so velocity/cross-rail-budget
  // mandates fail closed here with a reason naming that — a counter we do
  // not have is never treated as zero.
  if (req.proposal && cred) {
    const { counterparty, amount, currency } = req.proposal;
    // EVERY REFUSAL BEFORE enforceMandate CARRIES evaluated:false. These are the paths on which
    // the mandate's rules were never applied, so a `false` here is not a statement about the
    // proposal being outside the mandate. It is this service saying it could not ask.
    if (typeof counterparty !== 'string' || counterparty.length === 0) {
      out.scope = { inScope: false, evaluated: false, reason: 'proposal carries no counterparty — not evaluated' };
      return out;
    }
    if (typeof currency !== 'string' || currency.length === 0) {
      out.scope = { inScope: false, evaluated: false, reason: 'proposal carries no currency — not evaluated' };
      return out;
    }
    // The exponent comes from the amount the caller wrote, not from a table of currencies. See
    // MAX_AMOUNT_EXPONENT above for why that is a removal of a wrong mechanism rather than a
    // loosening: measured, the exponent changes no verdict.
    const exp = amountExponent(amount);
    if (exp === null) {
      out.scope = {
        inScope: false,
        evaluated: false,
        reason:
          `amount ${JSON.stringify(amount)} is not a plain non-negative decimal with at most ` +
          `${MAX_AMOUNT_EXPONENT} decimal places — not evaluated (fail closed)`,
      };
      return out;
    }
    const raw = decimalToRaw(amount, exp);
    if (raw === null) {
      // Unreachable via amountExponent, which has already accepted the shape. Kept because a
      // fail-closed branch that cannot be reached is cheaper than a null that reaches BigInt.
      out.scope = { inScope: false, evaluated: false, reason: `amount ${JSON.stringify(amount)} could not be scaled — not evaluated (fail closed)` };
      return out;
    }
    const railId = 'hosted-verify';
    const config = {
      rails: { [railId]: { rail: railId, currency, decimals: exp, family: 'other' } },
      allowContractCalls: false,
    } as unknown as VerifierConfig;
    const resolved: ResolvedTransfer = {
      kind: 'native',
      assetSymbol: currency,
      amount: raw,
      decimals: exp,
      recipient: counterparty,
      recipientKind: 'wallet',
      notes: [],
    };
    const ctx: PolicyContext = {
      chain_id: railId,
      wallet_id: req.agentDid,
      api_key_id: 'hosted-verify',
      transaction: { to: counterparty },
      timestamp: verifiedAt,
    };
    const verdict = enforceMandate(ctx, cred, config, resolved);
    // The engine ran and answered, so the mandate's rules WERE applied. Whatever it decided,
    // including a refusal to establish scope across currencies, is the mandate's answer and is
    // carried through verbatim in `reason`.
    out.scope = {
      inScope: verdict.allow,
      evaluated: true,
      ...(verdict.reason ? { reason: verdict.reason } : {}),
      notes: [
        // NAME THE ASSUMPTION IN THE ANSWER. The exponent is derived from the caller's own amount,
        // and a caller comparing two verdicts should be able to see that rather than infer it.
        `amount scaled at 10^${exp}, derived from the ${exp} decimal place(s) in ${JSON.stringify(amount)}`,
        ...(verdict.notes ?? []),
      ],
    };
  }
  return out;
}
