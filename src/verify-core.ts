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

/** ISO-4217 minor-unit exponents. Unlisted currency -> fail closed. */
export const ISO4217_EXPONENT: Record<string, number> = {
  USD: 2, EUR: 2, GBP: 2, CHF: 2, CAD: 2, AUD: 2, MXN: 2, BRL: 2, SGD: 2, HKD: 2,
  JPY: 0, KRW: 0, BHD: 3, KWD: 3,
};

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
  /** Present only when a proposal was submitted AND the mandate verified. */
  scope?: { inScope: boolean; reason?: string; notes?: string[] };
  verifiedAt: string;
}

export interface VerifyCoreConfig {
  /** Issuer DIDs this deployment accepts mandates from. Closed list. */
  issuerAllowlist: string[];
  /** credentialSchema ids accepted (frozen schema URLs). Closed list. */
  schemaAllowlist: string[];
  cacheDir: string;
  auditLog: string;
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
      auditLog: cfg.auditLog,
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
    const exp = ISO4217_EXPONENT[currency];
    if (typeof counterparty !== 'string' || counterparty.length === 0) {
      out.scope = { inScope: false, reason: 'proposal carries no counterparty' };
      return out;
    }
    if (exp === undefined) {
      out.scope = { inScope: false, reason: `currency ${JSON.stringify(currency)} has no known minor-unit exponent — amount cannot be scaled (fail closed)` };
      return out;
    }
    const raw = decimalToRaw(amount, exp);
    if (raw === null) {
      out.scope = { inScope: false, reason: `amount ${JSON.stringify(amount)} is not a valid ${currency} decimal (fail closed)` };
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
    out.scope = { inScope: verdict.allow, ...(verdict.reason ? { reason: verdict.reason } : {}), notes: verdict.notes };
  }
  return out;
}
