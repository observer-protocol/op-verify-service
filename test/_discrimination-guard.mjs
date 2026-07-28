// Discrimination guard — a harness must prove it can produce more than one answer
// before any of its answers are worth reading.
//
// WHY THIS EXISTS (2026-07-28, two failures in one day):
//
//   1. A resolver probe returned the same AbortError for every DID it tried, because
//      it passed `fetchTimeoutMs` to a function that takes `timeoutMs` — the unknown
//      option was undefined, so the AbortController fired at 0ms. Uniform failure was
//      read as "resolution is broken." It was "the harness is not measuring."
//   2. A version-comparison probe reported five engine versions agreeing, because a
//      concurrent session had upgraded one operand's node_modules under it and two
//      paths had converged on the same bytes. Uniform agreement was read as "no
//      behavioural delta."
//
// Both are the same shape: EVERY CASE RETURNED THE SAME VERDICT, and that uniformity
// was reported as a finding rather than as a broken harness.
//
// The rule: a negative control proves a harness CAN produce the other answer. This
// makes producing the other answer a PRECONDITION OF REPORTING AT ALL.
//
// ─── THE LIMIT OF THIS GUARD — read before trusting it ──────────────────────────
//
// It catches a harness measuring NOTHING. It does NOT catch a harness measuring the
// WRONG THING discriminatingly. A probe that confidently separates two cases on an
// irrelevant axis passes this guard cleanly, and nothing here will tell you.
//
// Nor does it apply to every result set. A fail-closed inventory is LEGITIMATELY
// uniform — every case denies, and that is the point. Applying the bare guard there
// would misfire. Use `requireVerdicts` whenever the expected verdicts are known, and
// apply the guard only to sets whose PURPOSE is to distinguish.
//
// A guard whose boundary is undocumented gets read as stronger than it is. That
// sentence is the reason this comment block is longer than the code.
// ────────────────────────────────────────────────────────────────────────────────

export class NonDiscriminatingHarness extends Error {
  constructor(message, detail) {
    super(message);
    this.name = 'NonDiscriminatingHarness';
    this.detail = detail;
  }
}

/**
 * @param {Array<{name: string, verdict: string}>} results
 * @param {{ requireVerdicts?: string[], axis?: string }} [opts]
 *   requireVerdicts — every listed verdict MUST appear at least once. Prefer this
 *                     whenever you know what the set should contain: it is strictly
 *                     stronger than "at least two distinct".
 *   axis           — human label for what is being distinguished, used in the error.
 * @returns {{ distinct: string[], counts: Record<string, number> }}
 * @throws {NonDiscriminatingHarness} before any caller can print a result.
 */
export function assertDiscriminating(results, opts = {}) {
  const axis = opts.axis ? ` on ${opts.axis}` : '';

  if (!Array.isArray(results) || results.length < 2) {
    throw new NonDiscriminatingHarness(
      `harness ran ${Array.isArray(results) ? results.length : 0} case(s)${axis}: ` +
        `a single case cannot discriminate, so its verdict is not evidence`,
      { results },
    );
  }

  const counts = {};
  for (const r of results) counts[r.verdict] = (counts[r.verdict] ?? 0) + 1;
  const distinct = Object.keys(counts);

  if (opts.requireVerdicts?.length) {
    const missing = opts.requireVerdicts.filter((v) => !(v in counts));
    if (missing.length) {
      throw new NonDiscriminatingHarness(
        `harness never produced ${missing.join(', ')}${axis} — every case returned ` +
          `${distinct.join('/')}. The harness is not measuring what it claims; ` +
          `fix the harness before reading any verdict from this run.`,
        { counts, missing },
      );
    }
    return { distinct, counts };
  }

  if (distinct.length < 2) {
    throw new NonDiscriminatingHarness(
      `all ${results.length} cases returned ${distinct[0]}${axis}. A run in which every ` +
        `case returns the same verdict FAILS as non-discriminating, regardless of what ` +
        `that verdict is — uniformity is what a broken harness produces by default.`,
      { counts },
    );
  }

  return { distinct, counts };
}

/**
 * Operand-distinctness guard, for probes that COMPARE things (versions, builds,
 * environments, prod-vs-repo, vendored-vs-source).
 *
 * A comparison is only a comparison if the things compared are distinct. Under
 * concurrent editing you cannot assume they are: a path is a location, not an
 * identity, and another session can converge two of them without telling you.
 *
 * Both assertions are required and neither is sufficient alone:
 *   - self-declaration alone passes when two paths both CORRECTLY declare the same
 *     version (exactly the 2026-07-28 failure);
 *   - distinctness alone passes when two genuinely different builds are mislabelled.
 *
 * @param {Array<{label: string, declared?: string, fingerprint: string}>} operands
 * @throws {NonDiscriminatingHarness} before any comparison result is produced.
 */
export function assertOperandsDistinct(operands) {
  const seen = new Map();
  for (const o of operands) {
    if (o.declared !== undefined && o.declared !== o.label) {
      throw new NonDiscriminatingHarness(
        `operand "${o.label}" declares itself as "${o.declared}" — it is not the thing ` +
          `it is being compared as`,
        { operand: o },
      );
    }
    if (seen.has(o.fingerprint)) {
      throw new NonDiscriminatingHarness(
        `operands "${o.label}" and "${seen.get(o.fingerprint)}" are byte-identical: ` +
          `this is not a comparison, and any agreement it reports was never measured`,
        { a: o.label, b: seen.get(o.fingerprint), fingerprint: o.fingerprint },
      );
    }
    seen.set(o.fingerprint, o.label);
  }
  return { count: operands.length };
}
