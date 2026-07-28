// Tests for the discrimination guard.
//
// A guard needs its own negative control, or it is exactly the thing it warns about:
// a check that has never been observed to fire. Every test below is paired — one that
// must throw, one that must not — so the suite proves the guard DISCRIMINATES rather
// than proving it is merely silent.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  assertDiscriminating,
  assertOperandsDistinct,
  NonDiscriminatingHarness,
} from './_discrimination-guard.mjs';

const R = (name, verdict) => ({ name, verdict });

test('uniform verdicts FAIL — the 0.2.0-vs-0.3.3 convergence shape', () => {
  assert.throws(
    () => assertDiscriminating([R('a', 'ALLOW'), R('b', 'ALLOW'), R('c', 'ALLOW')], { axis: 'engine version' }),
    NonDiscriminatingHarness,
  );
});

test('uniform FAILURE also fails — the AbortError shape (uniformity, not polarity)', () => {
  // The resolver probe returned the same error for every case. A guard that only
  // distrusted uniform PASSES would have let this through.
  assert.throws(
    () => assertDiscriminating([R('did:web:a', 'ERROR'), R('did:web:b', 'ERROR')]),
    NonDiscriminatingHarness,
  );
});

test('mixed verdicts pass', () => {
  const { distinct, counts } = assertDiscriminating([R('a', 'ALLOW'), R('b', 'DENY')]);
  assert.deepEqual(distinct.sort(), ['ALLOW', 'DENY']);
  assert.equal(counts.ALLOW, 1);
});

test('a single case cannot discriminate', () => {
  assert.throws(() => assertDiscriminating([R('only', 'ALLOW')]), NonDiscriminatingHarness);
  assert.throws(() => assertDiscriminating([]), NonDiscriminatingHarness);
});

test('requireVerdicts is stronger than "at least two distinct"', () => {
  // Two distinct verdicts, but not the two that were expected: the bare guard would
  // pass this and the harness would still not be measuring what it claims.
  const results = [R('a', 'ERROR'), R('b', 'TIMEOUT')];
  assert.doesNotThrow(() => assertDiscriminating(results));
  assert.throws(
    () => assertDiscriminating(results, { requireVerdicts: ['ALLOW', 'DENY'] }),
    NonDiscriminatingHarness,
  );
});

test('requireVerdicts passes when every named verdict appears', () => {
  assert.doesNotThrow(() =>
    assertDiscriminating([R('a', 'ALLOW'), R('b', 'DENY'), R('c', 'DENY')], {
      requireVerdicts: ['ALLOW', 'DENY'],
    }),
  );
});

test('LIMIT, asserted so it cannot be quietly forgotten: a legitimately uniform set', () => {
  // A fail-closed inventory SHOULD be all-deny. The bare guard misfires here, which is
  // why requireVerdicts exists and why the guard is opt-in per result set. This test
  // exists to keep that boundary visible in the suite, not only in a comment.
  const failClosedInventory = [R('wrong key', 'DENY'), R('expired', 'DENY'), R('tampered', 'DENY')];
  assert.throws(() => assertDiscriminating(failClosedInventory), NonDiscriminatingHarness);
  assert.doesNotThrow(() => assertDiscriminating(failClosedInventory, { requireVerdicts: ['DENY'] }));
});

test('operands: byte-identical paths FAIL — a comparison needs distinct things', () => {
  assert.throws(
    () =>
      assertOperandsDistinct([
        { label: '0.2.0', declared: '0.2.0', fingerprint: 'abc' },
        { label: '0.3.3', declared: '0.3.3', fingerprint: 'abc' },
      ]),
    NonDiscriminatingHarness,
  );
});

test('operands: a mislabelled operand FAILS even when all are distinct', () => {
  // Distinctness alone is insufficient — this is the half self-declaration catches.
  assert.throws(
    () =>
      assertOperandsDistinct([
        { label: '0.2.0', declared: '0.3.3', fingerprint: 'aaa' },
        { label: '0.3.3', declared: '0.3.3', fingerprint: 'bbb' },
      ]),
    NonDiscriminatingHarness,
  );
});

test('operands: distinct and correctly declared passes', () => {
  assert.doesNotThrow(() =>
    assertOperandsDistinct([
      { label: '0.2.0', declared: '0.2.0', fingerprint: 'aaa' },
      { label: '0.3.3', declared: '0.3.3', fingerprint: 'bbb' },
    ]),
  );
});
