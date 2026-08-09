// THE FLOOR MUST BE A VALUE THE COMPARATOR CAN ORDER.
//
// `assertEngineFloor` refuses to start when `cmpVersion(installed, MIN_ENGINE_VERSION) < 0`, and
// `cmpVersion` prefers the engine's own exported `compareCoreVersion`. That comparator cannot
// compare prerelease identifiers: measured against 1.0.0-rc.10 on 2026-08-09,
// `compareCoreVersion('1.0.0-rc.2', '1.0.0-rc.10')` is 0, and so is
// `compareCoreVersion('1.0.0-rc.10', '1.0.0')`.
//
// So a floor set to any `1.0.0-rc.x` value makes every engine in the rc line compare EQUAL to it,
// `< 0` is never true, and the gate runs to completion while refusing nothing. It would still
// appear in the code, still execute on every boot, and still be worth nothing.
//
// The pin moved 0.3.3 -> 1.0.0-rc.10 on 2026-08-09 and raising the floor to match is the obvious
// next move. THIS TEST IS WHAT MAKES THE COMMENT AT THE CONSTANT A CONTROL RATHER THAN A NOTE:
// set MIN_ENGINE_VERSION to a prerelease and this fails, naming why.
//
// It binds to the EXPORTED constant and the EXPORTED comparator, not to copies. A test that
// restated either would keep passing after the real one changed.

import test from 'node:test';
import assert from 'node:assert/strict';
import { MIN_ENGINE_VERSION, cmpVersion } from '../dist/index.js';
import { assertDiscriminating } from './_discrimination-guard.mjs';

/**
 * The nearest version BELOW `v` in its own series: decrement the last numeric component that is
 * greater than zero. Derived from the floor rather than hardcoded, so this keeps testing the real
 * constant if it moves.
 *   '0.3.0'        -> '0.2.0'
 *   '1.0.0-rc.10'  -> '1.0.0-rc.9'
 */
function previousVersion(v) {
  const parts = v.split('.');
  for (let i = parts.length - 1; i >= 0; i--) {
    const m = /^(\D*)(\d+)$/.exec(parts[i]);
    if (m && Number(m[2]) > 0) {
      parts[i] = m[1] + String(Number(m[2]) - 1);
      return parts.join('.');
    }
  }
  return null;
}

test('engine floor: the comparator can order the configured floor', () => {
  const below = previousVersion(MIN_ENGINE_VERSION);
  assert.ok(below, `could not derive a version below ${MIN_ENGINE_VERSION}`);

  // THE WHOLE PROPERTY: the gate must be able to REFUSE. If the nearest version below the floor
  // does not compare as below it, there is no engine this gate rejects.
  assert.ok(
    cmpVersion(below, MIN_ENGINE_VERSION) < 0,
    `cmpVersion(${below}, ${MIN_ENGINE_VERSION}) is ${cmpVersion(below, MIN_ENGINE_VERSION)}, not < 0. ` +
      `The floor is set to a value this comparator cannot order, so assertEngineFloor refuses ` +
      `NOTHING and the interlock is disarmed while still appearing to run. The engine's ` +
      `compareCoreVersion ignores prerelease identifiers, so a 1.0.0-rc.x floor has exactly this ` +
      `effect. Fix the comparator in the engine before moving this constant.`,
  );

  // ...and be able to ACCEPT, so the assertion above is not passing because everything is < 0.
  assert.ok(
    cmpVersion(MIN_ENGINE_VERSION, below) > 0,
    `cmpVersion(${MIN_ENGINE_VERSION}, ${below}) is not > 0 — the comparator is not antisymmetric here`,
  );
  assert.equal(cmpVersion(MIN_ENGINE_VERSION, MIN_ENGINE_VERSION), 0);

  // A harness that answers the same thing three times has not measured an ordering.
  assertDiscriminating(
    [
      { name: `below < floor`, verdict: String(cmpVersion(below, MIN_ENGINE_VERSION)) },
      { name: `floor > below`, verdict: String(cmpVersion(MIN_ENGINE_VERSION, below)) },
      { name: `floor = floor`, verdict: String(cmpVersion(MIN_ENGINE_VERSION, MIN_ENGINE_VERSION)) },
    ],
    { requireVerdicts: ['-1', '0', '1'], axis: 'version ordering' },
  );
});

test('engine floor: the defect this guards is real, so the guard is not theoretical', () => {
  // The negative control. If a future engine fixes compareCoreVersion, THIS test fails and the
  // constraint above can be relaxed deliberately rather than discovered by accident. Recording the
  // defect as an assertion is what stops it being repaired silently and the floor rule outliving
  // its reason.
  assert.equal(
    cmpVersion('1.0.0-rc.2', '1.0.0-rc.10'),
    0,
    'compareCoreVersion now orders prereleases. The DO-NOT-RAISE constraint on MIN_ENGINE_VERSION ' +
      'was written against a comparator that could not, and can be revisited — deliberately, with ' +
      'the comment at the constant updated in the same change.',
  );
});
