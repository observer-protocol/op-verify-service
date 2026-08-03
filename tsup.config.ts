import { defineConfig } from 'tsup';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

/** A build-time fact, or the string that says we could not establish it.
 *
 * "unknown" IS A FAILURE STATE, NOT A PASS — the same rule `assertEngineFloor` already applies to the
 * engine version. A stamp that quietly reports an empty string is worse than no stamp: it looks
 * answered. Anything that cannot be established says so, in the artifact, forever.
 */
const shell = (cmd: string, args: string[]): string => {
  try {
    return execFileSync(cmd, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim() || 'unknown';
  } catch {
    return 'unknown';
  }
};

// ─── STAMPED AT BUILD TIME, NOT AT DEPLOY TIME ──────────────────────────────────────────────────
//
// A deploy-time stamp drifts the moment someone copies a file, and that is not hypothetical: this
// service's PROVENANCE named a commit three days older than the bytes that were running, because a
// partial overlay updated the files and not the file that described them.
//
// Embedded in the BUNDLE means the artifact carries its own identity. Copy it anywhere, and it still
// says what it is.
const COMMIT = shell('git', ['rev-parse', 'HEAD']);
const BRANCH = shell('git', ['rev-parse', '--abbrev-ref', 'HEAD']);
const DIRTY = shell('git', ['status', '--porcelain']) !== 'unknown'
  && shell('git', ['status', '--porcelain']).length > 0;
const BUILT_AT = new Date().toISOString();

/** The engine the bundle was BUILT against. `installedEngineVersion()` reports the one it RUNS
 * against, and the two can differ — a dist copied onto a box whose node_modules moved underneath it.
 * Capturing both is what makes that visible; capturing one makes it invisible. */
const ENGINE = (() => {
  try {
    const pkg = JSON.parse(readFileSync('node_modules/@observer-protocol/policy-engine/package.json', 'utf8'));
    return String(pkg.version ?? 'unknown');
  } catch {
    return 'unknown';
  }
})();

export default defineConfig({
  entry: ['src/index.ts', 'src/server.ts'],
  format: ['esm', 'cjs'],
  dts: true,
  clean: true,
  sourcemap: true,
  target: 'es2022',
  define: {
    __BUILD_COMMIT__: JSON.stringify(COMMIT),
    __BUILD_BRANCH__: JSON.stringify(BRANCH),
    // A DIRTY TREE IS PART OF THE IDENTITY. A commit hash alone says which commit was checked out,
    // not that the bytes match it — and "built from uncommitted changes" is exactly the state
    // nobody can reproduce later.
    __BUILD_DIRTY__: JSON.stringify(DIRTY),
    __BUILT_AT__: JSON.stringify(BUILT_AT),
    __BUILD_ENGINE__: JSON.stringify(ENGINE),
  },
});
