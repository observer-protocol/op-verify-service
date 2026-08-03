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

/** THREE OUTCOMES, NOT TWO, and collapsing them is what broke this the first time.
 *
 * `shell()` returns 'unknown' both when git FAILS and when it succeeds with EMPTY output — and a
 * clean tree produces empty output. So "clean" and "no git here" were the same value, and the flag
 * derived from it was wrong on a clean tree: it stamped `dirty: true` on every build, which is a
 * field that is always true and therefore carries nothing.
 *
 * Caught by measuring it — a clean checkout produced `dirty: true` in the bundle — rather than by
 * reading the expression, which looked right.
 *
 *   'clean'    tracked tree matches HEAD
 *   'dirty'    it does not, so the bytes do not correspond to the commit
 *   'unknown'  git could not be consulted, which is neither of the above
 */
const DIRTY_STATE: 'clean' | 'dirty' | 'unknown' = (() => {
  try {
    // TRACKED CHANGES ONLY, AND THE REASON IS THE MEASUREMENT CHANGING WHAT IT MEASURES.
    //
    // `git status --porcelain` includes UNTRACKED files, and tsup writes its own temporary bundled
    // config into the repo while this very function runs — so the check observed the build tool's
    // scratch file and stamped `dirty` on every build of a clean checkout. A detector written inside
    // the thing it detects.
    //
    // `git diff --quiet HEAD` asks the question that actually matters: do the TRACKED bytes
    // correspond to the commit being stamped? Untracked files are by definition not in the commit.
    //
    // THE LIMIT: a new, untracked source file that the bundle imports would change the output and
    // not show here. That is narrow — an import of an untracked file fails typecheck and CI — but it
    // is real, and it is why this says `clean` rather than `reproducible`.
    execFileSync('git', ['diff', '--quiet', 'HEAD'], { stdio: 'ignore' });
    return 'clean';
  } catch (e) {
    // `git diff --quiet` EXITS 1 WHEN THERE ARE DIFFERENCES, which is not an error — it is the
    // answer. Distinguished from git being absent, which is the third state.
    const code = (e as { status?: number }).status;
    return code === 1 ? 'dirty' : 'unknown';
  }
})();
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
    // nobody can reproduce later. Three-valued, so "clean" and "could not tell" stay distinct.
    __BUILD_DIRTY__: JSON.stringify(DIRTY_STATE),
    __BUILT_AT__: JSON.stringify(BUILT_AT),
    __BUILD_ENGINE__: JSON.stringify(ENGINE),
  },
});
