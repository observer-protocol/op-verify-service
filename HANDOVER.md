# op-verify-service — ownership handover

**Written 10 August 2026 as a close, not a pause.** The session that owned this service is ending and
v1 scope is frozen to five items, none of them here. This file is in **this repo** rather than in
`op-at-specs` deliberately: a successor picking up `verify.observerprotocol.org` opens this repo, and
filing a handover under the session that wrote it has cost this estate twice in one day.

---

## 1. What I owned, and what establishes it

**`op-verify-service` — owned.** Not asserted: I moved its engine pin, merged to `main` via PR #2,
tagged the deployed commit, deployed it to production and verified the result against the artifact.
`origin/main` is `9b300f0` and contains my six commits.

**Everything else I touched, I did not own**, and the distinction matters more than the list:

| repo | what I actually did | standing |
|---|---|---|
| `op-at-specs` | wrote scopes, routings, findings | **shared**, five sessions write it concurrently. I have no authority there and I damaged provenance in it — see §5 |
| `observer-protocol-api` | read it extensively; wrote three fixes into its working tree under explicit instruction | **not mine.** I never committed to it. A sibling's `git add -A` committed my changes for me — see §5 |
| `observerprotocol-website`, `agenticterminal-dashboard`, `op-policy-engine`, `op-vps-ops` | read only | not mine, never written |

**op-vps:** I ran read-only commands throughout (`ls`, `cat`, `grep`, `readlink`, `systemctl`,
`psql` SELECTs), plus three authorised production writes — see §4.

---

## 2. Branches ahead of origin

**None. Nothing is unpushed, in any repo.** Measured at close:

```
op-verify-service        main                                     0 ahead, 0 uncommitted
op-at-specs              session/mcp-seed-queue-routing-constraint 0 ahead, 0 uncommitted
observer-protocol-api    fix/delegation-requests-tenant-scope      0 ahead, 0 uncommitted
memory                   clean, audit 0 FAILs
```

**Read that carefully rather than as reassurance.** `op-verify-service` local `main` is `d3278ef`
while `origin/main` is `9b300f0` — I am *behind* by the merge commit, not ahead. And the `op-at-specs`
clone has been switched by a sibling to a branch that does not contain my work; my commits are on
`session/human-approval-discovery`, pushed to origin at `daacb0f`. **A successor running
`git status` in that shared clone will see a clean tree and conclude I left nothing.**

What is on origin, by name:

- `op-verify-service` `origin/main` @ `9b300f0`, containing deployed commit `d3278ef`
- annotated tag **`deploy/2026-08-09-engine-1.0.0-rc.10`** → `d3278ef`, reachable from `main`
- branch `upgrade/engine-rc10-and-scope-evaluated` @ `d3278ef` (merged, safe to delete)
- `op-at-specs` `origin/session/human-approval-discovery` @ `daacb0f`

## 3. Uncommitted work

**None anywhere.** The three SIWW fixes I wrote into `observer-protocol-api` are committed — by
someone else, inside `784c5aa` (§5).

---

## 4. Open items

| item | state | blocked on | whose decision |
|---|---|---|---|
| **DID-cache privacy change** in this repo — remove the per-subject record, clear the accumulation, add an aggregate per-caller counter | **ruled, never started.** No code written | nothing technical; it was displaced by the login lockout and then by close-out | Boyd ruled it; needs an owner |
| **`bind_wallet` accepts any signature** — live auth bypass | measured, routed, **not fixed** | API implementing the two-part fix | ruled by Boyd, API owns |
| **Alby / LUD-04 re-point** | scoped, **held** | the `bind_wallet` fix landing first; then a join that does not exist | two design questions go to Boyd |
| **`opdeploy` items 1–3** (`node_modules` in `TREES` landed; `PROVENANCE` deleted; `source_ref`/`source_sha` **not** landed) | 2 of 3 done | API | API |
| **`main` cannot deploy `op-verify`** — `origin/main` of the API repo carries the 36-line `ARTIFACTS=()` manifest | routed, open | a branch merge, 162 commits | API |
| **Cloudflare reading** for `verify.observerprotocol.org` | never taken | no credential on this machine | anyone with dashboard access. Subtract 12 requests from 9 Aug |
| **Clause-zero `credentialStatus` object form** | routed as an issuance fix | API | API |
| **Object-`issuer` conformance** | ruled: schema is narrower than W3C, it stands | nothing | closed |

**Scratch evidence left in place by standing instruction, not by oversight:** PID 813
(`op-deploytest.service`), and scratch orgs **6** (`zz-scratch-siww-probe-20260809`) and **9**
(`zz-scratch-siww-probe2-20260810`) with two invitations and two user rows. **Do not clean these up
without Boyd.**

---

## 5. What I measured that contradicts something written elsewhere

1. **`opdeploy` shipped no dependencies.** Its manifest named only `dist` in `TREES`, so a deploy
   whose content was a dependency version would have restarted the unit, passed all three probes and
   shipped an unchanged engine. Every observable was green. Fixed in `e244e32`.
2. **`origin/main` of `observer-protocol-api` still cannot deploy this service** — the 36-line
   `ARTIFACTS=()` manifest. A deploy from a clean `main` checkout ships zero bytes and reports
   success. Anyone rolling back to `main` under pressure gets that.
3. **`PROVENANCE` on the box was four commits and two days stale**, crediting the stopgap with a
   deploy `opdeploy` performed. Deleted.
4. **The `credentialStatus` requirement starts at v2.5, not v2.7** — I reported v2.7 first, having
   compared only v2.4 and v2.7. Three served versions require it, none enforced.
5. **Clause-zero has never verified through this service**, contradicting my own earlier inference.
   It is refused at the structure gate two checks before the origin pin, identically on both engines.
6. **`invitation_routes.py` would 500 on create** — it INSERTs `capability_bundle` and `note`, neither
   of which exists in the live table.
7. **The service's DID cache is a per-subject record.** The README said "a cache of public DID
   documents", which is true and narrower than the artifact: the set of files records which agents
   callers asked about. Corrected in the README; the removal is item 1 of §4.
8. **Two of my own `op-at-specs` commits carry files I did not author**, swept by `git add -A` in a
   shared repo. Recorded in `2026-08-09-PROVENANCE-CORRECTION-swept-commits.md`. The same then
   happened to me: `784c5aa` — "the meter and the expiry job, together" — contains my three SIWW
   fixes and does not mention them.

---

## 6. What not to trust

- **Do not trust `git status` in the shared `op-at-specs` clone** to tell you what I left. See §2.
- **Do not trust `.opdeploy-current.json` for this service's commit.** On a source build its `ref` and
  `sha` name the *manifest* repo. Read `build.commit` from `GET /version`, or
  `grep -rhoE '[0-9a-f]{40}'` over `dist/` — the stamp is in the bytes.
- **Do not trust `agree: true` alone** after a deploy. It is also true when nothing moved. The check
  is `running == "<expected>"` **and** `agree == true`.
- **Do not raise `MIN_ENGINE_VERSION` to a `1.0.0-rc.x` value.** `compareCoreVersion` cannot order
  prereleases, so the interlock would refuse nothing while still running.
  `test/engine-floor-comparator.test.mjs` fails if you try.
- **Do not trust a `ps` line to identify a unit.** Three units here run byte-identical relative
  `ExecStart` commands; only `WorkingDirectory` differs and `ps` does not show it. Use
  `/proc/<pid>/cgroup`.
- **Do not trust `opdeploy --check` to be read-only.** It builds, uploads and runs `npm ci` on the box,
  and leaves the stage behind.
- **Do not trust this file's §4 to be current.** It is true at close and every row belongs to someone
  else's queue.
- **Trust the tests over me.** 37/37 on a clean install against rc.10, and the two that matter most
  are `engine floor: the comparator can order the configured floor` and the four `scope:` tests — they
  encode reasoning that is easy to undo by accident.

---

## Verified at close

`GET /version` → `running: 1.0.0-rc.10`, `agree: true`, `commit: d3278ef`. Live, correct, and matching
the tag.
