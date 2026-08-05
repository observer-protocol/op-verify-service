#!/usr/bin/env bash
# Smoke test for the self-hosted verifier.
#
# Run after `docker compose up --build`. Exits non-zero on any failure, so it is usable as a gate
# rather than something a human reads and interprets.
#
# WHAT MAKES THIS A TEST AND NOT A DEMO: it checks a credential that MUST verify and one that MUST
# be refused, and fails if either answer is wrong. A smoke test that only proves the happy path
# cannot tell a working verifier from one that says yes to everything, which is the failure mode
# that matters most here.
set -uo pipefail

BASE="${OP_VERIFY_URL:-http://127.0.0.1:${OP_VERIFY_PORT:-8091}}"
UA='Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/126 Safari/537.36'
VALID_URL='https://observerprotocol.org/credentials/maxi-0001-trading-mandate-2026-08.json'
INVALID_URL='https://observerprotocol.org/credentials/maxi-0001-trading-mandate.json'
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
FAILED=0

pass() { printf '  PASS  %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1"; FAILED=1; }

echo "verifier: $BASE"
echo

# ─── 1. the service is up and says what it loaded ────────────────────────────────────────────
echo "1. service reachable"
if ! curl -sf --max-time 10 "$BASE/health" -o "$TMP/health.json"; then
  fail "GET /health did not answer. Is the container up? docker compose up --build"
  exit 1
fi
pass "GET /health"
SIGNING_VM=$(python3 -c "import json;print(json.load(open('$TMP/health.json'))['signingVm'])" 2>/dev/null)
pass "signing as ${SIGNING_VM}"
case "$SIGNING_VM" in
  did:key:*) pass "signed by a LOCAL key — verdicts are this operator's, not Observer attestations" ;;
  *)         echo "  NOTE  signing VM is not a did:key. This deployment claims an identity it must actually control." ;;
esac
echo

# ─── 1b. it can actually reach the issuers it is pinned to ───────────────────────────────────
#
# STEP 1 PASSING IS NOT EVIDENCE FOR THIS. /health answers whenever the process is up, including on
# a cold cache behind a corporate proxy where every credential below will be refused. That is the
# first thing a new reader hits, and before this step it presented as a bad credential rather than
# as a blocked network. Checked SEPARATELY and named separately, so the two failures never wear
# each other's error message.
echo "1b. the verifier can reach its pinned issuers"
READY_CODE=$(curl -s -o "$TMP/ready.json" -w '%{http_code}' --max-time 20 "$BASE/ready")
if [ "$READY_CODE" = "200" ]; then
  pass "GET /ready 200 — every pinned issuer DID resolves"
  if python3 -c "
import json,sys
d=json.load(open('$TMP/ready.json'))
sys.exit(0 if d.get('degraded') else 1)" 2>/dev/null; then
    echo "  NOTE  ready, but DEGRADED — not every issuer was fetched live. Per-issuer state:"
    python3 -c "
import json
for i in json.load(open('$TMP/ready.json'))['issuers']:
    print('          %s  %s%s' % (i['state'], i['issuer'], (' — ' + i['note']) if i.get('note') else ''))" 2>/dev/null
  fi
elif [ "$READY_CODE" = "503" ]; then
  fail "GET /ready 503 — the container is running and CANNOT VERIFY ANYTHING."
  python3 -c "
import json
d=json.load(open('$TMP/ready.json'))
print('        %s' % d.get('reason',''))
for i in d['issuers']:
    if not i.get('resolvable'):
        print('        %s: %s' % (i['issuer'], i.get('error','')))" 2>/dev/null
  echo "        Steps 2 and 3 below will fail for THIS reason, not because the credentials are bad."
  echo "        Behind a proxy, allowlist the DID-document hosts named above."
else
  fail "GET /ready returned $READY_CODE — expected 200 or 503. An old image predates this endpoint."
fi
echo

# ─── 2. a credential that MUST verify ────────────────────────────────────────────────────────
echo "2. a valid published credential must VERIFY"
if ! curl -sf --max-time 20 -A "$UA" "$VALID_URL" -o "$TMP/valid.json"; then
  fail "could not fetch $VALID_URL — network, not the verifier"
else
  python3 -c "
import json;c=json.load(open('$TMP/valid.json'))
json.dump({'agentDid':c['credentialSubject']['id'],'mandate':c},open('$TMP/req-valid.json','w'))"
  curl -s --max-time 25 -X POST "$BASE/v1/verify" -H 'Content-Type: application/json' \
    --data @"$TMP/req-valid.json" -o "$TMP/res-valid.json"
  RESULT=$(python3 -c "
import json
try:
  d=json.load(open('$TMP/res-valid.json'))
  print('%s|%s|%s' % (d.get('identity',{}).get('valid'), d.get('mandate',{}).get('valid'), d.get('mandate',{}).get('reason','')))
except Exception as e: print('ERR|ERR|%s' % e)")
  IFS='|' read -r ID MAND REASON <<< "$RESULT"
  [ "$ID"   = "True" ] && pass "identity.valid true"  || fail "identity.valid is $ID"
  [ "$MAND" = "True" ] && pass "mandate.valid true"   || fail "mandate.valid is $MAND — $REASON"
fi
echo

# ─── 3. a credential that MUST be refused ────────────────────────────────────────────────────
echo "3. an invalid published credential must be REFUSED"
echo "   (a real defect in a real published credential, not a contrived fixture)"
if ! curl -sf --max-time 20 -A "$UA" "$INVALID_URL" -o "$TMP/invalid.json"; then
  fail "could not fetch $INVALID_URL — network, not the verifier"
else
  python3 -c "
import json;c=json.load(open('$TMP/invalid.json'))
json.dump({'agentDid':c['credentialSubject']['id'],'mandate':c},open('$TMP/req-invalid.json','w'))"
  curl -s --max-time 25 -X POST "$BASE/v1/verify" -H 'Content-Type: application/json' \
    --data @"$TMP/req-invalid.json" -o "$TMP/res-invalid.json"
  RESULT=$(python3 -c "
import json
try:
  d=json.load(open('$TMP/res-invalid.json'))
  print('%s|%s' % (d.get('mandate',{}).get('valid'), d.get('mandate',{}).get('reason','')))
except Exception as e: print('ERR|%s' % e)")
  IFS='|' read -r MAND REASON <<< "$RESULT"
  if [ "$MAND" = "False" ]; then
    pass "mandate.valid false"
    case "$REASON" in
      *authorizationConfig*) pass "refused for the expected reason: $REASON" ;;
      *) fail "refused, but for an unexpected reason: $REASON" ;;
    esac
  else
    fail "mandate.valid is $MAND — a verifier that accepts this accepts anything"
  fi
fi
echo

# ─── 4. the offline engine agrees, when it is available ──────────────────────────────────────
#
# examples/verify-a-credential/ lives in op-policy-engine and is the SAME example the npm package
# ships. Pointed at this container it answers the question that matters: does the endpoint you are
# running agree with the engine you can audit? Skipped, loudly, when that checkout is not a sibling
# — a skipped check must never read as a passed one.
echo "4. offline engine cross-check"
EXAMPLE="$(cd "$(dirname "$0")/.." 2>/dev/null && pwd)/op-policy-engine/examples/verify-a-credential"
if [ -f "$EXAMPLE/verify.mjs" ]; then
  if [ ! -d "$EXAMPLE/node_modules" ]; then
    echo "  SKIP  $EXAMPLE has no node_modules — run 'npm install' there first"
  else
    ( cd "$EXAMPLE" && OP_VERIFY_URL="$BASE" node verify.mjs ) > "$TMP/example.txt" 2>&1
    if grep -q "AGREE" "$TMP/example.txt"; then
      pass "the auditable offline engine and this container reached the same verdict"
    else
      fail "offline engine and this container DISAGREE, or the example errored:"
      sed 's/^/        /' "$TMP/example.txt"
    fi
  fi
else
  echo "  SKIP  op-policy-engine is not a sibling checkout, so the offline cross-check did NOT run."
  echo "        Steps 1-3 tested this container only. They do not establish that it agrees with"
  echo "        the published engine. Clone https://github.com/observer-protocol/op-policy-engine"
  echo "        alongside this repo to close that gap."
fi
echo

if [ "$FAILED" -eq 0 ]; then
  echo "SMOKE PASSED"
else
  echo "SMOKE FAILED"
fi
exit "$FAILED"
