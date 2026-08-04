#!/bin/sh
# Entrypoint for the self-hosted verifier.
#
# Everything this service needs is either public or generated here on first run. Nothing is fetched
# from Observer at startup beyond the issuer DID documents the verifier would resolve anyway, and
# there is no Observer key material in this image.
set -eu

: "${OP_VERIFY_SIGNING_KEY_PATH:=/var/lib/op-verify/signer.pem}"
: "${OP_VERIFY_CACHE_DIR:=/var/lib/op-verify/cache}"
mkdir -p "$(dirname "$OP_VERIFY_SIGNING_KEY_PATH")" "$OP_VERIFY_CACHE_DIR"

# The signing identity. Generated once and reused across restarts — see scripts/gen-did-key.mjs for
# why this is a did:key and not Observer's #key-7.
if [ -z "${OP_VERIFY_SIGNING_VM:-}" ]; then
  OP_VERIFY_SIGNING_VM="$(node /app/scripts/gen-did-key.mjs "$OP_VERIFY_SIGNING_KEY_PATH")"
  export OP_VERIFY_SIGNING_VM
fi
export OP_VERIFY_SIGNING_KEY_PATH OP_VERIFY_CACHE_DIR

# ─── SAY WHAT THIS DEPLOYMENT IS, BEFORE IT ANSWERS ANYTHING ──────────────────────────────────
#
# A verdict from this container is signed by the key above, which belongs to whoever ran it. It is
# NOT an Observer attestation, and the difference is invisible in the response body to anyone who
# does not already know to look at proof.verificationMethod. So the service says it, unprompted,
# every boot.
cat <<BANNER
─────────────────────────────────────────────────────────────────────────────
 Observer Protocol — self-hosted verifier

 Verification only. This deployment issues nothing, holds no funds, and has
 no payment or issuance capability compiled into it.

 Verdicts are signed by THIS deployment's own key:
   ${OP_VERIFY_SIGNING_VM}

 That is a did:key generated on first run. It proves this operator's engine
 reached this verdict. It is NOT an Observer-signed attestation — for that,
 ask https://verify.observerprotocol.org, which signs with a key published in
 Observer's DID document.

 Everything this service checks is public and re-checkable without it:
 issuer DID documents, the frozen schema URLs, and static revocation lists.
─────────────────────────────────────────────────────────────────────────────
BANNER

exec "$@"
