#!/bin/sh
# Fetch the ARC *signing* vector file, pinned and checksum-verified.
#
# WHY THIS EXISTS, since the sibling validation file is committed and this one is not:
# arc-draft-sign-tests.yml carries an RSA private key inline -- ValiMail's published
# test key, needed verbatim because the fixture messages already contain ARC sets
# signed by it (see README, "This file cannot be pushed"). The Forgejo pre-receive hook
# runs gitleaks and rejects any push containing it, and does not honour a repository
# .gitleaksignore. So the file is fetched rather than committed.
#
# The checksum is what keeps this equivalent to vendoring: it pins the exact bytes, so
# a conformance run is still reproducible and still tied to a known suite version. It
# is arguably stronger than the committed copy it replaces, which could be edited
# without anything noticing.
#
# Usage:  ./fetch-vectors.sh [--check]
#   --check  verify an existing file and download nothing (for CI)

set -eu

COMMIT=f137dcb9d6d5baeef1310024ce9ccca94a9a92c8
FILE=arc-draft-sign-tests.yml
WANT=d56f156b8833939e4ad8a3a4b270e497a5a440eef8fb5aaf7a9a1b655869aeb8
URL="https://raw.githubusercontent.com/ValiMail/arc_test_suite/$COMMIT/tests/$FILE"

cd "$(dirname "$0")"

checksum() {
    if command -v sha256 >/dev/null 2>&1; then
        sha256 -q "$1"
    else
        sha256sum "$1" | cut -d' ' -f1
    fi
}

verify() {
    got=$(checksum "$FILE")
    if [ "$got" != "$WANT" ]; then
        echo "$FILE: CHECKSUM MISMATCH" >&2
        echo "  expected $WANT" >&2
        echo "  got      $got" >&2
        echo "The vector file is not the pinned upstream one. Conformance numbers" >&2
        echo "produced against it would not be comparable. Delete it and re-run." >&2
        return 1
    fi
    echo "$FILE: ok ($COMMIT)"
}

if [ "${1:-}" = "--check" ]; then
    if [ ! -f "$FILE" ]; then
        echo "$FILE: missing. Run ./fetch-vectors.sh" >&2
        exit 1
    fi
    verify
    exit
fi

if [ -f "$FILE" ] && checksum "$FILE" | grep -q "^$WANT$"; then
    echo "$FILE: already present and pinned ($COMMIT)"
    exit
fi

echo "fetching $FILE from ValiMail arc_test_suite $COMMIT"
# Downloaded to a temporary name so a failed or truncated transfer cannot leave a file
# that the suite would then happily run against.
if command -v fetch >/dev/null 2>&1; then
    fetch -q -o "$FILE.tmp" "$URL"
elif command -v curl >/dev/null 2>&1; then
    curl -fsSL -o "$FILE.tmp" "$URL"
else
    echo "need fetch(1) or curl(1)" >&2
    exit 1
fi

got=$(checksum "$FILE.tmp")
if [ "$got" != "$WANT" ]; then
    rm -f "$FILE.tmp"
    echo "downloaded $FILE has the wrong checksum" >&2
    echo "  expected $WANT" >&2
    echo "  got      $got" >&2
    exit 1
fi

mv "$FILE.tmp" "$FILE"
verify
