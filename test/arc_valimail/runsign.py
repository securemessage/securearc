#!/usr/bin/env python3
"""Drive the ValiMail ARC signing suite against `securearc-seal`.

The counterpart to `runsuite.py`, and it closes the last untested signing path in
this repository: nothing had ever examined a seal `securearc` produced.

WHAT MAKES THIS A STRONGER ORACLE THAN THE VALIDATION HALF. The validation suite
asks "did you reach the same verdict?", a three-valued answer. This one supplies a
message, a key, an `h=` list and a FIXED TIMESTAMP, and compares the AAR, ARC-Seal
and ARC-Message-Signature we produce against tag lists ValiMail generated. RSA
PKCS#1 v1.5 is deterministic, so `b=` is reproducible and every tag is checked --
including the two signatures themselves. There is no room for a wrong answer that
happens to fall in the same bucket.

COMPARISON SEMANTICS, matching the reference runner in `testarc.py` rather than
inventing a stricter rule: strip all whitespace, split on `;`, compare as SETS. So
tag order and folding do not matter and tag content must match exactly. Adopting the
upstream comparison is deliberate -- a harness stricter than the suite it vendors
reports failures the suite's own author would not recognise.

WITH ONE DOCUMENTED DEPARTURE, AND IT MATTERS. `b=` is compared separately from every
other tag, because ValiMail's expected values were produced by dkimpy with
`standardize=True`, which sorts the tag list ALPHABETICALLY. An AMS and an ARC-Seal
sign themselves with `b=` empty, so a different tag ORDER is a different signing
input and therefore a different signature. Tag order is unconstrained by RFC 6376 and
RFC 8617 -- ours is valid, simply not byte-identical -- so requiring a match would be
scoring a cosmetic implementation choice as conformance, and "fixing" production to
match a test that is not testing a rule.

THAT LEAVES A BLIND SPOT WHICH IS NOT ALLOWED TO STAND. If our *header*
canonicalization for signing were wrong, `bh=` would still match, every comparable
tag would still match, and only `b=` would differ -- indistinguishable from the
harmless ordering difference. So `b=` is not merely excused: every sealed message is
handed to DKIMPY'S OWN ARC VALIDATOR, which recomputes both signatures over its own
canonicalization and must accept the chain. That is the assertion the whole exercise
exists for -- an implementation that is not ours, agreeing that our seals are good.
"""

import argparse
import os
import subprocess
import sys
import tempfile

import dkim
import yaml

# One DNS fake serves every conformance suite in the tree; securemilter-lib's
# test/dnsfake.py records why it is not four any more. Reachable because
# build.zig.zon already depends on ../securemilter-lib by path, so the six
# repositories are checked out side by side.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "..", "..", "securemilter-lib", "test"))

from dnsfake import DnsFake, TxtZone   # noqa: E402

# Resolve the binary from this file's location so the suite runs from a fresh clone
# with no editing. SECUREARC_SEAL overrides it, for a package build or CI runner
# where the binary is not in the tree.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SEAL = os.environ.get(
    "SECUREARC_SEAL", os.path.join(_REPO_ROOT, "zig-out", "bin", "securearc-seal")
)

SUITE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                     "arc-draft-sign-tests.yml")

# The authentication methods this host claims to perform, for the AAR trust rule in
# RFC 8617 5.1.1.
#
# `buildAarContent` only copies an Authentication-Results result whose method is on
# this list, because sealing a method we did not perform would have this host
# cryptographically vouch for a stranger's assertion. Every message in this suite
# carries `arc`, `spf`, `dkim` and `dmarc` results from the authserv-id under test,
# and the expected AAR reproduces all of them -- so the suite is implicitly asking us
# to act as a host that performs all four. Saying so explicitly here is the honest
# way to satisfy it; widening the trust rule itself would not be.
LOCAL_METHODS = "arc,spf,dkim,dmarc"


def seal(message, privatekey, *, domain, selector, authserv_id, headers, timestamp,
         port, verbose=False):
    """Seal one message. Returns (headers_dict, error_text)."""
    with tempfile.TemporaryDirectory() as tmp:
        msg_path = os.path.join(tmp, "message.eml")
        key_path = os.path.join(tmp, "key.pem")
        # newline="" so Python does not translate the suite's line endings. The tool
        # normalises to CRLF itself, and doing it in two places would hide which one
        # is responsible when a body hash disagrees.
        with open(msg_path, "w", newline="") as f:
            f.write(message)
        # 0600, created that way rather than chmod'ed afterwards. securearc-seal
        # refuses a private key with any group or other bit set, the same rule the
        # daemon applies to its sealing key; a plain open() here produced 0644 and
        # the harness could not seal at all. Writing it correctly is the fix, not
        # relaxing the tool -- a fixture that hands the sealer a world-readable
        # private key is not modelling a deployment anyone should run.
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", newline="") as f:
            f.write(privatekey)

        cmd = [SEAL, "-d", domain, "-s", selector, "-k", key_path,
               "-a", authserv_id, "--headers", headers,
               "--methods", LOCAL_METHODS,
               "-t", str(timestamp),
               "-n", "127.0.0.1", "-p", str(port), msg_path]
        try:
            proc = subprocess.run(cmd, capture_output=True, timeout=30)
        except subprocess.TimeoutExpired:
            return None, "securearc-seal timed out"

        out = proc.stdout.decode("utf-8", "replace")
        err = proc.stderr.decode("utf-8", "replace").strip()
        if proc.returncode != 0:
            return None, err or f"exit {proc.returncode}"
        if err:
            return None, f"wrote to stderr: {err}"

        # Both forms are kept: the squashed one is what the upstream comparison
        # operates on, the raw one is needed to rebuild a message dkimpy can verify.
        squashed, raw = {}, {}
        for chunk in out.split("\n\n"):
            if ":" not in chunk:
                continue
            name, _, value = chunk.partition(":")
            key = "".join(name.split()).lower()
            if not key:
                continue
            squashed[key] = "".join(value.split())
            raw[key] = value.strip("\r\n")
        return {"squashed": squashed, "raw": raw}, ""


def tagset(raw):
    """Whitespace-stripped set of `;`-delimited tags, as testarc.py compares them."""
    return set("".join(raw.split()).split(";"))


def compare(expected, produced):
    """Differences in every tag except `b=`. Empty list when they agree.

    `b=` is dropped from both sides rather than compared and excused, so a genuine
    signature difference cannot hide inside a diff that is expected to be noisy.
    Its correctness is asserted by `verify_with_dkimpy` instead.
    """
    def comparable(raw):
        return {t for t in tagset(raw) if t and not t.startswith("b=")}

    want, got = comparable(expected), comparable(produced)
    if want == got:
        return []
    diffs = []
    for missing in sorted(want - got):
        diffs.append(f"missing tag: {missing[:110]}")
    for extra in sorted(got - want):
        diffs.append(f"unexpected tag: {extra[:110]}")
    return diffs


def verify_with_dkimpy(message, produced, records, expect_pass):
    """Prepend our ARC set to the message and have dkimpy validate the chain.

    The independent half of the assertion, and the reason `b=` not being comparable
    is acceptable: dkimpy recanonicalizes the headers itself, recomputes both
    signatures and reports cv. Anything wrong with our signing input shows up here
    regardless of how we ordered the tags.

    `expect_pass` IS NOT ALWAYS TRUE, and getting that wrong was this harness's first
    bug. When we correctly seal `cv=fail`, a conformant validator must NOT return
    pass -- RFC 8617 §5.2 step 2 terminates a chain whose highest instance says fail.
    Demanding pass everywhere failed two cases where our output already matched
    ValiMail's expectation exactly. The assertion is AGREEMENT WITH THE EXPECTED
    OUTCOME, not success; a suite that only accepts success cannot test the paths
    whose correct answer is failure.

    Returns (ok, detail). DNS is injected rather than served, so a fault in the
    loopback zone cannot make both sides fail together and look like agreement.
    """
    def dnsfunc(name, timeout=5):
        key = name.decode("utf-8") if isinstance(name, bytes) else name
        value = records.get(key.rstrip("."))
        if value is None:
            return None
        return value.encode() if isinstance(value, str) else value

    # Field order on the wire is AAR, AMS, AS topmost-last within the set; the whole
    # set is prepended above everything already on the message, which is what a
    # sealing hop does.
    sealed = (
        "ARC-Seal: " + produced["raw"]["arc-seal"] + "\r\n" +
        "ARC-Message-Signature: " + produced["raw"]["arc-message-signature"] + "\r\n" +
        "ARC-Authentication-Results: " + produced["raw"]["arc-authentication-results"] + "\r\n" +
        to_crlf(message)
    ).encode()

    try:
        cv, results, reason = dkim.arc_verify(sealed, dnsfunc=dnsfunc)
    except Exception as e:                                   # noqa: BLE001
        return False, f"dkimpy raised while validating our chain: {e}"

    status = (cv.decode() if isinstance(cv, bytes) else str(cv)).lower()
    passed = status == "pass"
    if passed == expect_pass:
        return True, ""
    if expect_pass:
        return False, (f"dkimpy rejected the chain we sealed: cv={status} "
                       f"reason={reason}")
    return False, ("dkimpy ACCEPTED a chain we sealed cv=fail, which RFC 8617 5.2 "
                   "step 2 says must terminate as fail")


FIELDS = (
    ("arc-authentication-results", "AAR"),
    ("arc-seal", "AS"),
    ("arc-message-signature", "AMS"),
)


def to_crlf(text):
    """Normalise to CRLF without producing CR CR LF on input that already has it."""
    return text.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "\r\n")


def run_case(test, scenario, records, port, verbose):
    """Seal one case, compare every comparable tag, and have dkimpy verify the result.

    Both assertions must hold. The comparison catches a wrong or missing tag; the
    verification catches a wrong signature, which the comparison cannot see because
    `b=` is not byte-comparable across tag orderings.
    """
    produced, err = seal(
        test["message"], scenario["privatekey"],
        domain=scenario["domain"], selector=scenario["sel"],
        authserv_id=test["srv-id"], headers=test["sig-headers"],
        timestamp=test["t"], port=port, verbose=verbose,
    )
    if produced is None:
        return False, [err]

    # A case whose expected AAR, AMS and AS are all empty is asserting that NO set
    # should be added -- RFC 8617 §5.1.3, a chain already marked cv=fail cannot be
    # continued. Producing nothing is the pass condition, and there is no chain of
    # ours for dkimpy to validate.
    expects_no_set = not any(test[k].strip() for _, k in FIELDS)
    if expects_no_set:
        if produced["squashed"]:
            got = ", ".join(sorted(produced["squashed"]))
            return False, [f"expected no ARC set to be added, but got: {got}"]
        return True, []

    problems = []
    for header_name, yaml_key in FIELDS:
        want = test[yaml_key]
        got = produced["squashed"].get(header_name)
        if got is None:
            problems.append(f"{yaml_key}: no {header_name} produced")
            continue
        for d in compare(want, got):
            problems.append(f"{yaml_key}: {d}")

    # Only worth handing to dkimpy if all three fields exist. A sealer that emitted
    # nothing has already been recorded as a failure above, and reaching into the
    # missing values to build a message would raise here -- turning a clean "this
    # tool is broken" result into a traceback. Found by pointing the suite at
    # /usr/bin/true, which is what that check is for.
    if all(name in produced["raw"] for name, _ in FIELDS):
        # What the expected ARC-Seal says about the chain decides what a conformant
        # validator must conclude about the chain we produced.
        expect_pass = "cv=fail" not in "".join(test["AS"].split())
        ok, detail = verify_with_dkimpy(test["message"], produced, records, expect_pass)
        if not ok:
            problems.append(detail)

    return not problems, problems


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("-v", "--verbose", action="store_true", help="list every case")
    ap.add_argument("--test", help="run one case by name")
    ap.add_argument("--port", type=int, default=5301, help="loopback DNS port")
    args = ap.parse_args()

    if not os.path.isfile(SEAL):
        print(f"securearc-seal not found at {SEAL}\n"
              f"Build it first:  cd ../.. && zig build", file=sys.stderr)
        return 2

    # Fetched rather than committed, because it carries ValiMail's published RSA test
    # key inline and the pre-receive hook rejects it. See README, "This file cannot be
    # pushed". Checked here so its absence reads as a setup step rather than a
    # traceback out of yaml.
    if not os.path.isfile(SUITE):
        print(f"{os.path.basename(SUITE)} not found.\n"
              f"Fetch it first:  ./fetch-vectors.sh", file=sys.stderr)
        return 2

    scenarios = list(yaml.safe_load_all(open(SUITE, "rb")))

    cases = []
    for scenario in scenarios:
        for name, test in scenario["tests"].items():
            cases.append((name, test, scenario))
    if args.test:
        cases = [c for c in cases if c[0] == args.test]
    if not cases:
        print("no cases selected", file=sys.stderr)
        return 2

    # One DNS zone for every scenario's key records. The sealer validates the chain
    # already on the message to decide its own cv=, so it needs the previous hops'
    # public keys -- the same reason the validation half serves a zone.
    records = {}
    for scenario in scenarios:
        for name, value in scenario["txt-records"].items():
            records[name] = value

    print(f"ARC signing suite: {len(cases)} cases\n")

    passed, failures = 0, []
    with DnsFake(TxtZone(records), port=args.port):
        for name, test, scenario in cases:
            ok, detail = run_case(test, scenario, records, args.port, args.verbose)
            if ok:
                passed += 1
                if args.verbose:
                    print(f"  PASS  {name:26s} {test['description']}")
            else:
                failures.append((name, test, detail))
                print(f"  FAIL  {name:26s} {test['description']}")

    print(f"\ntotal={len(cases)} passed={passed} failed={len(failures)}")

    if failures:
        print("\nFAILURES -- each is a difference between a seal securearc produced")
        print("and the one ValiMail's implementation produced for the same input.")
        for name, test, detail in failures:
            print(f"\n  {name}  [spec {test.get('spec', '-')}]")
            print(f"    {test['description']}")
            for d in detail:
                print(f"    {d}")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
