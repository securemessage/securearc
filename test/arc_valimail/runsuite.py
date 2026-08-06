"""Drive the ValiMail arc_test_suite validation cases against securearc-check.

Usage: runsuite.py [-v] [--scenario SUBSTRING] [--test NAME] [--port N]

Each case supplies a complete RFC 5322 message and the chain validation value a
conforming verifier must report -- none, pass or fail. That is exactly what
`securearc-check` prints, so the suite drives the shipped verifier rather than a
reimplementation written to satisfy it.

Each scenario carries its own `txt-records`, served by the shared DNS fake on a
loopback port, so securearc's real resolver does the key lookups.

Exit status is 1 if any case fails or errors, 0 only on a clean run, so this is
usable as a gate rather than as output a human has to read.
"""

import argparse
import os
import subprocess
import sys
import tempfile

import yaml

# One DNS fake serves every conformance suite in the tree; securemilter-lib's
# test/dnsfake.py records why it is not four any more. Reachable because
# build.zig.zon already depends on ../securemilter-lib by path, so the six
# repositories are checked out side by side.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "..", "..", "securemilter-lib", "test"))

from dnsfake import DnsFake, TxtZone   # noqa: E402

# Resolve the checker from this file's location -- test/arc_valimail/ -> repo root
# -- so the suite runs from a fresh clone with no editing. SECUREARC_CHECK
# overrides it, which is what a package build or CI runner uses when the binary is
# not in the tree.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CHECK = os.environ.get(
    "SECUREARC_CHECK", os.path.join(_REPO_ROOT, "zig-out", "bin", "securearc-check")
)

SUITE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                     "arc-draft-validation-tests.yml")

# The three values RFC 8617 defines for cv=. Anything else from the checker is an
# error rather than a wrong answer: `temperror`, `internalerror` and `unknown` all
# mean no verdict was reached, and scoring them as a verdict would let a DNS
# outage or an allocation failure be recorded as conformance.
VERDICTS = {"none", "pass", "fail"}

# The suite is dated 2018-11 and written against draft-ietf-dmarc-arc-protocol-18.
# RFC 8617 published 2019-07 and changed what a validator reports for a chain whose
# most recent ARC-Seal already says cv=fail. These three cases encode the draft's
# answer -- an empty cv, which the reference runner produces because dkimpy returns
# Python None -- where RFC 8617 5.2 is explicit:
#
#   step 2:  "If the Chain Validation Status of the highest instance value ARC Set
#             is 'fail', then the Chain Validation Status is 'fail', and the
#             algorithm stops here."
#   step 3C: "The 'cv' value for all ARC-Seal header fields MUST NOT be 'fail'
#             ... If any of these conditions are not met, the Chain Validation
#             Status is 'fail'."
#
# So `fail` is correct and the suite's expectation is stale. These are overridden
# rather than skipped, and counted and printed separately, because a harness that
# silently drops the cases it disagrees with is no longer measuring anything. Each
# entry has to state the RFC clause that overrides it.
RFC8617_OVERRIDES = {
    "cv_fail_i1_as_cv_fail": ("fail", "RFC 8617 5.2 step 3C: cv MUST NOT be fail"),
    "cv_fail_i2_as2_fail": ("fail", "RFC 8617 5.2 step 2: highest-instance cv=fail -> fail"),
    "cv_fail_i2_as1_fail": ("fail", "RFC 8617 5.2 step 3C: cv MUST NOT be fail"),
}


def run_case(message, port, verbose):
    """Feed one message to securearc-check and return its verdict token."""
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "message.eml")
        # newline="" so Python does not translate the suite's line endings; the
        # checker normalises to CRLF itself, and doing it in two places would hide
        # which one is responsible when a body hash disagrees.
        with open(path, "w", newline="") as f:
            f.write(message if message is not None else "")
        cmd = [CHECK, "-n", "127.0.0.1", "-p", str(port), path]
        if verbose:
            cmd.insert(1, "-v")
        try:
            proc = subprocess.run(cmd, capture_output=True, timeout=30)
        except subprocess.TimeoutExpired:
            return "timeout", ""
        out = proc.stdout.decode("utf-8", "replace").strip()
        err = proc.stderr.decode("utf-8", "replace").strip()
        if proc.returncode != 0:
            return f"exit{proc.returncode}", err or out
        token = out.split()[0].lower() if out else ""
        return token, out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-v", "--verbose", action="store_true", help="list every case")
    ap.add_argument("--scenario", help="only scenarios whose description contains this")
    ap.add_argument("--test", help="only this test name")
    ap.add_argument("--port", type=int, default=5354, help="loopback DNS port")
    args = ap.parse_args()

    if not os.path.exists(CHECK):
        print(f"checker not found: {CHECK}\nBuild it with `zig build`, or set SECUREARC_CHECK.",
              file=sys.stderr)
        return 2

    with open(SUITE) as f:
        scenarios = [s for s in yaml.safe_load_all(f) if s]

    passed = failed = errored = overridden = 0
    failures = []

    for scenario in scenarios:
        desc = " ".join((scenario.get("description") or "").split())
        if args.scenario and args.scenario.lower() not in desc.lower():
            continue
        tests = scenario.get("tests") or {}
        records = scenario.get("txt-records") or {}

        # One server per scenario rather than one per case: the records are shared
        # across a scenario's tests, and binding a fresh UDP port 172 times invites
        # TIME_WAIT flakiness that would look like conformance failures.
        with DnsFake(TxtZone(records), port=args.port, verbose=args.verbose):
            for name, test in tests.items():
                if args.test and args.test != name:
                    continue
                want = str(test.get("cv", "")).strip().lower()
                citation = None
                if name in RFC8617_OVERRIDES:
                    want, citation = RFC8617_OVERRIDES[name]
                    overridden += 1
                got, detail = run_case(test.get("message"), args.port, args.verbose)

                if got == want:
                    passed += 1
                    status = "ok"
                elif got in VERDICTS:
                    failed += 1
                    status = "FAIL"
                    failures.append((desc, name, want, got, test.get("description", "")))
                else:
                    errored += 1
                    status = "ERROR"
                    failures.append((desc, name, want, got or "<no output>",
                                     (test.get("description", "") + " " + detail).strip()))

                if args.verbose or status != "ok":
                    tag = " [RFC8617 override]" if citation else ""
                    print(f"  {status:<5} {name:<28} want={want:<5} got={got or '<none>'}"
                          f"  {' '.join((test.get('description') or '').split())[:60]}{tag}")

    total = passed + failed + errored
    print(f"\ntotal={total} passed={passed} failed={failed} errored={errored}"
          f" (scored against RFC 8617; {overridden} suite expectations overridden as pre-RFC)")
    if overridden and args.verbose:
        print("\nRFC 8617 overrides applied:")
        for n, (w, why) in RFC8617_OVERRIDES.items():
            print(f"  {n}: suite says '' -> scored as {w!r}  ({why})")

    if failures:
        print("\nfailing cases:")
        for scen, name, want, got, note in failures:
            print(f"  [{scen[:34]}] {name}: want={want} got={got}  {note[:70]}")

    return 1 if (failed or errored) else 0


if __name__ == "__main__":
    sys.exit(main())
