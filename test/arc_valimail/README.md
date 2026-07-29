# ARC conformance suite (ValiMail `arc_test_suite`)

Drives the **ValiMail ARC test suite** validation cases against `securearc-check`.

Current result: **160 / 171**, with **11 real conformance defects** open. See below.

```
$ cd ../.. && zig build                       # produces zig-out/bin/securearc-check
$ python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
$ .venv/bin/python runsuite.py

total=171 passed=160 failed=11 errored=0 (scored against RFC 8617; 3 suite
expectations overridden as pre-RFC)
```

Flags: `-v` lists every case and the overrides, `--scenario SUBSTRING` restricts to
one scenario, `--test NAME` runs one case, `--port N` moves the loopback DNS port.
`SECUREARC_CHECK=/path/to/binary` overrides the checker location.

## What it tests, and why it is shaped this way

Each case supplies a complete RFC 5322 message and the chain validation value a
conforming verifier must report. `securearc-check` prints exactly that, and it
calls the same `arc.parseArcSets` and `chain.validateChain` the milter calls, in
the same order, with the same treatment of a chain that fails to parse. So a score
here is a statement about the **shipped verifier**, not about a parallel
implementation written to pass tests.

`txtdns.py` serves each scenario's own `txt-records` on a loopback port, and
`securearc-check -n 127.0.0.1 -p <port>` points securearc's own resolver at it —
so record rejoining and negative answers are exercised as shipped. **No production
code is modified or conditionally compiled to run this suite.**

TXT-only, unlike `securespf/test/rfc7208/mockdns.py`, because ARC key lookups are a
single TXT query for `<selector>._domainkey.<domain>`. The two are not shared
because securespf and securearc are separate repositories.

## Scored against RFC 8617, not the draft

The suite is dated **2018-11** and written against
`draft-ietf-dmarc-arc-protocol-18`. **RFC 8617 published 2019-07** and changed what
a validator reports for a chain whose most recent ARC-Seal already says `cv=fail`.

Three cases — `cv_fail_i1_as_cv_fail`, `cv_fail_i2_as2_fail`, `cv_fail_i2_as1_fail`
— expect an *empty* `cv`, which the suite's reference runner produces because
`dkimpy` returns Python `None`. RFC 8617 §5.2 is explicit:

> **step 2:** "If the Chain Validation Status of the highest instance value ARC Set
> is 'fail', then the Chain Validation Status is 'fail', and the algorithm stops
> here."
>
> **step 3C:** "The 'cv' value for all ARC-Seal header fields MUST NOT be 'fail'
> … If any of these conditions are not met, the Chain Validation Status is 'fail'."

So `fail` is correct and the suite's expectation is stale. Those three are
**overridden, not skipped** — counted and reported separately, each carrying the
clause that overrides it. A harness that silently drops the cases it disagrees with
has stopped measuring anything, and "we exclude the failures we think are wrong" is
indistinguishable from "we exclude the failures".

## The 11 open defects

Grouped by cause. All are `securearc` verifier defects except where noted.

**`a=` algorithm tag is not validated** — `ams_fields_a_empty`,
`ams_fields_a_unknown`, `as_fields_a_empty`, `as_fields_a_unknown`. An AMS or AS
declaring an empty or unrecognised algorithm is accepted and validated anyway.
Security-relevant: the verifier is deciding the algorithm rather than being told it.

**`c=simple/*` header canonicalization** — `ams_fields_c_sr`, `ams_fields_c_ss`.
These expect **pass** and get **fail**, so this direction *rejects valid chains*.
`c=simple/relaxed` and `c=simple/simple` are not being honoured for the header half.

**AMS `h=` must not include ARC-Seal** — `ams_fields_h_includes_as`. Accepted where
RFC 8617 requires failure.

**AS tag-list parsing is too lenient** — `as_format_inv_tag_key`,
`as_format_tags_dup`, `as_format_tags_key_case`, `as_format_tags_sc`. An invalid tag
key, a duplicated tag, a wrong-case tag key and a stray semicolon are each accepted.
This **confirms open audit finding D-6** (duplicate tags) and extends it to ARC.

## Provenance

`arc-draft-validation-tests.yml` is the validation half of
<https://github.com/ValiMail/arc_test_suite>, commit
`f137dcb9d6d5baeef1310024ce9ccca94a9a92c8` (2018-11-23), vendored verbatim. MIT
licensed — see `LICENSE-valimail.txt`. Committed rather than downloaded so a
conformance run is reproducible from a clone and pinned to a known suite version.

The **signing** half (`arc-draft-sign-tests.yml`) is not yet wired up; it needs a
sealing entry point equivalent to `securearc-check`.

## Scope

Passing this suite is a statement about **ARC chain validation**. It says nothing
about sealing, the milter protocol layer, or the `Authentication-Results` stamp.

> Verified able to fail: pointed at `/usr/bin/true` the runner reports
> **171 errored, 0 passed**. Exit status is 1 on any failure or error and 0 only on
> a clean run, so this is usable as a gate rather than as output a human reads.
