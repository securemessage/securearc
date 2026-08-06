# ARC conformance suite (ValiMail `arc_test_suite`)

Drives the **ValiMail ARC test suite** against both halves of `securearc`:
`runsuite.py` measures the verifier, `runsign.py` measures the sealer.

Current result: **171 / 171** validation, **17 / 17** signing.

```
$ cd ../.. && zig build            # securearc-check and securearc-seal
$ python3.12 -m venv --system-site-packages .venv
$ .venv/bin/pip install -r requirements.txt

$ .venv/bin/python runsuite.py
total=171 passed=171 failed=0 errored=0 (scored against RFC 8617; 3 suite
expectations overridden as pre-RFC)

$ .venv/bin/python runsign.py
total=17 passed=17 failed=0
```

**The venv needs `python3.12` and `--system-site-packages`**, because `runsign.py`
verifies our seals with `py312-dkimpy` from the system while PyYAML comes from
`requirements.txt`. `runsuite.py` needs only PyYAML and works either way.

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

`securemilter-lib/test/dnsfake.py` serves each scenario's own `txt-records` on a
loopback port, and `securearc-check -n 127.0.0.1 -p <port>` points securearc's own
resolver at it — so record rejoining and negative answers are exercised as shipped.
**No production code is modified or conditionally compiled to run this suite.**

This file used to hold its own copy, `txtdns.py`, and said the two were not shared
"because securespf and securearc are separate repositories and a test helper is not
worth a package". That was overturned on 2026-08-05, on evidence rather than taste:
there were **four** copies by the time anyone counted, three of them holding a
byte-identical wire codec, and no package was needed — `build.zig.zon` already
depends on `../securemilter-lib` by path, so a `sys.path` insert reaches it. The
ARC scenarios still use a TXT-only zone (`TxtZone`); RFC 7208's fuller zone model
is a separate class in the same file.

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

## What the first run found

The first run scored **160/171**. Nine of the eleven failures were real defects,
now fixed. **Two were not defects at all**, which is worth recording as loudly as
the fixes.

### Fixed (nine cases, four causes)

- **`a=` was never validated** — `ams_fields_a_empty`, `ams_fields_a_unknown`,
  `as_fields_a_empty`, `as_fields_a_unknown`. `verifyAms` and `verifySeal`
  hardcoded SHA-256 and RSA and never read the algorithm tag, so `a=` empty and
  `a=rsa-poptart` were verified as though they said `rsa-sha256`. The verifier was
  choosing the algorithm instead of being told it.
- **Tag-list syntax was unchecked** — `as_format_inv_tag_key`,
  `as_format_tags_dup`, `as_format_tags_sc`, and `as_format_tags_key_case`. An
  invalid tag name, a duplicated tag and an interior `;;` are now rejected via
  `sig_header.validateTagList`. This also **confirms open audit finding D-6** and
  gives `securedkim` the same validator to call.
- **`findTag` matched tag names case insensitively** — `as_format_tags_key_case`.
  RFC 6376 §3.2 makes them case sensitive, so `S=dummy` was satisfying a lookup for
  `s` and a seal with a mis-cased selector verified against a key it named by
  accident.
- **AMS `h=` covering ARC-Seal was accepted** — `ams_fields_h_includes_as`.

### Not defects (two cases)

- **`c=simple/relaxed` and `c=simple/simple`** were failing because of *this
  harness*, not `securearc`. `check.zig` kept the space after the colon while
  `buildAmsSigningInput` reconstructs `name: value`, so `simple` — which hashes the
  field verbatim — saw two spaces. A milter receives values with leading whitespace
  already stripped unless it negotiates `SMFIP_HDR_LEADSPC`, and
  `ProtocolFlags.header_leading_space` is defined in the lib and requested by
  nobody. **Before filing a suite failure as a product defect, check that the
  harness presents the bytes production presents.**

### The mistake the harness caught

RFC 8617 §4.1.2 names **all three** ARC header fields as MUST NOT appear in an AMS
`h=`. Enforcing all three took the score from **162/171 to 118/171** — the suite's
own base messages sign `arc-authentication-results` and expect `pass`. Enforcing
`ARC-Message-Signature` too still failed `ams_fields_h_includes_ams`, which also
expects `pass`. Only `ARC-Seal` is enforced.

That paragraph sits under *"To reduce the chances of accidental invalidation of AMS
signatures"*, beside a SHOULD about attachment order: it constrains **signers**. The
normative validator algorithm is §5.2, and no step of it rejects a chain over the
contents of `h=`.

> **When a conformance fix makes the score go down, the fix is wrong — not the
> suite.** This is the thing an external oracle does that tests written from your
> own reading of the spec cannot: it disagrees with you.

## Known limitation: `c=simple` and `SMFIP_HDR_LEADSPC`

Because no daemon negotiates `SMFIP_HDR_LEADSPC`, the original spacing after the
colon is unrecoverable, so `simple` header canonicalization cannot be reproduced
faithfully for a header that had two spaces after the colon, or none.
`buildAmsSigningInput` reconstructs exactly one, which is right for the
overwhelmingly common case and wrong for the rest. Fixing it properly means
negotiating the flag and changing header-value semantics for all four daemons, so
it is cross-cutting work rather than a `securearc` patch.

## Provenance

`arc-draft-validation-tests.yml` is the validation half of
<https://github.com/ValiMail/arc_test_suite>, commit
`f137dcb9d6d5baeef1310024ce9ccca94a9a92c8` (2018-11-23), vendored verbatim. MIT
licensed — see `LICENSE-valimail.txt`. Committed rather than downloaded so a
conformance run is reproducible from a clone and pinned to a known suite version.

The **signing** half (`arc-draft-sign-tests.yml`) is wired up too — see
`runsign.py` below, which drives it through `securearc-seal`.

## Scope

Passing *this* suite is a statement about **ARC chain validation** only. It says
nothing about the milter protocol layer or the `Authentication-Results` stamp.
Sealing is covered separately by `runsign.py`.

> Verified able to fail: pointed at `/usr/bin/true` the runner reports
> **171 errored, 0 passed**. Exit status is 1 on any failure or error and 0 only on
> a clean run, so this is usable as a gate rather than as output a human reads.

---

# The signing half — `runsign.py`

**17 / 17.** Every tag of all three header fields is compared against output ValiMail
generated, and dkimpy has to accept the chain we produce. **The first run found three
defects.**

Flags: `-v` lists every case, `--test NAME` runs one, `--port N` moves the loopback
DNS port. `SECUREARC_SEAL=` overrides the binary.

## Why this had to exist

The validation half measures our **verifier** against an independent signer. Nothing
measured our **sealer** against anything — and that is the gap that hid D-18 in
`securedkim` for as long as it existed. Ed25519 signing and verification were broken
*symmetrically*, so they round-tripped perfectly against each other while every
signature the daemon emitted was rejected by every conformant verifier. Reverting only
that defect's signing half is caught by an external verifier at once and is
**invisible** to 204 differential cases, 17 RFC vectors and 388 unit tests.

> **A round-trip test agrees with a symmetric mistake.** If nothing outside the project
> inspects what a daemon *produces*, that half of it is untested however green the
> suite looks.

`securearc-seal` closes it, calling the same `sealbuild.buildSet` the milter calls
through a real `Connection`, and deriving `cv` and the instance number exactly as
`flow.doSeal` does. Message parsing is shared with `securearc-check` through
`msgfile.zig` so the two tools cannot drift into modelling production differently —
harness fidelity has already cost this project two rounds of phantom defects.

## A stronger oracle than the validation half

The validation suite asks "did you reach the same verdict?", three possible answers.
This one supplies a message, a key, an `h=` list and a **fixed timestamp**, then
compares tag by tag. There is no room for a wrong answer that lands in the same bucket.

Two assertions per case, and **both** must hold:

| assertion | what it catches |
|---|---|
| every comparable tag matches ValiMail's expected output | a wrong, missing or extra tag — this found the absent `t=` |
| dkimpy's `arc_verify` reaches the expected verdict | a wrong signature, over its own canonicalization |

### Why `b=` is compared separately, and why that is not a loophole

ValiMail's expected values come from dkimpy with `standardize=True`, which sorts tags
**alphabetically**. An AMS and an ARC-Seal sign themselves with `b=` empty, so a
different tag *order* is a different signing input and therefore a different signature.
Tag order is unconstrained by RFC 6376 and RFC 8617 — ours is valid, simply not
byte-identical — so requiring a match would score a cosmetic implementation choice as
conformance, and "fixing" production to satisfy it would be changing shipped output to
please a test that is not testing a rule.

That leaves a hole which is **not** allowed to stand: if our *header* canonicalization
for signing were wrong, `bh=` would still match, every comparable tag would still
match, and only `b=` would differ — indistinguishable from the harmless ordering
difference. Hence the second assertion. dkimpy recanonicalizes the headers itself and
recomputes both signatures, so a bad signing input surfaces there whatever the order.

### The assertion is the expected outcome, not success

`expect_pass` is derived from the expected ARC-Seal's `cv=`, and getting that wrong was
this harness's first bug. When we correctly seal `cv=fail`, a conformant validator
**must not** return pass — RFC 8617 §5.2 step 2 terminates a chain whose highest
instance says fail. Demanding pass everywhere failed two cases whose output already
matched ValiMail exactly. The same lesson the DKIM differential suite records: a suite
that only accepts success cannot test the paths whose correct answer is failure.

## What it found

### A-21 — `t=` omitted from both the AMS and the ARC-Seal (Low)

RFC 8617 §4.1.3 lists the AS's tags as `i`, `a`, `b`, `d`, `s` and **`t`**; RFC 6376
§3.5 marks `t=` **RECOMMENDED**. We emitted neither. Legal, but every ARC set we
produced carried no creation time — no forensics, and `x=` would be meaningless
without it. Fixing it was also the precondition for this suite to exist, since
reproducible output needs an injectable timestamp.

### A-19 — a chain already marked `cv=fail` was still extended (Medium)

RFC 8617 §5.1.3: *"A message can have only one Authenticated Received Chain on it at a
time. **Once broken, the chain cannot be continued**, as the chain of custody is no
longer valid, and responsibility for the message has been lost."* We added a set
anyway.

**The subtlety is the part worth keeping.** A chain that fails validation *here and
now* must still be sealed `cv=fail`, because that is what records the break for the
next hop. Only a break an *earlier* hop already recorded stops us sealing. The suite
separates the two directly — `i1_base_fail` and `i2_base_fail` expect a `cv=fail` set
to be added, `no_additional_sig` expects nothing at all — and getting it backwards
would suppress newly detected failures, which is the worse defect.

### A-20 — a `cv=fail` seal signed the prior chain (Medium) — *and the suite cannot see it*

RFC 8617 §5.1.2, a MUST that inverts the usual rule: *"In the case of a failed
Authenticated Received Chain, the header fields included in the signature scope of the
AS header field b= value MUST only include the ARC Set header fields created by the MTA
that detected the malformed chain, as if this newest ARC Set was the only set
present."* The reason is in the section's own note: for a malformed chain *"there is no
way to generate a deterministic set of AS header fields"*, so signing them yields a
signature no verifier can reconstruct. Our `cv=fail` seals were **unverifiable**, not
merely unusual.

**Reintroducing this defect leaves the suite at 17/17.** Measured, not assumed: for a
`cv=fail` chain a validator stops at the failed seal and never reaches ours, and `b=`
is not byte-comparable. An external suite of 17 cases *and* an independent validator
both miss it. The rule is therefore pinned by unit tests on `sealbuild.sealScope` —
which is why a one-line rule is its own named function.

> **When an oracle provably cannot see a defect, say so and pin it another way.** The
> alternative is a green suite standing in for coverage it does not have.

## Gate properties

| property | how it was verified |
|---|---|
| Independent | ValiMail generated the expected output; dkimpy validates ours |
| Committed | Suite and runner live here; keys come from the suite |
| Proven able to fail | `/usr/bin/true` → 16/17 fail, exit 1; three bug reintroductions |
| Correct exit status | Non-zero on any failure |
| Real component | The shipped `sealbuild.buildSet`, through a real `Connection` |

Bug reintroductions, all measured:

- **`t=` removed** → 16 failures, each naming `missing tag: t=12345`.
- **A-19 reverted** → `no_additional_sig` fails, *and* a unit test fails.
- **A-20 reverted** → **suite still 17/17**; two unit tests fail.
- **`/usr/bin/true`** → 16/17 fail, exit 1.

The honest limit: `no_additional_sig` **passes** against a stub, because producing
nothing is its pass condition and a stub produces nothing. That is inherent to
asserting "correctly added nothing", and the reason the other 16 carry the detection
load. The stub run also exposed a crash in this harness rather than a clean failure,
now fixed — which is the second thing pointing a suite at `/usr/bin/true` is for.

## Provenance

`arc-draft-sign-tests.yml` is vendored verbatim from ValiMail `arc_test_suite` commit
`f137dcb9d6d5baeef1310024ce9ccca94a9a92c8` (2018-11-23), MIT licensed — the same commit
as the validation half, under the same `LICENSE-valimail.txt`. Comparison semantics
follow the upstream runner `testarc.py` rather than a stricter rule of our own, with
the single documented departure for `b=` above.

### This file is fetched, not committed — and its key cannot be substituted

Run this once after cloning:

```sh
./fetch-vectors.sh          # downloads and checksum-verifies
./fetch-vectors.sh --check  # verifies only; for CI
```

**The file carries an RSA private key inline**, so the Forgejo `pre-receive` hook runs
gitleaks and rejects any push containing it. The hook does **not** honour a repository
`.gitleaksignore` — tried and confirmed. `securearc` was unpushable for ten commits
because of it.

**The checksum is what makes fetching equivalent to vendoring**, and it is the reason
this is not a retreat from the rule that a harness which is not committed is a claim
rather than a test. `fetch-vectors.sh` pins upstream commit
`f137dcb9d6d5baeef1310024ce9ccca94a9a92c8` and refuses any file whose SHA256 is not
`d56f156b8833939e4ad8a3a4b270e497a5a440eef8fb5aaf7a9a1b655869aeb8` — verified equal to
the copy that was previously committed here, byte for byte. That is a stronger
guarantee than the vendored copy gave, since a committed file can be edited and nothing
would notice; a wrong checksum stops the run.

The validation half stays committed, because it contains no key.

The obvious fix does not work, and the reason is worth recording so nobody spends the
afternoon on it again. **Generating a fresh keypair at run time and substituting both
halves fails `i=2 basic test`:**

```
AS: missing tag: cv=pass
AS: unexpected tag: cv=fail
dkimpy rejected the chain we sealed: cv=none reason=ARC-Seal[3] reported failure
```

`compare()` drops `b=` from both sides, so no *expected* value depends on which key
signs — that part of the reasoning is sound. What it misses is that **the fixture
messages already contain ARC sets signed by ValiMail's key**, and those resolve through
the same `dummy._domainkey.example.org` record our own seal uses. One record, two jobs.
Replace the key and the sealer can no longer validate the chain it is being asked to
extend, so it correctly seals `cv=fail` where the suite expects `cv=pass`.

So the key is load-bearing for the **input**, not for comparing our output. It has to
be the published one, which is why it is fetched rather than replaced.

**Storing the key in a form gitleaks does not pattern-match was rejected outright** —
stripping the PEM armour, or base64-wrapping the whole block, would have been a
two-line change and would have pushed cleanly. It defeats the control rather than
satisfying it, and it would teach the next *real* key to hide the same way.

The cost of the path taken is stated plainly: **the signing half no longer runs from a
bare clone**, and needs one network fetch first. `runsign.py` checks for the file and
prints the command instead of raising out of the YAML parser.
