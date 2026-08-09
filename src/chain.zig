const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const securemilter = @import("securemilter");
const dns_mod = securemilter.dns;
const deadline_mod = securemilter.deadline;

const securemilter_crypto = @import("securemilter_crypto");
const crypto = securemilter_crypto.crypto;
const canon = securemilter_crypto.canon;
const header_select = securemilter_crypto.header_select;
const sig_header = securemilter_crypto.sig_header;

const arc = @import("arc.zig");
const keycycle = @import("keycycle.zig");

// Owned by `keycycle.zig` since A-24, aliased here so the many uses below and the
// public surface `check.zig`/`seal_cli.zig` reach for both stay as they were.
const CheckOutcome = keycycle.CheckOutcome;
const classifyDataError = keycycle.classifyDataError;
pub const Policy = keycycle.Policy;
pub const DEFAULT_MAX_KEY_RECORDS = keycycle.DEFAULT_MAX_KEY_RECORDS;

/// Field name of an ARC header, for `header_select`.
fn amsHeaderName(hdr: arc.Header) []const u8 {
    return hdr.name;
}

/// Whether chain validation actually reached a verdict.
///
/// A `cv=` value asserts something about the message, and RFC 8617 §5.1.2 makes
/// `cv=fail` permanent for the life of that message: no later hop may revise it.
/// So a verdict must only be reported when it was genuinely determined. This
/// says whether it was (audit A-12).
pub const Evaluation = enum {
    /// Every signature was checked; `status` is a real verdict.
    complete,
    /// A signer's key could not be fetched because DNS failed transiently.
    /// Nothing is known about the chain, and `status` is `.unknown`.
    dns_temp_error,
    /// A local fault — an allocation, or a crypto primitive failing on our side.
    /// Our problem rather than the sender's, and never chargeable to the chain
    /// (audit A-12a).
    internal_error,
    /// The evaluation's own wall-clock budget ran out (X-21). Not a verdict:
    /// the chain was not fully checked, so `status` is `.unknown`. Distinct
    /// from `dns_temp_error` because the operator response differs -- one is
    /// their resolver, the other is our budget.
    deadline_exceeded,
};

/// Result of validating an ARC chain.
pub const ValidationResult = struct {
    status: arc.ChainValidation,
    highest_instance: u8,
    failure_reason: ?[]const u8,
    /// Whether `status` is a determination or a placeholder. Callers MUST check
    /// this before acting on `status`: a transient DNS failure previously
    /// arrived here indistinguishable from a forged signature, and both were
    /// reported as `fail` (audit A-12).
    evaluation: Evaluation = .complete,
};

/// Classify a failure from the resolver.
///
/// Order matters. `OutOfMemory` can surface from the resolver as readily as from
/// anywhere else, and `isTransientError` would call it transient — it treats
/// everything except an authoritative "no such name" as transient, which is the
/// right default for DNS but wrong for a local allocation failure. Checking for
/// it first keeps our own faults out of the DNS bucket.
fn classifyDnsError(err: anyerror) CheckOutcome {
    if (err == error.OutOfMemory) return .internal_error;
    return if (dns_mod.isTransientError(err)) .dns_temp_error else .fail;
}

/// Validate an ARC chain per RFC 8617 §5.2.
///
/// Steps:
/// 1. Verify ARC sets are complete and ordered (i=1..N, no gaps)
/// 2. For each ARC set, verify the ARC-Message-Signature (same as DKIM verify)
/// 3. For each ARC set, verify the ARC-Seal (signs over all prior ARC headers)
/// 4. Check cv= values: i=1 must be "none", i>1 must be "pass"
/// 5. If any step fails, result is "fail"
pub fn validateChain(
    allocator: Allocator,
    resolver: *dns_mod.Resolver,
    sets: []const arc.ArcSet,
    all_headers: []const arc.Header,
    body_data: []const u8,
    policy: Policy,
) ValidationResult {
    // X-21: one deadline for the whole walk, set at the start. An N-set chain
    // spends N+1 key fetches; the per-selector cap (MaxKeyRecords) bounds the
    // work of each, and this bounds the time of all of them together. Expiry
    // is never a verdict against the chain -- it maps to the same "we could
    // not check" answer as a transient DNS failure, but stays distinguishable
    // in the log.
    return validateChainInner(
        allocator,
        resolver,
        sets,
        all_headers,
        body_data,
        policy,
        deadline_mod.Deadline.fromNow(policy.max_evaluation_ms),
    );
}

/// The walk, with the deadline as a parameter. Public callers go through
/// `validateChain`; tests inject `Deadline.initAbsolute(0)` so expiry is
/// deterministic -- no sleep, no clock control, no slow resolver to lean on.
fn validateChainInner(
    allocator: Allocator,
    resolver: *dns_mod.Resolver,
    sets: []const arc.ArcSet,
    all_headers: []const arc.Header,
    body_data: []const u8,
    policy: Policy,
    deadline: deadline_mod.Deadline,
) ValidationResult {
    if (sets.len == 0) {
        return .{ .status = .none, .highest_instance = 0, .failure_reason = null };
    }

    // Step 1: Verify completeness — sets must be sequential starting at 1
    for (sets, 0..) |set, idx| {
        if (set.instance != @as(u8, @intCast(idx)) + 1) {
            return .{
                .status = .fail,
                .highest_instance = @intCast(idx),
                .failure_reason = "instance gap in ARC chain",
            };
        }
        // Each set must have all 3 headers
        if (set.aar_value.len == 0 or set.ams_value.len == 0 or set.as_value.len == 0) {
            return .{
                .status = .fail,
                .highest_instance = set.instance,
                .failure_reason = "incomplete ARC set",
            };
        }
    }

    // Step 2: Check cv= values
    if (sets[0].seal_cv != .none) {
        return .{
            .status = .fail,
            .highest_instance = 1,
            .failure_reason = "first ARC-Seal cv must be none",
        };
    }
    for (sets[1..]) |set| {
        if (set.seal_cv != .pass) {
            return .{
                .status = .fail,
                .highest_instance = set.instance,
                .failure_reason = "ARC-Seal cv must be pass for i>1",
            };
        }
    }

    // Step 3: Verify the most recent AMS (i=N) — validates message integrity
    if (deadline.expired()) return .{
        .status = .unknown,
        .highest_instance = sets[sets.len - 1].instance,
        .failure_reason = "evaluation deadline exceeded before the AMS check",
        .evaluation = .deadline_exceeded,
    };
    const newest = sets[sets.len - 1];
    var ams_reason: ?[]const u8 = null;
    switch (verifyAms(allocator, resolver, &newest, all_headers, body_data, policy, &ams_reason)) {
        .pass => {},
        .fail => return .{
            .status = .fail,
            .highest_instance = newest.instance,
            .failure_reason = ams_reason orelse "AMS verification failed for newest set",
        },
        // Not a verdict. `unknown` rather than `fail`, because we do not know
        // that the chain is broken — we know we could not check it (audit A-12).
        .dns_temp_error => return .{
            .status = .unknown,
            .highest_instance = newest.instance,
            .failure_reason = ams_reason orelse "DNS lookup for the AMS key failed transiently",
            .evaluation = .dns_temp_error,
        },
        .internal_error => return .{
            .status = .unknown,
            .highest_instance = newest.instance,
            .failure_reason = "internal error validating the AMS",
            .evaluation = .internal_error,
        },
    }

    // Step 4: Verify each ARC-Seal (validates chain integrity)
    for (sets) |set| {
        // The deadline is checked per seal: each iteration spends a key fetch,
        // so this is the point where a slow resolver would otherwise be
        // re-entered without limit.
        if (deadline.expired()) return .{
            .status = .unknown,
            .highest_instance = set.instance,
            .failure_reason = "evaluation deadline exceeded during ARC-Seal checks",
            .evaluation = .deadline_exceeded,
        };
        var seal_reason: ?[]const u8 = null;
        switch (verifySeal(allocator, resolver, &set, sets[0..set.instance], policy, &seal_reason)) {
            .pass => {},
            .fail => return .{
                .status = .fail,
                .highest_instance = set.instance,
                .failure_reason = seal_reason orelse "ARC-Seal verification failed",
            },
            .dns_temp_error => return .{
                .status = .unknown,
                .highest_instance = set.instance,
                .failure_reason = seal_reason orelse "DNS lookup for the ARC-Seal key failed transiently",
                .evaluation = .dns_temp_error,
            },
            .internal_error => return .{
                .status = .unknown,
                .highest_instance = set.instance,
                .failure_reason = "internal error validating an ARC-Seal",
                .evaluation = .internal_error,
            },
        }
    }

    return .{
        .status = .pass,
        .highest_instance = newest.instance,
        .failure_reason = null,
    };
}

/// Verify an ARC-Message-Signature (same algorithm as DKIM-Signature verification).
///
/// Fetches the public key via DNS: <selector>._domainkey.<domain> TXT
/// Then verifies the signature over canonicalized headers + body hash.
/// `reason`, when set, replaces the caller's generic failure message. Most
/// failures here are genuinely "the signature did not verify" and leave it
/// alone; a key refused on policy grounds is worth naming, because the fix
/// belongs to the signing hop and nobody can act on it unless it is reported.
fn verifyAms(
    allocator: Allocator,
    resolver: *dns_mod.Resolver,
    set: *const arc.ArcSet,
    all_headers: []const arc.Header,
    body_data: []const u8,
    policy: Policy,
    reason: *?[]const u8,
) CheckOutcome {
    // RFC 6376 §3.5 makes a= REQUIRED, and this daemon implements exactly one
    // algorithm, so anything else names something it cannot compute. Checked
    // before the DNS lookup so a signature we could never verify does not cost a
    // query -- and reported as `fail`, not `internal_error`, because the
    // unsupported algorithm is the signer's choice and not our fault (A-12a).
    if (!isSupportedAlgorithm(set.ams_algorithm)) {
        reason.* = if (set.ams_algorithm.len == 0)
            "AMS has no a= algorithm tag"
        else
            "AMS a= names an unsupported algorithm";
        return .fail;
    }

    // RFC 8617 §4.1.2 forbids an AMS from covering ARC header fields. Only
    // ARC-Seal is enforced -- see `signsArcSeal` for why the other two are not.
    if (signsArcSeal(set.ams_signed_headers)) {
        reason.* = "AMS h= covers ARC-Seal";
        return .fail;
    }

    // Fetch public key from DNS
    const qname = std.fmt.allocPrint(allocator, "{s}._domainkey.{s}", .{
        set.ams_selector,
        set.ams_domain,
    }) catch return .internal_error;
    defer allocator.free(qname);

    var dns_result = resolver.resolve(qname, .TXT) catch |err| {
        const outcome = classifyDnsError(err);
        if (outcome == .dns_temp_error) {
            reason.* = "DNS lookup for the AMS key failed transiently";
        }
        return outcome;
    };
    defer dns_result.deinit();

    // The name resolved but publishes no usable p=. That is the signer's record
    // saying the key is not there, which is permanent, so it is settled before any
    // key-independent work is spent below.
    if (!keycycle.hasUsableKey(&dns_result)) {
        reason.* = "AMS key record has no p= value";
        return .fail;
    }

    // The AMS has the same syntax and semantics as a DKIM-Signature (RFC 8617
    // §4.1.2), so its c= tag governs both halves of canonicalization and an
    // absent c= means simple/simple (RFC 6376 §3.5) -- not relaxed/relaxed.
    //
    // A c= this daemon cannot parse names an algorithm it cannot perform, so the
    // signature cannot be checked and cannot be honoured. That is a property of
    // the signature rather than of this host, so it is the signer's failure and
    // `fail` is the honest verdict -- not `internal_error`, which A-12 reserves
    // for our own faults, and not a silent guess at relaxed/relaxed, which used
    // to compute a hash against an algorithm the signer never used (audit A-5).
    const canon_pair = canon.parseCanonicalization(set.ams_canonicalization) catch {
        reason.* = "AMS c= names an unknown canonicalization";
        return .fail;
    };

    // Build signing input: canonicalize headers per h= tag + AMS header with empty b=
    const signing_input = buildAmsSigningInput(allocator, set, all_headers, canon_pair.header) catch |err|
        return classifyDataError(err);
    defer allocator.free(signing_input);

    // Canonicalize body and compute SHA-256 hash, then compare against claimed bh=
    var body_canon = canon.BodyCanonicalizer.init(allocator, canon_pair.body);
    defer body_canon.deinit();
    // Canonicalizing our own accumulated body can only fail on allocation.
    body_canon.update(body_data) catch |err| return classifyDataError(err);
    const canon_body = body_canon.finish() catch |err| return classifyDataError(err);
    defer allocator.free(canon_body);
    const computed_hash = crypto.sha256(canon_body);

    const claimed_bh = crypto.base64Decode(allocator, set.ams_body_hash) catch |err|
        return classifyDataError(err);
    defer allocator.free(claimed_bh);
    if (claimed_bh.len != computed_hash.len) return .fail;
    if (!mem.eql(u8, claimed_bh, &computed_hash)) return .fail;

    // Decode signature from base64
    const sig_bytes = crypto.base64Decode(allocator, set.ams_signature) catch |err|
        return classifyDataError(err);
    defer allocator.free(sig_bytes);

    // Everything above is key-independent and has now been done exactly once.
    // What repeats inside is only the public-key operation, which is irreducible:
    // deciding whether a given key verifies this signature IS the question.
    return keycycle.tryKeys(
        allocator,
        &dns_result,
        signing_input,
        sig_bytes,
        policy,
        keycycle.AMS_LABELS,
        reason,
    );
}

/// Build the signing input for AMS verification.
///
/// Canonicalizes the headers listed in the h= tag under `header_canon` -- which
/// comes from the AMS's own c= tag, not a fixed choice -- then appends the AMS
/// header itself with the b= value removed, under the same algorithm.
///
/// `header_canon` is a parameter rather than read from `set` here so that the
/// one place that interprets c= is the caller, next to where the body half of
/// the same tag is applied. Splitting the two halves across two functions is how
/// they came to disagree in the first place (audit A-5).
fn buildAmsSigningInput(
    allocator: Allocator,
    set: *const arc.ArcSet,
    all_headers: []const arc.Header,
    header_canon: canon.Algorithm,
) ![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .{};
    errdefer buf.deinit(allocator);

    // RFC 8617 inherits DKIM's signing rules, so the AMS `h=` tag selects header
    // instances exactly as a DKIM `h=` does: a repeated name walks up from the
    // bottom, and a mention with no instance left contributes nothing. This loop
    // used to take the last match for every mention, which is the same defect as
    // D-1 and made an oversigned AMS impossible to validate (audit A-6).
    var walk = header_select.walker(arc.Header, amsHeaderName, set.ams_signed_headers, all_headers);
    while (walk.next()) |hdr| {
        const full = try hdr.render(allocator);
        defer allocator.free(full);
        const canonicalized = try canon.canonicalizeHeader(allocator, header_canon, full);
        defer allocator.free(canonicalized);
        try buf.appendSlice(allocator, canonicalized);
        try buf.appendSlice(allocator, "\r\n");
    }

    // Append AMS header with b= value emptied (for self-referencing signature).
    // Rendered as it arrived: the AMS covers itself, so under `c=simple` its own
    // separator is hashed verbatim (audit D-23).
    const ams_hdr = arc.Header{ .name = "ARC-Message-Signature", .value = set.ams_value, .had_space = set.ams_had_space };
    const ams_full = ams_hdr.render(allocator) catch return error.OutOfMemory;
    defer allocator.free(ams_full);

    // Remove the b= value: replace "b=<sig>" with "b=". Allocation failure used
    // to fall through to the header WITH its signature still in it, which does
    // not fail -- it hashes different bytes, so a good signature reads as bad and
    // the chain is sealed cv=fail, which RFC 8617 §5.1.2 makes permanent for the
    // life of the message. Same class as X-10.
    const stripped = try sig_header.emptyBValue(allocator, ams_full);
    defer allocator.free(stripped);

    // The AMS header field is itself one of the fields the signature covers, so
    // it takes the same canonicalization as the rest of them (audit A-5).
    const canon_ams = canon.canonicalizeHeader(allocator, header_canon, stripped) catch
        return error.OutOfMemory;
    defer allocator.free(canon_ams);
    try buf.appendSlice(allocator, canon_ams);

    return buf.toOwnedSlice(allocator);
}

/// Verify an ARC-Seal signature.
///
/// The seal signs over ALL prior ARC headers (AAR, AMS, AS) for instances
/// 1..i-1, plus the current instance's AAR and AMS (but NOT the current AS
/// being verified — that would be circular).
/// See `verifyAms` for the meaning of `reason`.
fn verifySeal(
    allocator: Allocator,
    resolver: *dns_mod.Resolver,
    set: *const arc.ArcSet,
    prior_sets: []const arc.ArcSet,
    policy: Policy,
    reason: *?[]const u8,
) CheckOutcome {
    // Same requirement as the AMS: RFC 8617 §4.1.3 gives the AS a DKIM-style a=
    // tag, and an algorithm this daemon does not implement cannot be checked.
    if (!isSupportedAlgorithm(set.seal_algorithm)) {
        reason.* = if (set.seal_algorithm.len == 0)
            "ARC-Seal has no a= algorithm tag"
        else
            "ARC-Seal a= names an unsupported algorithm";
        return .fail;
    }

    // RFC 8617 §4.1.3 on the DKIM `h` tag: it "is NOT allowed and, if found, MUST
    // result in a cv status of fail" (audit A-13).
    //
    // The verdict was already `fail`, but by accident -- nothing read `h=` on an AS,
    // the fixed §5.1.1 scope was used regardless, so such a seal hashed differently
    // and failed to verify. Right answer, wrong reason, and the accident points the
    // wrong way: the day the AS scope honours `h=`, a sealer could choose which ARC
    // headers its own seal covers, which is the one property the chain exists to deny.
    if (sealCarriesH(set.as_value)) {
        reason.* = "ARC-Seal carries a forbidden h= tag (RFC 8617 4.1.3)";
        return .fail;
    }

    // Fetch public key
    const qname = std.fmt.allocPrint(allocator, "{s}._domainkey.{s}", .{
        set.seal_selector,
        set.seal_domain,
    }) catch return .internal_error;
    defer allocator.free(qname);

    var dns_result = resolver.resolve(qname, .TXT) catch |err| {
        const outcome = classifyDnsError(err);
        if (outcome == .dns_temp_error) {
            reason.* = "DNS lookup for the ARC-Seal key failed transiently";
        }
        return outcome;
    };
    defer dns_result.deinit();

    // As on the AMS path, and for the same reason.
    if (!keycycle.hasUsableKey(&dns_result)) {
        reason.* = "ARC-Seal key record has no p= value";
        return .fail;
    }

    // Build seal signing input: all prior ARC headers (relaxed canonicalized)
    // in order (AAR, AMS, AS for each prior instance), plus current AAR + AMS
    const signing_input = buildSealSigningInput(allocator, set, prior_sets) catch |err|
        return classifyDataError(err);
    defer allocator.free(signing_input);

    // Decode signature
    const sig_bytes = crypto.base64Decode(allocator, set.seal_signature) catch |err|
        return classifyDataError(err);
    defer allocator.free(sig_bytes);

    // Key-independent work is done; cycle the candidates (A-24).
    return keycycle.tryKeys(
        allocator,
        &dns_result,
        signing_input,
        sig_bytes,
        policy,
        keycycle.SEAL_LABELS,
        reason,
    );
}

/// Build the seal signing input per RFC 8617 §5.1.1.
/// Order: for each instance 1..i, canonicalize AAR, AMS, AS headers.
/// For the current instance (last in prior_sets), include AAR + AMS but NOT AS
/// (the seal signs over everything except itself).
///
/// **Always relaxed here, and deliberately so.** The seal is not DKIM-like in
/// this respect: RFC 8617 §4.1.3 says that for the ARC-Seal "only 'relaxed'
/// header field canonicalization is used", and the AS carries no c= tag to say
/// otherwise. So the fixed algorithm below is correct, unlike the fixed
/// algorithm the AMS path used to have, which A-5 removed. Do not make this
/// configurable to match the AMS.
fn buildSealSigningInput(
    allocator: Allocator,
    set: *const arc.ArcSet,
    prior_sets: []const arc.ArcSet,
) ![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .{};
    errdefer buf.deinit(allocator);

    // Prior sets (i=1..i-1): include all 3 headers for each
    for (prior_sets) |prior| {
        if (prior.instance >= set.instance) break;
        try appendCanonHeader(allocator, &buf, "ARC-Authentication-Results", prior.aar_value);
        try appendCanonHeader(allocator, &buf, "ARC-Message-Signature", prior.ams_value);
        try appendCanonHeader(allocator, &buf, "ARC-Seal", prior.as_value);
    }

    // Current instance: AAR + AMS only (not the AS being verified)
    try appendCanonHeader(allocator, &buf, "ARC-Authentication-Results", set.aar_value);
    try appendCanonHeader(allocator, &buf, "ARC-Message-Signature", set.ams_value);

    // Append AS header with empty b= (self-referencing)
    const as_full = try std.fmt.allocPrint(allocator, "ARC-Seal: {s}", .{set.as_value});
    defer allocator.free(as_full);
    const stripped = try sig_header.emptyBValue(allocator, as_full);
    defer allocator.free(stripped);

    const canon_as = try canon.canonicalizeHeader(allocator, .relaxed, stripped);
    defer allocator.free(canon_as);
    try buf.appendSlice(allocator, canon_as);

    return buf.toOwnedSlice(allocator);
}

/// Canonicalize a header and append it (with CRLF) to the buffer.
fn appendCanonHeader(
    allocator: Allocator,
    buf: *std.ArrayListUnmanaged(u8),
    name: []const u8,
    value: []const u8,
) !void {
    const full = try std.fmt.allocPrint(allocator, "{s}: {s}", .{ name, value });
    defer allocator.free(full);
    const canonicalized = try canon.canonicalizeHeader(allocator, .relaxed, full);
    defer allocator.free(canonicalized);
    try buf.appendSlice(allocator, canonicalized);
    try buf.appendSlice(allocator, "\r\n");
}

/// Is `a=` an algorithm this daemon can actually verify?
///
/// Exactly `rsa-sha256`. The verification path is `loadRsaPublicKeyDer` plus
/// `rsaVerify` over a SHA-256 digest, so RSA-SHA256 is the only thing it can
/// compute -- there is no Ed25519 path here to fall through to. `rsa-sha1` is
/// deliberately absent even though RFC 6376 §3.5 lists it: RFC 8301 §3.1 says
/// signers must not use it and verifiers must treat it as a failure.
///
/// Compared case sensitively, because RFC 6376 §3.2 says "Values MUST be
/// processed as case sensitive unless the specific tag description of semantics
/// specifies otherwise", and §3.5's a= description says no such thing.
fn isSupportedAlgorithm(a: []const u8) bool {
    return mem.eql(u8, a, "rsa-sha256");
}

/// Does an AMS `h=` list cover ARC-Seal?
///
/// RFC 8617 §4.1.2 names all three ARC header fields as MUST NOT appear in an
/// AMS's covered-header list. **Only ARC-Seal is enforced here.** That paragraph
/// sits under "To reduce the chances of accidental invalidation of AMS
/// signatures", beside a SHOULD about attachment order, so it reads as guidance
/// to a *signer*; the normative validator algorithm is §5.2 and none of its steps
/// rejects a chain over the contents of `h=`.
///
/// The boundary was settled by measurement rather than by choosing a reading.
/// Enforcing all three took the ValiMail suite from 162/171 to **118/171**: the
/// suite's own base messages sign `arc-authentication-results` and expect `pass`,
/// so signing the AAR is normal practice and refusing it fails ordinary mail.
/// Enforcing ARC-Message-Signature as well still failed `ams_fields_h_includes_ams`,
/// which also expects `pass`. Only `ams_fields_h_includes_as` expects `fail`.
///
/// The asymmetry is not arbitrary. The AS is the one ARC field written *after*
/// the AMS in the same set, so an AMS covering ARC-Seal either reaches forward to
/// a field that did not exist when it was computed, or -- for i>1 -- pins a prior
/// hop's seal into this hop's message signature. Neither is reproducible by a
/// verifier rebuilding the signing input. Covering an earlier AMS or AAR is
/// merely inadvisable, and implementations accept it.
fn signsArcSeal(h_list: []const u8) bool {
    var it = mem.splitScalar(u8, h_list, ':');
    while (it.next()) |raw| {
        const name = mem.trim(u8, raw, &std.ascii.whitespace);
        if (arc.eqlLower(name, "ARC-Seal")) return true;
    }
    return false;
}

/// Does this ARC-Seal carry the forbidden DKIM `h` tag (audit A-13)?
///
/// Named rather than inlined so it is testable without a resolver, like `signsArcSeal`.
/// `findTag` matches whole tag names, so this does not fire on `bh=`, and tag names are
/// case sensitive per RFC 6376 §3.2, so `H=` is a different tag.
fn sealCarriesH(as_value: []const u8) bool {
    return arc.findTag(as_value, "h") != null;
}

// =============================================================================
// Tests
// =============================================================================

test "validateChain empty" {
    const sets: []const arc.ArcSet = &.{};
    const headers: []const arc.Header = &.{};
    const result = validateChain(std.testing.allocator, undefined, sets, headers, "", .{ .min_key_bits = crypto.RFC8301_MIN_RSA_BITS });
    try std.testing.expectEqual(arc.ChainValidation.none, result.status);
    try std.testing.expectEqual(@as(u8, 0), result.highest_instance);
}

test "validateChain cv=pass required for i>1" {
    // Construct a chain where i=2 has cv=none (invalid)
    const sets = [_]arc.ArcSet{
        .{
            .instance = 1,
            .aar_value = "i=1; test",
            .ams_value = "i=1; a=rsa-sha256; d=a.com; s=s1; b=x; bh=y; h=from",
            .as_value = "i=1; cv=none; a=rsa-sha256; d=a.com; s=s1; b=x",
            .seal_cv = .none,
            .seal_algorithm = "rsa-sha256",
            .seal_domain = "a.com",
            .seal_selector = "s1",
            .seal_signature = "x",
            .ams_algorithm = "rsa-sha256",
            .ams_domain = "a.com",
            .ams_selector = "s1",
            .ams_signature = "x",
            .ams_body_hash = "y",
            .ams_canonicalization = "relaxed/relaxed",
            .ams_signed_headers = "from",
        },
        .{
            .instance = 2,
            .aar_value = "i=2; test",
            .ams_value = "i=2; a=rsa-sha256; d=b.com; s=s1; b=x; bh=y; h=from",
            .as_value = "i=2; cv=none; a=rsa-sha256; d=b.com; s=s1; b=x",
            .seal_cv = .none, // Should be .pass for i=2
            .seal_algorithm = "rsa-sha256",
            .seal_domain = "b.com",
            .seal_selector = "s1",
            .seal_signature = "x",
            .ams_algorithm = "rsa-sha256",
            .ams_domain = "b.com",
            .ams_selector = "s1",
            .ams_signature = "x",
            .ams_body_hash = "y",
            .ams_canonicalization = "relaxed/relaxed",
            .ams_signed_headers = "from",
        },
    };

    const headers: []const arc.Header = &.{};
    const result = validateChain(std.testing.allocator, undefined, &sets, headers, "", .{ .min_key_bits = crypto.RFC8301_MIN_RSA_BITS });
    try std.testing.expectEqual(arc.ChainValidation.fail, result.status);
    try std.testing.expectEqualStrings("ARC-Seal cv must be pass for i>1", result.failure_reason.?);
    // A structural verdict is a real determination, not a placeholder.
    try std.testing.expectEqual(Evaluation.complete, result.evaluation);
}

// --- A-6: duplicate h= names select successive instances ---------------------

/// An ArcSet carrying only what `buildAmsSigningInput` reads.
fn amsSetWithSignedHeaders(h: []const u8) arc.ArcSet {
    return amsSetWith(h, "relaxed/relaxed");
}

/// As above, with an explicit c= value.
fn amsSetWith(h: []const u8, c: []const u8) arc.ArcSet {
    return .{
        .instance = 1,
        .aar_value = "i=1; test",
        .ams_value = "i=1; h=x; b=",
        .as_value = "i=1; cv=none",
        .seal_cv = .none,
        .seal_algorithm = "rsa-sha256",
        .seal_domain = "a.com",
        .seal_selector = "s1",
        .seal_signature = "x",
        .ams_algorithm = "rsa-sha256",
        .ams_domain = "a.com",
        .ams_selector = "s1",
        .ams_signature = "x",
        .ams_body_hash = "y",
        .ams_canonicalization = c,
        .ams_signed_headers = h,
    };
}

test "AMS h= repeated: successive instances bottom upward, not the same one twice" {
    // RFC 8617 inherits RFC 6376 §5.4.2. Asserted on the exact octet string,
    // because that is what gets hashed -- a substring check cannot see a header
    // counted twice (audit A-6).
    const allocator = std.testing.allocator;
    const set = amsSetWithSignedHeaders("from:from");
    const headers = [_]arc.Header{
        .{ .name = "From", .value = "top@example.com" },
        .{ .name = "From", .value = "bottom@example.com" },
    };

    const input = try buildAmsSigningInput(allocator, &set, &headers, .relaxed);
    defer allocator.free(input);

    try std.testing.expectEqualStrings(
        "from:bottom@example.com\r\n" ++
            "from:top@example.com\r\n" ++
            "arc-message-signature:i=1; h=x; b=",
        input,
    );
}

test "AMS h= oversigned: the surplus mention contributes nothing" {
    // One From, named twice. The second mention is the null input of RFC 6376
    // §3.7, so the field is hashed once. Hashing it twice, as this used to,
    // makes every oversigned AMS fail validation.
    const allocator = std.testing.allocator;
    const set = amsSetWithSignedHeaders("from:from");
    const headers = [_]arc.Header{
        .{ .name = "From", .value = "only@example.com" },
    };

    const input = try buildAmsSigningInput(allocator, &set, &headers, .relaxed);
    defer allocator.free(input);

    try std.testing.expectEqualStrings(
        "from:only@example.com\r\narc-message-signature:i=1; h=x; b=",
        input,
    );
}

// --- A-5: the AMS c= tag governs header canonicalization -----------------------

test "simple header canonicalization is preserved exactly, not lowercased" {
    // The whole difference: relaxed lowercases the field name and strips the
    // space after the colon, simple changes nothing at all (RFC 6376 §3.4.1).
    // Forcing relaxed on a signature that said simple hashes bytes the signer
    // never hashed, so a legitimate AMS could not verify (audit A-5).
    const allocator = std.testing.allocator;
    const set = amsSetWith("from", "simple/simple");
    const headers = [_]arc.Header{
        .{ .name = "From", .value = "User@Example.COM" },
    };

    const input = try buildAmsSigningInput(allocator, &set, &headers, .simple);
    defer allocator.free(input);

    // Field name case kept, single space after the colon kept, and the AMS
    // header itself takes the same treatment rather than being relaxed.
    try std.testing.expectEqualStrings(
        "From: User@Example.COM\r\nARC-Message-Signature: i=1; h=x; b=",
        input,
    );
}

test "relaxed and simple produce different bytes for the same message" {
    // Guards against the two algorithms being wired to the same implementation:
    // if these ever match, honouring c= has stopped meaning anything.
    const allocator = std.testing.allocator;
    const set = amsSetWith("from", "simple/simple");
    const headers = [_]arc.Header{
        .{ .name = "From", .value = "User@Example.COM" },
    };

    const as_simple = try buildAmsSigningInput(allocator, &set, &headers, .simple);
    defer allocator.free(as_simple);
    const as_relaxed = try buildAmsSigningInput(allocator, &set, &headers, .relaxed);
    defer allocator.free(as_relaxed);

    try std.testing.expect(!std.mem.eql(u8, as_simple, as_relaxed));
}

test "an absent c= means simple/simple, not relaxed/relaxed" {
    // RFC 6376 §3.5: c= defaults to simple/simple. A sealer that omits the tag
    // entirely is legal and common, and used to false-fail here because the body
    // half honoured the default while the header half was forced to relaxed.
    const pair = try canon.parseCanonicalization("");
    try std.testing.expectEqual(canon.Algorithm.simple, pair.header);
    try std.testing.expectEqual(canon.Algorithm.simple, pair.body);
}

test "a c= naming only the header algorithm leaves the body simple" {
    const pair = try canon.parseCanonicalization("relaxed");
    try std.testing.expectEqual(canon.Algorithm.relaxed, pair.header);
    try std.testing.expectEqual(canon.Algorithm.simple, pair.body);
}

test "an unparseable c= is the signer's failure, not ours" {
    // It names an algorithm this daemon cannot perform, so the signature cannot
    // be checked. Guessing relaxed/relaxed and hashing against an algorithm the
    // signer never used is what A-5 removed.
    try std.testing.expectError(
        error.InvalidCanonicalization,
        canon.parseCanonicalization("relaxed/wobbly"),
    );
    try std.testing.expectError(
        error.InvalidCanonicalization,
        canon.parseCanonicalization("wobbly"),
    );
}

// --- A-12 / A-12a: an unevaluable chain is not a failed chain -----------------

test "classifyDnsError keeps our own allocation failure out of the DNS bucket" {
    // The ordering that matters: isTransientError calls everything except
    // DnsNameError transient, so OutOfMemory would be reported as a nameserver
    // problem and, under On-DNSError=tempfail, defer mail because *we* ran out
    // of memory. It must be internal instead (audit A-12a).
    try std.testing.expectEqual(CheckOutcome.internal_error, classifyDnsError(error.OutOfMemory));
    try std.testing.expectEqual(CheckOutcome.dns_temp_error, classifyDnsError(error.DnsServerFailure));
    try std.testing.expectEqual(CheckOutcome.dns_temp_error, classifyDnsError(error.ConnectionRefused));
    // An authoritative "no such name" is the signer saying the key is absent.
    try std.testing.expectEqual(CheckOutcome.fail, classifyDnsError(error.DnsNameError));
}

test "classifyDataError blames the publisher for malformed data, us for OOM" {
    try std.testing.expectEqual(CheckOutcome.internal_error, classifyDataError(error.OutOfMemory));
    try std.testing.expectEqual(CheckOutcome.fail, classifyDataError(error.InvalidCharacter));
    try std.testing.expectEqual(CheckOutcome.fail, classifyDataError(error.RsaKeyTooSmall));
}

test "X-21: an expired deadline stops the walk before any DNS, and is not a verdict" {
    // The deadline is injected as already expired, so this is deterministic.
    // `undefined` for the resolver is the assertion, as in the A-13 test:
    // reaching DNS would crash, so passing IS the proof the budget was checked
    // first.
    const sets = [_]arc.ArcSet{.{
        .instance = 1,
        .aar_value = "i=1; mail.example.org; spf=none",
        .ams_value = "i=1; a=rsa-sha256; d=example.org; s=sel; b=abc; bh=y; h=from",
        .as_value = "i=1; cv=none; a=rsa-sha256; d=example.org; s=sel; b=abc",
        .seal_cv = .none,
        .seal_algorithm = "rsa-sha256",
        .seal_domain = "example.org",
        .seal_selector = "sel",
        .seal_signature = "abc",
        .ams_algorithm = "rsa-sha256",
        .ams_domain = "example.org",
        .ams_selector = "sel",
        .ams_signature = "abc",
        .ams_body_hash = "y",
        .ams_canonicalization = "relaxed/relaxed",
        .ams_signed_headers = "from",
    }};

    const headers: []const arc.Header = &.{};
    const result = validateChainInner(
        std.testing.allocator,
        undefined,
        &sets,
        headers,
        "body",
        .{ .min_key_bits = crypto.RFC8301_MIN_RSA_BITS },
        deadline_mod.Deadline.initAbsolute(0),
    );
    try std.testing.expectEqual(Evaluation.deadline_exceeded, result.evaluation);
    try std.testing.expectEqual(arc.ChainValidation.unknown, result.status);
}

test "validateChain reports unknown/dns_temp_error when the key lookup fails transiently" {
    // A single well-formed set whose AMS key can never be fetched: the resolver
    // points at a port nothing listens on, with no retries and a short timeout.
    // Before A-12 this produced cv=fail, which RFC 8617 5.1.2 makes permanent —
    // so one nameserver blip destroyed a legitimate chain for good.
    const sets = [_]arc.ArcSet{.{
        .instance = 1,
        .aar_value = "i=1; test",
        .ams_value = "i=1; a=rsa-sha256; d=a.com; s=s1; b=x; bh=y; h=from",
        .as_value = "i=1; cv=none; a=rsa-sha256; d=a.com; s=s1; b=x",
        .seal_cv = .none,
        .seal_algorithm = "rsa-sha256",
        .seal_domain = "a.com",
        .seal_selector = "s1",
        .seal_signature = "x",
        .ams_algorithm = "rsa-sha256",
        .ams_domain = "a.com",
        .ams_selector = "s1",
        .ams_signature = "x",
        .ams_body_hash = "y",
        .ams_canonicalization = "relaxed/relaxed",
        .ams_signed_headers = "from",
    }};

    var resolver = dns_mod.Resolver.init(std.testing.allocator, .{
        .nameservers = &.{"127.0.0.1"},
        .port = 1,
        .timeout_ms = 50,
        .retries = 0,
    });
    defer resolver.deinit();

    const headers: []const arc.Header = &.{};
    const result = validateChain(
        std.testing.allocator,
        &resolver,
        &sets,
        headers,
        "body",
        .{ .min_key_bits = crypto.RFC8301_MIN_RSA_BITS },
    );

    try std.testing.expectEqual(Evaluation.dns_temp_error, result.evaluation);
    // Not `fail`: we do not know the chain is broken, only that we could not
    // check it. The caller decides what to do about that.
    try std.testing.expectEqual(arc.ChainValidation.unknown, result.status);
    try std.testing.expect(result.failure_reason != null);
}

// --- ValiMail conformance: a= validation and the AMS h= rule ------------------

test "isSupportedAlgorithm accepts only rsa-sha256" {
    try std.testing.expect(isSupportedAlgorithm("rsa-sha256"));

    // An absent a= and an unrecognised one are both unusable: the verifier can
    // only compute RSA over SHA-256, so anything else names an algorithm it
    // cannot perform. Previously neither was checked and the signature was
    // verified as though it had said rsa-sha256 -- so a signature claiming
    // `a=rsa-poptart` was honoured. Suite cases: ams_fields_a_empty,
    // ams_fields_a_unknown, as_fields_a_empty, as_fields_a_unknown.
    try std.testing.expect(!isSupportedAlgorithm(""));
    try std.testing.expect(!isSupportedAlgorithm("rsa-poptart"));
    try std.testing.expect(!isSupportedAlgorithm("rsa-sha42"));
    try std.testing.expect(!isSupportedAlgorithm("ed25519-sha256"));

    // RFC 8301 3.1: signers MUST NOT use rsa-sha1 and verifiers MUST treat it as
    // a failure, even though RFC 6376 3.5 still lists it.
    try std.testing.expect(!isSupportedAlgorithm("rsa-sha1"));

    // Case sensitive, per RFC 6376 3.2 on tag values.
    try std.testing.expect(!isSupportedAlgorithm("RSA-SHA256"));
    try std.testing.expect(!isSupportedAlgorithm("rsa-SHA256"));
}

test "AMS h= may cover AAR and AMS but not ARC-Seal" {
    // Only ARC-Seal is refused. The other two are accepted deliberately: the
    // suite's own base messages sign arc-authentication-results and expect pass,
    // and ams_fields_h_includes_ams expects pass as well. Enforcing the whole of
    // RFC 8617 4.1.2 as a verifier rule scored 118/171.
    try std.testing.expect(!signsArcSeal("from:to:date:subject:mime-version"));
    try std.testing.expect(!signsArcSeal("from:to:arc-authentication-results"));
    try std.testing.expect(!signsArcSeal("from:arc-message-signature"));

    // ams_fields_h_includes_as expects fail.
    try std.testing.expect(signsArcSeal("from:to:arc-seal"));
    // Header field names are case insensitive (RFC 5322), unlike tag names.
    try std.testing.expect(signsArcSeal("from:ARC-Seal"));
    try std.testing.expect(signsArcSeal("ARC-SEAL"));
    // Whitespace around a name in the list is permitted by RFC 6376 3.5's h=.
    try std.testing.expect(signsArcSeal("from : arc-seal : to"));

    // A name that merely starts the same must not match.
    try std.testing.expect(!signsArcSeal("from:arc-sealed-with-a-kiss"));
}

// A-13. The counterpart to the test above: that one is about what an AMS may cover,
// this one about a tag an ARC-Seal may not carry at all.
test "A-13: an h= tag on an ARC-Seal is detected" {
    // A well-formed seal. No h=, so nothing to refuse.
    try std.testing.expect(!sealCarriesH("i=1; a=rsa-sha256; c=none; d=example.org; s=sel; t=1; cv=none; b=abc"));
    try std.testing.expect(!sealCarriesH(""));

    // Present in any position, including last, which a scan that stopped at the
    // first unrecognised tag would miss.
    try std.testing.expect(sealCarriesH("i=1; a=rsa-sha256; h=from:to; cv=none; b=abc"));
    try std.testing.expect(sealCarriesH("h=from; i=1; a=rsa-sha256; cv=none; b=abc"));
    try std.testing.expect(sealCarriesH("i=1; a=rsa-sha256; cv=none; b=abc; h=from"));

    // THE ONE THAT WOULD BITE. `bh=` is a legitimate tag name that ENDS in the
    // forbidden one, so a substring search would refuse every ordinary seal that
    // carried it -- turning a MUST-fail rule into a deny-everything bug. `findTag`
    // compares whole names, and this pins that.
    try std.testing.expect(!sealCarriesH("i=1; a=rsa-sha256; bh=xyz; cv=none; b=abc"));

    // Likewise a tag that merely starts with `h`.
    try std.testing.expect(!sealCarriesH("i=1; a=rsa-sha256; hash=sha256; cv=none; b=abc"));

    // Case sensitive per RFC 6376 §3.2, so `H=` is a different (unrecognised) tag.
    try std.testing.expect(!sealCarriesH("i=1; a=rsa-sha256; H=from; cv=none; b=abc"));

    // Whitespace around the name, which RFC 6376 §3.2's FWS permits.
    try std.testing.expect(sealCarriesH("i=1; a=rsa-sha256;  h = from ; cv=none; b=abc"));
}

// A-13, the wiring rather than the predicate. The test above would pass with the
// check present but never called, and the ValiMail suite does NOT cover this: its
// `as_fields_h_present` case looks like it does, but the mock resolver returns
// NXDOMAIN for `test._domainkey.example.com`, so the AMS fails at its key lookup and
// `verifySeal` is never reached. Confirmed by making this branch return
// `internal_error` (which maps to cv=unknown, not cv=fail) and watching the suite
// still score 171/171.
//
// `undefined` for the resolver is the assertion, not a shortcut: reaching DNS would
// segfault, so passing this test IS the proof that the refusal happens before any
// query is spent. Same device `validateChain empty` uses.
//
// Verified by deleting the call site: this then dies with a bus error inside
// `resolver.resolve`, not with a tidy assertion failure. That is the intended
// mechanism, so do not "fix" a crash here by handing it a real resolver -- the crash
// is what proves no query was spent.
test "A-13: verifySeal refuses a sealed h= before it spends a DNS query" {
    const set = arc.ArcSet{
        .instance = 1,
        .aar_value = "",
        .ams_value = "",
        // The forbidden tag, on an otherwise well-formed seal.
        .as_value = "i=1; a=rsa-sha256; d=example.org; s=sel; cv=none; h=from:to; b=abc",
        .seal_cv = .none,
        .seal_algorithm = "rsa-sha256",
        .seal_domain = "example.org",
        .seal_selector = "sel",
        .seal_signature = "abc",
        .ams_algorithm = "rsa-sha256",
        .ams_domain = "example.org",
        .ams_selector = "sel",
        .ams_signature = "",
        .ams_body_hash = "",
        .ams_canonicalization = "relaxed/relaxed",
        .ams_signed_headers = "from",
    };

    var reason: ?[]const u8 = null;
    const outcome = verifySeal(std.testing.allocator, undefined, &set, &.{}, .{ .min_key_bits = crypto.RFC8301_MIN_RSA_BITS }, &reason);

    try std.testing.expectEqual(CheckOutcome.fail, outcome);
    try std.testing.expect(reason != null);
    try std.testing.expect(mem.indexOf(u8, reason.?, "h=") != null);

    // And the same seal without the tag gets past this check -- so the refusal is
    // the `h=`, not something else about the fixture. It reaches the resolver, which
    // is `undefined` here, so it cannot be called: only the negative is asserted.
    var without = set;
    without.as_value = "i=1; a=rsa-sha256; d=example.org; s=sel; cv=none; b=abc";
    try std.testing.expect(!sealCarriesH(without.as_value));
}
