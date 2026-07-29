//! Construction of the ARC set's header bytes: the AAR content, the canonicalized
//! signing inputs for the AMS and the ARC-Seal, and base64 folding.
//!
//! Split out of `main.zig` under megaplan Phase 10 R1. The seam is a real one
//! rather than a line count: everything here turns message content plus explicit
//! configuration into bytes, and decides nothing. The seal *decision* flow --
//! which key to use, what to do when DNS fails, whether to seal at all -- stays in
//! `main.zig` with the daemon state it reads.
//!
//! Seven of these nine functions were already free of global state. The two that
//! were not (`buildSigningHeaders`, `buildAarContent`) now take their configuration
//! as parameters, which is what makes the whole layer testable without starting a
//! daemon: the AAR trust rule in `buildAarContent` is a security boundary, and it
//! was previously reachable only through a live sealing path.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const securemilter = @import("securemilter");
const connection_mod = securemilter.connection;
const auth_results = securemilter.auth_results;
const log = securemilter.log;

const securemilter_crypto = @import("securemilter_crypto");
const header_select = securemilter_crypto.header_select;
const crypto = securemilter_crypto.crypto;

const arc = @import("arc.zig");

/// Field name of a connection header, for `header_select`.
fn connHeaderName(hdr: connection_mod.Header) []const u8 {
    return hdr.name;
}

/// Canonicalize the headers named in `signed_headers` and append them to `buf`.
///
/// The AMS we sign has to select header instances by the same rule a verifier
/// will use to check it (RFC 8617 via RFC 6376 §5.4.2), so this shares the
/// selector with validation rather than repeating the walk. Taking the last
/// match for every mention, as this did, would make any oversigned AMS we
/// produced unverifiable everywhere else (audit A-6).
pub fn buildSigningHeaders(
    conn: *connection_mod.Connection,
    buf: *std.ArrayListUnmanaged(u8),
    signed_headers: []const u8,
) !void {
    const canon_mod = securemilter_crypto.canon;
    var walk = header_select.walker(
        connection_mod.Header,
        connHeaderName,
        signed_headers,
        conn.headers.items,
    );
    while (walk.next()) |hdr| {
        // The message's own field name, not the `h=` spelling of it: relaxed
        // canonicalization lowercases both, but simple preserves what the
        // message carried, and that is what a verifier hashes.
        const full = try std.fmt.allocPrint(conn.allocator, "{s}: {s}", .{ hdr.name, hdr.value });
        defer conn.allocator.free(full);
        const canonicalized = try canon_mod.canonicalizeHeader(conn.allocator, .relaxed, full);
        defer conn.allocator.free(canonicalized);
        try buf.appendSlice(conn.allocator, canonicalized);
        try buf.appendSlice(conn.allocator, "\r\n");
    }
}

/// Which prior ARC sets the ARC-Seal signature covers.
///
/// RFC 8617 §5.1.2 is a MUST, and it inverts the usual rule: *"In the case of a
/// failed Authenticated Received Chain, the header fields included in the signature
/// scope of the AS header field b= value MUST only include the ARC Set header fields
/// created by the MTA that detected the malformed chain, as if this newest ARC Set
/// was the only set present."*
///
/// The section's own informational note gives the reason: for a malformed chain
/// *"there is no way to generate a deterministic set of AS header fields"*. Signing
/// the prior sets anyway produces a signature over bytes no verifier can reliably
/// reconstruct, so a `cv=fail` seal built that way is not merely different — it is
/// unverifiable (audit A-20).
///
/// **Its own function because the conformance suite cannot see this.** Reintroducing
/// the defect leaves the ValiMail signing suite at 17/17: for a `cv=fail` chain a
/// validator stops at the failed seal (§5.2 step 2) and never checks ours, and `b=`
/// is not byte-comparable across tag orderings. Verified by reverting it and
/// re-running. So the rule is pinned by the test below instead, and the extraction
/// exists to make that test possible without a signing key.
pub fn sealScope(cv: arc.ChainValidation, prior_sets: []const arc.ArcSet) []const arc.ArcSet {
    return if (cv == .fail) &.{} else prior_sets;
}

/// Build the seal signing input: prior ARC headers + current AAR + AMS + AS template.
pub fn buildSealInput(
    conn: *connection_mod.Connection,
    buf: *std.ArrayListUnmanaged(u8),
    prior_sets: []const arc.ArcSet,
    current_aar: []const u8,
    current_ams_value: []const u8,
    as_template: []const u8,
) !void {
    const canon_mod = securemilter_crypto.canon;

    // Prior sets: canonicalize all 3 headers for each
    for (prior_sets) |prior| {
        try appendCanonHdr(conn.allocator, buf, "ARC-Authentication-Results", prior.aar_value);
        try appendCanonHdr(conn.allocator, buf, "ARC-Message-Signature", prior.ams_value);
        try appendCanonHdr(conn.allocator, buf, "ARC-Seal", prior.as_value);
    }

    // Current instance: AAR + AMS
    try appendCanonHdr(conn.allocator, buf, "ARC-Authentication-Results", current_aar);
    try appendCanonHdr(conn.allocator, buf, "ARC-Message-Signature", current_ams_value);

    // AS header with empty b= (no trailing CRLF — last header in signing input)
    const as_full = try std.fmt.allocPrint(conn.allocator, "ARC-Seal: {s}", .{as_template});
    defer conn.allocator.free(as_full);
    const canon_as = try canon_mod.canonicalizeHeader(conn.allocator, .relaxed, as_full);
    defer conn.allocator.free(canon_as);
    try buf.appendSlice(conn.allocator, canon_as);
}

fn appendCanonHdr(allocator: Allocator, buf: *std.ArrayListUnmanaged(u8), name: []const u8, value: []const u8) !void {
    const canon_mod = securemilter_crypto.canon;
    const full = try std.fmt.allocPrint(allocator, "{s}: {s}", .{ name, value });
    defer allocator.free(full);
    const canonicalized = try canon_mod.canonicalizeHeader(allocator, .relaxed, full);
    defer allocator.free(canonicalized);
    try buf.appendSlice(allocator, canonicalized);
    try buf.appendSlice(allocator, "\r\n");
}

/// Assemble the ARC-Authentication-Results content from results this ADMD
/// actually produced (RFC 8617 §5.1.1).
///
/// An A-R header qualifies only if it claims our authserv-id *and* every
/// method it asserts is listed in `LocalAuthMethods`. Anything else is a
/// sender-supplied claim: copying it here would have this host cryptographically
/// vouch for authentication it never performed. A host that lists no local
/// methods therefore seals an honest `none`.
///
/// Caller owns the returned slice. Returns null only on allocation failure.
pub fn buildAarContent(
    conn: *connection_mod.Connection,
    authserv_id: []const u8,
    local_auth_methods: []const []const u8,
) ?[]const u8 {
    var buf: std.ArrayListUnmanaged(u8) = .{};
    errdefer buf.deinit(conn.allocator);

    var found = false;
    for (conn.headers.items) |hdr| {
        if (!eqlIgnoreCase(hdr.name, "Authentication-Results")) continue;
        if (!auth_results.matchesAuthservId(hdr.value, authserv_id)) continue;
        if (!auth_results.assertsAnyMethod(hdr.value, local_auth_methods)) continue;
        if (auth_results.assertsMethodOutside(hdr.value, local_auth_methods)) {
            log.warn("ignoring Authentication-Results claiming our authserv-id with non-local methods", .{});
            continue;
        }

        // Keep the raw result text (properties included); drop the repeated
        // authserv-id, which the AAR states once up front.
        const results = resultsPart(hdr.value) orelse continue;
        if (!found) {
            buf.appendSlice(conn.allocator, authserv_id) catch return null;
            found = true;
        }
        buf.appendSlice(conn.allocator, "; ") catch return null;
        buf.appendSlice(conn.allocator, results) catch return null;
    }

    if (!found) {
        buf.deinit(conn.allocator);
        return std.fmt.allocPrint(conn.allocator, "{s}; none", .{authserv_id}) catch null;
    }
    return buf.toOwnedSlice(conn.allocator) catch null;
}

/// The portion of an A-R value after the authserv-id, trimmed of surrounding
/// whitespace and trailing separators.
pub fn resultsPart(header_value: []const u8) ?[]const u8 {
    const trimmed = mem.trimLeft(u8, header_value, &std.ascii.whitespace);
    const semi = mem.indexOfScalar(u8, trimmed, ';') orelse return null;
    const rest = mem.trim(u8, trimmed[semi + 1 ..], &std.ascii.whitespace);
    const cleaned = mem.trim(u8, rest, ";");
    const result = mem.trim(u8, cleaned, &std.ascii.whitespace);
    return if (result.len == 0) null else result;
}

/// Fold a base64 string by inserting CRLF+TAB every 76 characters, so Postfix cannot
/// introduce a mid-token fold at an arbitrary position.
///
/// Returns a NEW allocation the caller owns in every case.
///
/// It used to return `b64` itself when short enough to need no folding, so the result
/// was sometimes borrowed and sometimes owned, with nothing in the type to say which.
/// Both call sites did the only thing available to them and freed neither, which leaked
/// a folded RSA signature on every sealed message (audit X-11). Duplicating the short
/// case costs one copy of a value that is, by definition, at most 76 bytes, and makes
/// `defer allocator.free(...)` correct unconditionally.
pub fn foldBase64(allocator: Allocator, b64: []const u8) ![]const u8 {
    const chunk_size = 76;
    if (b64.len <= chunk_size) return allocator.dupe(u8, b64);

    var result: std.ArrayListUnmanaged(u8) = .{};
    errdefer result.deinit(allocator);

    var offset: usize = 0;
    while (offset < b64.len) {
        const end = @min(offset + chunk_size, b64.len);
        try result.appendSlice(allocator, b64[offset..end]);
        if (end < b64.len) {
            try result.appendSlice(allocator, "\r\n\t");
        }
        offset = end;
    }
    return result.toOwnedSlice(allocator);
}
fn eqlIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ca, cb| {
        if (toLower(ca) != toLower(cb)) return false;
    }
    return true;
}

fn toLower(c: u8) u8 {
    if (c >= 'A' and c <= 'Z') return c + 32;
    return c;
}

/// Failure to build the set. The step that failed is reported out-of-band rather
/// than as a distinct error per step: the caller logs it and tempfails either way,
/// and twenty error names would be twenty things to keep in sync with one `switch`.
pub const BuildError = error{BuildFailed};

/// The three header values of one ARC set, owned as a unit.
///
/// Modelled on `securedkim`'s `SignResult`: the struct names the allocator that
/// made it and frees itself, so a caller cannot get the ownership wrong. That is
/// exactly the contract `foldBase64` lacked, and X-11 was the price -- two
/// allocations leaked per sealed message that no caller could have known to free,
/// because the signature did not say. Handing back three bare slices instead would
/// be the same trap three times over.
pub const BuiltSet = struct {
    aar: []u8,
    ams: []u8,
    seal: []u8,
    allocator: Allocator,

    pub fn deinit(self: *BuiltSet) void {
        self.allocator.free(self.aar);
        self.allocator.free(self.ams);
        self.allocator.free(self.seal);
    }
};

/// Everything `buildSet` needs beyond the message already on the connection.
///
/// All of it is resolved configuration and an already-acquired key: this layer
/// reads no daemon state and makes no policy choice. `cv` in particular arrives
/// *decided*, because deciding it is where A-12 lived — a nameserver blip must not
/// become a permanent `cv=fail` — and that judgement needs to see the DNS outcome,
/// so it stays with the flow.
pub const SetParams = struct {
    instance: u8,
    cv: arc.ChainValidation,
    domain: []const u8,
    selector: []const u8,
    signed_headers: []const u8,
    authserv_id: []const u8,
    local_auth_methods: []const []const u8,
    sign_key: *const crypto.SigningKey,
    /// Sets already on the message, for the ARC-Seal's signing input.
    prior_sets: []const arc.ArcSet,
    /// Signature timestamp for `t=` on both the AMS and the ARC-Seal.
    ///
    /// Injected rather than read from the clock here, for two reasons that happen to
    /// point the same way. Sealing must be reproducible to be testable at all -- the
    /// ValiMail signing suite supplies a fixed timestamp and compares the resulting
    /// `b=` byte for byte, which is impossible if this layer calls `time()` itself.
    /// And this module decides nothing by design (see the file comment), so reading
    /// ambient state would be the one exception.
    timestamp: u64,
};

/// Record which step failed and fail. Keeps each failure site one line, as it was
/// when these lines called `sealInternalError` directly.
fn fail(step: *?[]const u8, what: []const u8) BuildError {
    step.* = what;
    return error.BuildFailed;
}

/// Build all three header values of the new ARC set. Writes nothing.
///
/// That it writes nothing is the point rather than an incidental property. A milter
/// header packet cannot be recalled once it is on the wire, so an allocation failure
/// partway through emission used to deliver a *partial* set — and RFC 8617 §5.1.2
/// makes the next hop record that as a permanent `cv=fail`, destroying a chain that
/// may have been valid (audit X-8). Keeping every allocation in this module and every
/// write in the flow makes that ordering structural: the caller has no set to emit
/// until it has all of it.
///
/// On failure `failed_step` names the step, following the `reason: *?[]const u8`
/// convention `chain.zig` already uses for the same job. Partially built values are
/// released here, so a failed call returns nothing and leaks nothing.
pub fn buildSet(
    conn: *connection_mod.Connection,
    p: SetParams,
    failed_step: *?[]const u8,
) BuildError!BuiltSet {
    const allocator = conn.allocator;
    const canon_mod = securemilter_crypto.canon;

    // AAR: the results this ADMD produced, from its own headers only. The trust
    // rule that decides "its own" is in `buildAarContent`.
    const ar_content = buildAarContent(conn, p.authserv_id, p.local_auth_methods) orelse
        return fail(failed_step, "building the ARC-Authentication-Results content");
    defer allocator.free(ar_content);

    const aar = std.fmt.allocPrint(allocator, "i={d}; {s}", .{ p.instance, ar_content }) catch
        return fail(failed_step, "formatting the ARC-Authentication-Results header");
    errdefer allocator.free(aar);

    // AMS: signs the message content. The caller has already refused to seal a
    // truncated copy, so this is the whole body.
    const body_data = conn.getBody() orelse
        return fail(failed_step, "the accumulated body is unavailable");

    var body_canon = canon_mod.BodyCanonicalizer.init(allocator, .relaxed);
    defer body_canon.deinit();
    body_canon.update(body_data) catch return fail(failed_step, "canonicalizing the body");
    const canon_body = body_canon.finish() catch
        return fail(failed_step, "finishing body canonicalization");
    defer allocator.free(canon_body);

    const body_hash_raw = crypto.sha256(canon_body);
    const body_hash_b64 = crypto.base64Encode(allocator, &body_hash_raw) catch
        return fail(failed_step, "encoding the body hash");
    defer allocator.free(body_hash_b64);

    // Pre-folded, and written once. The final header value below is this template
    // with the signature appended, so the bytes a verifier canonicalizes are the
    // bytes we hashed by construction. Spelling the layout out twice and keeping
    // the two in sync by hand is a silent break waiting for the first person to add
    // a tag to one of them: the signature would cover a header the message does not
    // carry, and every verifier everywhere would report a failure.
    const ams_template = std.fmt.allocPrint(
        allocator,
        "i={d}; a=rsa-sha256;\r\n\tc=relaxed/relaxed; d={s}; s={s}; t={d};\r\n\th={s};\r\n\tbh={s};\r\n\tb=",
        .{ p.instance, p.domain, p.selector, p.timestamp, p.signed_headers, body_hash_b64 },
    ) catch return fail(failed_step, "formatting the AMS template");
    defer allocator.free(ams_template);

    var ams_input: std.ArrayListUnmanaged(u8) = .{};
    defer ams_input.deinit(allocator);
    buildSigningHeaders(conn, &ams_input, p.signed_headers) catch
        return fail(failed_step, "canonicalizing the signed headers");

    // The template goes in as the final line, b= empty and no trailing CRLF
    // (RFC 6376 §3.7).
    const ams_full_template = std.fmt.allocPrint(
        allocator,
        "ARC-Message-Signature: {s}",
        .{ams_template},
    ) catch return fail(failed_step, "formatting the AMS signing input");
    defer allocator.free(ams_full_template);
    const canon_ams_tmpl = canon_mod.canonicalizeHeader(allocator, .relaxed, ams_full_template) catch
        return fail(failed_step, "canonicalizing the AMS header");
    defer allocator.free(canon_ams_tmpl);
    ams_input.appendSlice(allocator, canon_ams_tmpl) catch
        return fail(failed_step, "assembling the AMS signing input");

    const ams_sig_raw = crypto.rsaSign(allocator, p.sign_key.rsa_pkey.?, ams_input.items) catch
        return fail(failed_step, "signing the AMS");
    defer allocator.free(ams_sig_raw);
    const ams_sig_b64 = crypto.base64Encode(allocator, ams_sig_raw) catch
        return fail(failed_step, "encoding the AMS signature");
    defer allocator.free(ams_sig_b64);
    const folded_ams_sig = foldBase64(allocator, ams_sig_b64) catch
        return fail(failed_step, "folding the AMS signature");
    defer allocator.free(folded_ams_sig);

    // The template ends at `b=`, so appending the signature yields exactly what was
    // signed. No second copy of the layout to drift.
    const ams_value = std.fmt.allocPrint(allocator, "{s}{s}", .{ ams_template, folded_ams_sig }) catch
        return fail(failed_step, "formatting the AMS header");
    errdefer allocator.free(ams_value);

    // ARC-Seal: signs this set's AAR and AMS, plus whatever prior ARC headers
    // `sealScope` admits -- everything for a live chain, nothing for a failed one.
    const as_template = std.fmt.allocPrint(
        allocator,
        "i={d}; cv={s}; a=rsa-sha256; d={s}; s={s}; t={d};\r\n\tb=",
        .{ p.instance, p.cv.toString(), p.domain, p.selector, p.timestamp },
    ) catch return fail(failed_step, "formatting the ARC-Seal template");
    defer allocator.free(as_template);

    const seal_scope = sealScope(p.cv, p.prior_sets);

    var seal_input: std.ArrayListUnmanaged(u8) = .{};
    defer seal_input.deinit(allocator);
    buildSealInput(conn, &seal_input, seal_scope, aar, ams_value, as_template) catch
        return fail(failed_step, "assembling the ARC-Seal signing input");

    const seal_sig_raw = crypto.rsaSign(allocator, p.sign_key.rsa_pkey.?, seal_input.items) catch
        return fail(failed_step, "signing the ARC-Seal");
    defer allocator.free(seal_sig_raw);
    const seal_sig_b64 = crypto.base64Encode(allocator, seal_sig_raw) catch
        return fail(failed_step, "encoding the ARC-Seal signature");
    defer allocator.free(seal_sig_b64);
    const folded_seal_sig = foldBase64(allocator, seal_sig_b64) catch
        return fail(failed_step, "folding the ARC-Seal signature");
    defer allocator.free(folded_seal_sig);

    // Same construction as the AMS: the signed template plus the signature.
    const as_value = std.fmt.allocPrint(allocator, "{s}{s}", .{ as_template, folded_seal_sig }) catch
        return fail(failed_step, "formatting the ARC-Seal header");

    return .{ .aar = aar, .ams = ams_value, .seal = as_value, .allocator = allocator };
}
