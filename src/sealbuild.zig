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
const posix = std.posix;
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
        // Rendered rather than fabricated. Relaxed deletes the whitespace around
        // the colon so it cannot matter here, but knowing that is not this
        // function's job, and a future `c=` reaching this path would inherit the
        // bug (audit D-23).
        const full = try hdr.render(conn.allocator);
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
        if (!std.ascii.eqlIgnoreCase(hdr.name, "Authentication-Results")) continue;
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

test "results part drops the authserv-id" {
    try std.testing.expectEqualStrings(
        "spf=pass smtp.mailfrom=a.test",
        resultsPart("mail.example.org; spf=pass smtp.mailfrom=a.test").?,
    );
    try std.testing.expectEqualStrings(
        "dkim=pass header.d=a.test",
        resultsPart("  mail.example.org;  dkim=pass header.d=a.test;  ").?,
    );
    try std.testing.expect(resultsPart("mail.example.org") == null);
    try std.testing.expect(resultsPart("mail.example.org;   ") == null);
}

// --- X-11: the fold must always hand back an allocation the caller owns ------
//
// It used to return its input unchanged when short enough to need no folding, so the
// result was owned on one path and borrowed on the other with nothing in the type to
// say which. Neither call site freed it, which leaked a folded RSA signature on every
// sealed message and grew RSS without bound.
//
// `std.testing.allocator` is what makes this a real check rather than a restatement:
// it fails the test if the returned slice is never freed, and it fails just as loudly
// if the `free` below is handed memory it did not allocate. One contract, both
// directions.
test "foldBase64 returns owned memory on both the folding and the short path" {
    const a = std.testing.allocator;

    // The short path. This is the one that used to borrow.
    const short = "c2hvcnQ=";
    const folded_short = try foldBase64(a, short);
    defer a.free(folded_short);
    try std.testing.expectEqualStrings(short, folded_short);
    try std.testing.expect(folded_short.ptr != short.ptr);

    // Exactly at the 76-byte boundary: still no fold, still owned.
    const at_limit = "A" ** 76;
    const folded_limit = try foldBase64(a, at_limit);
    defer a.free(folded_limit);
    try std.testing.expectEqualStrings(at_limit, folded_limit);

    // The folding path, at the length an RSA-2048 signature actually reaches, which
    // is why the leak fired on every message rather than occasionally.
    const sig_b64 = "A" ** 344;
    const folded_sig = try foldBase64(a, sig_b64);
    defer a.free(folded_sig);
    try std.testing.expect(std.mem.indexOf(u8, folded_sig, "\r\n\t") != null);
    // Four folds over 344 bytes, each inserting CRLF+TAB, and no data lost.
    try std.testing.expectEqual(sig_b64.len + 4 * 3, folded_sig.len);
}

// --- The AAR trust rule (RFC 8617 §5.1.1) ------------------------------------
//
// This is a security boundary and it had no direct test. `buildAarContent` decides
// which Authentication-Results headers this ADMD is willing to vouch for
// cryptographically, and everything it accepts gets sealed into the chain under our
// domain's signature. Until the seal path was parameterised the rule was reachable
// only through a live daemon with a signing key, a resolver and a socket, so it was
// exercised end to end by the `a3` lab probe and not at all by anything cheaper.
// Being able to write these six tests is the reason the extraction was worth doing.
//
// An A-R header on an inbound message is attacker-controlled. Copying one we did not
// produce would have this host sign an assertion it never made -- the mail equivalent
// of countersigning a stranger's affidavit.

/// A connection carrying `hdrs` and nothing else.
///
/// `buildAarContent` reads `conn.headers` and allocates from `conn.allocator`; it
/// never touches the fd. The pipe exists because `Connection.deinit` closes whatever
/// it was given, and handing it a fabricated descriptor would close an unrelated file.
///
/// Names and values are duplicated because a `Connection` owns its headers -- it
/// frees every one in `deinit`, since in production they are copies the milter codec
/// made off the wire. Appending literals segfaults there, which is the invariant
/// stating itself. Duping also means these tests exercise the same ownership the
/// daemon has rather than a convenient fiction.
fn connWith(fd: posix.fd_t, hdrs: []const connection_mod.Header) !connection_mod.Connection {
    var conn = connection_mod.Connection.init(std.testing.allocator, fd, 0, .{});
    for (hdrs) |h| try conn.headers.append(std.testing.allocator, .{
        .name = try std.testing.allocator.dupe(u8, h.name),
        .value = try std.testing.allocator.dupe(u8, h.value),
    });
    return conn;
}

const our_id = "mail.relay.test";

test "an A-R claiming a different authserv-id is never vouched for" {
    const fds = try posix.pipe2(.{ .NONBLOCK = true });
    defer posix.close(fds[0]);

    // The attacker's own hostname in the authserv-id. Trivially forgeable, and the
    // only thing distinguishing it from ours is the string.
    var conn = try connWith(fds[1], &.{
        .{ .name = "Authentication-Results", .value = "mail.attacker.test; dkim=pass header.d=bank.example" },
    });
    defer conn.deinit();

    const out = buildAarContent(&conn, our_id, &.{"dkim"}).?;
    defer std.testing.allocator.free(out);

    // `none`, not the attacker's claim, and specifically not `dkim=pass` for a bank.
    try std.testing.expectEqualStrings("mail.relay.test; none", out);
}

test "an A-R claiming our authserv-id but a method we do not perform is rejected" {
    const fds = try posix.pipe2(.{ .NONBLOCK = true });
    defer posix.close(fds[0]);

    // Guessing our authserv-id is easy -- it is in every message we stamp. So the
    // id alone cannot be the test; what saves us is that we know which methods we
    // actually run. This host does SPF only.
    var conn = try connWith(fds[1], &.{
        .{ .name = "Authentication-Results", .value = "mail.relay.test; dkim=pass header.d=bank.example" },
    });
    defer conn.deinit();

    const out = buildAarContent(&conn, our_id, &.{"spf"}).?;
    defer std.testing.allocator.free(out);

    try std.testing.expectEqualStrings("mail.relay.test; none", out);
}

test "one non-local method rejects the whole header rather than being filtered out" {
    const fds = try posix.pipe2(.{ .NONBLOCK = true });
    defer posix.close(fds[0]);

    // A header mixing a method we do run with one we do not. Salvaging the spf=pass
    // and dropping the dkim=pass would be the tempting behaviour and the wrong one:
    // we would be sealing a partial copy of a header we did not write, and the
    // sender chose its contents. Reject entire.
    var conn = try connWith(fds[1], &.{
        .{ .name = "Authentication-Results", .value = "mail.relay.test; spf=pass smtp.mailfrom=ok.test; dkim=pass header.d=bank.example" },
    });
    defer conn.deinit();

    const out = buildAarContent(&conn, our_id, &.{"spf"}).?;
    defer std.testing.allocator.free(out);

    try std.testing.expectEqualStrings("mail.relay.test; none", out);
    try std.testing.expect(std.mem.indexOf(u8, out, "dkim") == null);
    try std.testing.expect(std.mem.indexOf(u8, out, "spf") == null);
}

test "a host that lists no local methods seals an honest none" {
    const fds = try posix.pipe2(.{ .NONBLOCK = true });
    defer posix.close(fds[0]);

    // Documented behaviour, and worth pinning because the failure mode is silent:
    // a misconfiguration that empties LocalAuthMethods must degrade to vouching for
    // nothing, never to vouching for whatever arrived.
    var conn = try connWith(fds[1], &.{
        .{ .name = "Authentication-Results", .value = "mail.relay.test; spf=pass smtp.mailfrom=ok.test" },
    });
    defer conn.deinit();

    const out = buildAarContent(&conn, our_id, &.{}).?;
    defer std.testing.allocator.free(out);

    try std.testing.expectEqualStrings("mail.relay.test; none", out);
}

test "a genuine result is carried through with the authserv-id stated once" {
    const fds = try posix.pipe2(.{ .NONBLOCK = true });
    defer posix.close(fds[0]);

    var conn = try connWith(fds[1], &.{
        .{ .name = "Authentication-Results", .value = "mail.relay.test; spf=pass smtp.mailfrom=ok.test" },
    });
    defer conn.deinit();

    const out = buildAarContent(&conn, our_id, &.{"spf"}).?;
    defer std.testing.allocator.free(out);

    // RFC 8617 §5.1.1: the AAR states the authserv-id once, then the results. The
    // per-header repeat is dropped by `resultsPart`.
    try std.testing.expectEqualStrings("mail.relay.test; spf=pass smtp.mailfrom=ok.test", out);
}

test "several genuine results are concatenated under one authserv-id" {
    const fds = try posix.pipe2(.{ .NONBLOCK = true });
    defer posix.close(fds[0]);

    // How the daemons actually stamp: one A-R per method, each written by a
    // different milter in the chain. Interleaved with a forgery claiming our id, to
    // check that rejecting one header does not disturb the others.
    var conn = try connWith(fds[1], &.{
        .{ .name = "Authentication-Results", .value = "mail.relay.test; spf=pass smtp.mailfrom=ok.test" },
        .{ .name = "Authentication-Results", .value = "mail.relay.test; dkim=pass header.d=evil.test" },
        .{ .name = "Authentication-Results", .value = "mail.relay.test; dmarc=fail (p=reject) header.from=ok.test" },
    });
    defer conn.deinit();

    const out = buildAarContent(&conn, our_id, &.{ "spf", "dmarc" }).?;
    defer std.testing.allocator.free(out);

    try std.testing.expectEqualStrings(
        "mail.relay.test; spf=pass smtp.mailfrom=ok.test; dmarc=fail (p=reject) header.from=ok.test",
        out,
    );
    try std.testing.expect(std.mem.indexOf(u8, out, "evil.test") == null);
}

test "an A-R claiming our authserv-id that asserts nothing parseable is rejected" {
    const fds = try posix.pipe2(.{ .NONBLOCK = true });
    defer posix.close(fds[0]);

    // This is what `assertsAnyMethod` uniquely protects, and it is not redundant
    // with the non-local-method check above. Both guards read the same
    // `ResultIterator`, which gives up at the first segment containing no `=`
    // (auth_results.zig:117) and therefore yields *nothing* for a value like this
    // one. A header asserting no results is outside no method set, so the
    // blacklist -- "reject if it claims a method we do not run" -- has nothing to
    // fire on. Only the whitelist -- "require a method we do run" -- stops it.
    //
    // Left unguarded, `resultsPart` would copy this text verbatim into the AAR and
    // this host would sign it. The immediate harm is bounded, since without an `=`
    // the attacker cannot spell `dkim=pass`, but it is arbitrary sender-controlled
    // prose inside a header we cryptographically vouch for and it violates the
    // RFC 8601 grammar the next hop parses. The general point is the one that
    // matters: a blacklist over what *our* parser recognises turns every parser
    // differential into a hole, and that early `return null` is one.
    //
    // Verified to have teeth: deleting the `assertsAnyMethod` guard fails this
    // test and nothing else in the suite.
    var conn = try connWith(fds[1], &.{
        .{ .name = "Authentication-Results", .value = "mail.relay.test; nothing here resembles a result" },
    });
    defer conn.deinit();

    const out = buildAarContent(&conn, our_id, &.{"spf"}).?;
    defer std.testing.allocator.free(out);

    try std.testing.expectEqualStrings("mail.relay.test; none", out);
}

// --- A-20: the ARC-Seal scope for a failed chain (RFC 8617 §5.1.2) -----------
//
// These exist because THE CONFORMANCE SUITE CANNOT SEE THIS DEFECT. Reverting the
// fix leaves the ValiMail signing suite at 17/17, measured: for a `cv=fail` chain a
// validator stops at the failed seal (§5.2 step 2) and never reaches ours, and `b=`
// is not byte-comparable because ValiMail's expected values come from dkimpy's
// alphabetical tag ordering. An external oracle covering 17 cases and an independent
// validator both miss it, so it is pinned directly.
//
// The rule inverts the usual one, which is why it is easy to get wrong: normally a
// seal covers the whole chain, but for a chain that does not validate §5.1.2 makes
// covering the prior sets a MUST NOT in effect -- there is no deterministic set of
// prior AS fields to sign, so the resulting signature is unverifiable rather than
// merely unusual.

/// Two prior sets, enough to tell "all of them" from "none of them".
fn priorSets() [2]arc.ArcSet {
    const empty = arc.ArcSet{
        .instance = 1,
        .aar_value = "i=1; example.org; none",
        .ams_value = "i=1; a=rsa-sha256; b=AAAA",
        .as_value = "i=1; cv=none; a=rsa-sha256; b=BBBB",
        .seal_cv = .none,
        .seal_algorithm = "rsa-sha256",
        .seal_domain = "example.org",
        .seal_selector = "s1",
        .seal_signature = "BBBB",
        .ams_algorithm = "rsa-sha256",
        .ams_domain = "example.org",
        .ams_selector = "s1",
        .ams_signature = "AAAA",
        .ams_body_hash = "CCCC",
        .ams_canonicalization = "relaxed/relaxed",
        .ams_signed_headers = "from",
    };
    var second = empty;
    second.instance = 2;
    second.seal_cv = .pass;
    return .{ empty, second };
}

test "a cv=fail seal covers only the new set, not the prior chain" {
    const sets = priorSets();
    // The MUST in §5.1.2: as if this newest ARC Set were the only set present.
    try std.testing.expectEqual(@as(usize, 0), sealScope(.fail, &sets).len);
}

test "a live chain's seal still covers every prior set" {
    const sets = priorSets();
    // The inverse must keep working: narrowing the scope for a passing chain would
    // break the chain of custody ARC exists to provide.
    try std.testing.expectEqual(@as(usize, 2), sealScope(.pass, &sets).len);
    try std.testing.expectEqual(@as(usize, 2), sealScope(.none, &sets).len);
    // `unknown` means no determination was made. It is not `fail`, so it must not
    // silently take the narrowed path.
    try std.testing.expectEqual(@as(usize, 2), sealScope(.unknown, &sets).len);
}

// --- A-19: a chain already marked cv=fail cannot be continued (§5.1.3) -------
//
// "Once broken, the chain cannot be continued, as the chain of custody is no longer
// valid, and responsibility for the message has been lost."
//
// The distinction these tests protect is the one that makes the rule subtle: a chain
// that fails validation HERE must be sealed cv=fail, because that is what records
// the break. Only a break an EARLIER hop already recorded stops us sealing. Getting
// that backwards would stop us marking newly detected failures, which is worse than
// the defect being fixed.

test "an existing cv=fail seal marks the chain as already broken" {
    var sets = priorSets();
    try std.testing.expect(!arc.chainAlreadyBroken(&sets));

    sets[1].seal_cv = .fail;
    try std.testing.expect(arc.chainAlreadyBroken(&sets));
}

test "a broken seal anywhere in the chain counts, not just the newest" {
    var sets = priorSets();
    // §5.1.3 is about the chain, not the last link: an earlier hop having recorded
    // the break is just as terminal, and a later cv=pass cannot revive it.
    sets[0].seal_cv = .fail;
    sets[1].seal_cv = .pass;
    try std.testing.expect(arc.chainAlreadyBroken(&sets));
}

test "an empty chain is not broken, it is absent" {
    // No sets means i=1 and cv=none, not a refusal to seal. Conflating "nothing to
    // continue" with "cannot continue" would stop this daemon sealing unsigned mail
    // at all, which is the common case.
    try std.testing.expect(!arc.chainAlreadyBroken(&.{}));
}
