//! ARC set construction: AAR content, signing inputs, and base64 folding.
//!
//! This module converts explicit configuration and message content into headers.
//! The milter flow retains daemon-state and sealing-policy decisions.

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

/// Canonicalize the headers selected by `signed_headers` into `buf`.
///
/// Uses the same header-instance selection rule as validation (RFC 6376 §5.4.2).
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
        // Render the original field name and spacing; simple canonicalization
        // preserves both.
        const full = try hdr.render(conn.allocator);
        defer conn.allocator.free(full);
        const canonicalized = try canon_mod.canonicalizeHeader(conn.allocator, .relaxed, full);
        defer conn.allocator.free(canonicalized);
        try buf.appendSlice(conn.allocator, canonicalized);
        try buf.appendSlice(conn.allocator, "\r\n");
    }
}

/// Select prior ARC sets covered by the ARC-Seal signature.
///
/// RFC 8617 §5.1.2 requires a `cv=fail` seal to cover only the new set; malformed
/// prior sets cannot provide a deterministic signing input.
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

/// Fold base64 with CRLF+TAB every 76 characters.
///
/// Always returns a caller-owned allocation, including the unwrapped case.
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

/// Set construction failure; the failing step is reported out-of-band.
pub const BuildError = error{BuildFailed};

/// The three owned header values in an ARC set.
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

/// Resolved inputs for `buildSet` beyond the connection.
///
/// The caller supplies policy decisions and an acquired signing key.
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
    /// Timestamp for both AMS and ARC-Seal `t=` tags, supplied for reproducibility.
    timestamp: u64,
};

/// Record which step failed and fail. Keeps each failure site one line, as it was
/// when these lines called `sealInternalError` directly.
fn fail(step: *?[]const u8, what: []const u8) BuildError {
    step.* = what;
    return error.BuildFailed;
}

/// Build all header values for a new ARC set without emitting them.
///
/// `failed_step` identifies failures; partial values are released before return.
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

// --- X-11: `foldBase64` always returns owned memory ---------------------------
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

// --- AAR trust rule (RFC 8617 §5.1.1) ------------------------------------------
//
// Only Authentication-Results for this authserv-id and configured local methods
// may be sealed into an ARC-Authentication-Results header.

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
