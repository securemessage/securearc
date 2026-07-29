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

/// Fold a base64 string by inserting CRLF+TAB every 76 characters.
/// Prevents Postfix from introducing mid-token folds at arbitrary positions.
pub fn foldBase64(allocator: Allocator, b64: []const u8) ![]const u8 {
    const chunk_size = 76;
    if (b64.len <= chunk_size) return b64;

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
