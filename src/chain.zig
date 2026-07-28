const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const securemilter = @import("securemilter");
const dns_mod = securemilter.dns;

const securemilter_crypto = @import("securemilter_crypto");
const crypto = securemilter_crypto.crypto;
const canon = securemilter_crypto.canon;

const arc = @import("arc.zig");

/// Result of validating an ARC chain.
pub const ValidationResult = struct {
    status: arc.ChainValidation,
    highest_instance: u8,
    failure_reason: ?[]const u8,
};

/// Validate an ARC chain per RFC 8617 §5.2.
///
/// Steps:
/// 1. Verify ARC sets are complete and ordered (i=1..N, no gaps)
/// 2. For each ARC set, verify the ARC-Message-Signature (same as DKIM verify)
/// 3. For each ARC set, verify the ARC-Seal (signs over all prior ARC headers)
/// 4. Check cv= values: i=1 must be "none", i>1 must be "pass"
/// 5. If any step fails, result is "fail"
///
/// `min_key_bits` is the smallest RSA modulus accepted for an AMS or AS
/// signature. ARC inherits DKIM's cryptography, so RFC 8301's floor applies
/// here too: a set signed with a factorable key must not validate, or the whole
/// point of a chain of custody is lost at that hop.
pub fn validateChain(
    allocator: Allocator,
    resolver: *dns_mod.Resolver,
    sets: []const arc.ArcSet,
    all_headers: []const arc.Header,
    body_data: []const u8,
    min_key_bits: u32,
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
    const newest = sets[sets.len - 1];
    var ams_reason: ?[]const u8 = null;
    if (!verifyAms(allocator, resolver, &newest, all_headers, body_data, min_key_bits, &ams_reason)) {
        return .{
            .status = .fail,
            .highest_instance = newest.instance,
            .failure_reason = ams_reason orelse "AMS verification failed for newest set",
        };
    }

    // Step 4: Verify each ARC-Seal (validates chain integrity)
    for (sets) |set| {
        var seal_reason: ?[]const u8 = null;
        if (!verifySeal(allocator, resolver, &set, sets[0..set.instance], min_key_bits, &seal_reason)) {
            return .{
                .status = .fail,
                .highest_instance = set.instance,
                .failure_reason = seal_reason orelse "ARC-Seal verification failed",
            };
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
    min_key_bits: u32,
    reason: *?[]const u8,
) bool {
    // Fetch public key from DNS
    const qname = std.fmt.allocPrint(allocator, "{s}._domainkey.{s}", .{
        set.ams_selector,
        set.ams_domain,
    }) catch return false;
    defer allocator.free(qname);

    var dns_result = resolver.resolve(qname, .TXT) catch return false;
    defer dns_result.deinit();

    // Find key record and extract p= value
    var pubkey_b64: ?[]const u8 = null;
    var txt_iter = dns_result.txtRecords();
    while (txt_iter.next()) |txt| {
        if (arc.findTag(txt, "p")) |p| {
            if (p.len > 0) {
                pubkey_b64 = p;
                break;
            }
        }
    }
    const key_data_b64 = pubkey_b64 orelse return false;

    // Decode public key from base64
    const key_der = crypto.base64Decode(allocator, key_data_b64) catch return false;
    defer allocator.free(key_der);

    // Build signing input: canonicalize headers per h= tag + AMS header with empty b=
    const signing_input = buildAmsSigningInput(allocator, set, all_headers) catch return false;
    defer allocator.free(signing_input);

    // Canonicalize body and compute SHA-256 hash, then compare against claimed bh=
    const canon_pair = canon.parseCanonicalization(set.ams_canonicalization) catch
        canon.CanonicalizationPair{ .header = .relaxed, .body = .relaxed };
    var body_canon = canon.BodyCanonicalizer.init(allocator, canon_pair.body);
    defer body_canon.deinit();
    body_canon.update(body_data) catch return false;
    const canon_body = body_canon.finish() catch return false;
    defer allocator.free(canon_body);
    const computed_hash = crypto.sha256(canon_body);

    const claimed_bh = crypto.base64Decode(allocator, set.ams_body_hash) catch return false;
    defer allocator.free(claimed_bh);
    if (claimed_bh.len != computed_hash.len) return false;
    if (!mem.eql(u8, claimed_bh, &computed_hash)) return false;

    // Decode signature from base64
    const sig_bytes = crypto.base64Decode(allocator, set.ams_signature) catch return false;
    defer allocator.free(sig_bytes);

    // Verify with RSA-SHA256
    const pkey = crypto.loadRsaPublicKeyDer(key_der, min_key_bits, null) catch |err| {
        reason.* = switch (err) {
            error.RsaKeyTooSmall => "AMS signed with an RSA key below the minimum size",
            error.NotRsaPublicKey => "AMS key record p= is not an RSA key",
            else => null,
        };
        return false;
    };
    defer crypto.freePublicKey(pkey);

    return crypto.rsaVerify(pkey, signing_input, sig_bytes) catch false;
}

/// Build the signing input for AMS verification.
/// Canonicalizes headers listed in h= tag (relaxed), then appends the AMS
/// header itself with the b= value removed (same as DKIM signing input).
fn buildAmsSigningInput(
    allocator: Allocator,
    set: *const arc.ArcSet,
    all_headers: []const arc.Header,
) ![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .{};
    errdefer buf.deinit(allocator);

    // Canonicalize headers listed in h= tag
    var h_rest = set.ams_signed_headers;
    while (h_rest.len > 0) {
        const colon_pos = mem.indexOfScalar(u8, h_rest, ':');
        const hdr_name = if (colon_pos) |cp| h_rest[0..cp] else h_rest;
        h_rest = if (colon_pos) |cp| h_rest[cp + 1 ..] else "";

        const trimmed_name = mem.trim(u8, hdr_name, &std.ascii.whitespace);
        if (trimmed_name.len == 0) continue;

        // Find this header in the message (last occurrence, per DKIM spec)
        var found: ?[]const u8 = null;
        for (all_headers) |hdr| {
            if (arc.eqlLower(hdr.name, trimmed_name)) {
                const full = std.fmt.allocPrint(allocator, "{s}: {s}", .{ hdr.name, hdr.value }) catch continue;
                if (found) |f| allocator.free(f);
                found = full;
            }
        }
        if (found) |full| {
            defer allocator.free(full);
            const canonicalized = canon.canonicalizeHeader(allocator, .relaxed, full) catch continue;
            defer allocator.free(canonicalized);
            try buf.appendSlice(allocator, canonicalized);
            try buf.appendSlice(allocator, "\r\n");
        }
    }

    // Append AMS header with b= value emptied (for self-referencing signature)
    const ams_full = std.fmt.allocPrint(allocator, "ARC-Message-Signature: {s}", .{set.ams_value}) catch
        return error.OutOfMemory;
    defer allocator.free(ams_full);

    // Remove the b= value: replace "b=<sig>" with "b="
    const stripped = stripBValue(allocator, ams_full) catch ams_full;
    defer if (stripped.ptr != ams_full.ptr) allocator.free(stripped);

    const canon_ams = canon.canonicalizeHeader(allocator, .relaxed, stripped) catch
        return error.OutOfMemory;
    defer allocator.free(canon_ams);
    try buf.appendSlice(allocator, canon_ams);

    return buf.toOwnedSlice(allocator);
}

/// Strip the b= tag value from a DKIM/AMS header (set to empty for signing input).
/// Correctly distinguishes "b=" from "bh=" even when whitespace/folding separates
/// the preceding delimiter from the tag name.
fn stripBValue(allocator: Allocator, header: []const u8) ![]u8 {
    // Find "b=" that isn't "bh="
    var i: usize = 0;
    while (i < header.len) {
        if (header[i] == 'b' and i + 1 < header.len and header[i + 1] == '=') {
            // Look backward past any WSP/CRLF to find the real preceding non-WSP char.
            // If that char is 'h', this is "bh=" not "b=".
            var j: usize = i;
            while (j > 0) {
                j -= 1;
                if (header[j] != ' ' and header[j] != '\t' and header[j] != '\r' and header[j] != '\n') {
                    break;
                }
            }
            // If preceding non-WSP is a letter (not ';' or ':'), this b is part of a larger tag name
            if (j < i and j > 0 and header[j] >= 'a' and header[j] <= 'z') {
                i += 1;
                continue;
            }
            if (j < i and j > 0 and header[j] >= 'A' and header[j] <= 'Z') {
                i += 1;
                continue;
            }

            // Found standalone "b=" — strip everything after = until next ;
            const val_start = i + 2;
            const semi = mem.indexOfScalar(u8, header[val_start..], ';');
            const val_end = if (semi) |s| val_start + s else header.len;

            var result: std.ArrayListUnmanaged(u8) = .{};
            try result.appendSlice(allocator, header[0..val_start]);
            if (val_end < header.len) {
                try result.appendSlice(allocator, header[val_end..]);
            }
            return result.toOwnedSlice(allocator);
        }
        i += 1;
    }
    return allocator.dupe(u8, header);
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
    min_key_bits: u32,
    reason: *?[]const u8,
) bool {
    // Fetch public key
    const qname = std.fmt.allocPrint(allocator, "{s}._domainkey.{s}", .{
        set.seal_selector,
        set.seal_domain,
    }) catch return false;
    defer allocator.free(qname);

    var dns_result = resolver.resolve(qname, .TXT) catch return false;
    defer dns_result.deinit();

    // Find and decode public key
    var pubkey_b64: ?[]const u8 = null;
    var txt_iter = dns_result.txtRecords();
    while (txt_iter.next()) |txt| {
        if (arc.findTag(txt, "p")) |p| {
            if (p.len > 0) {
                pubkey_b64 = p;
                break;
            }
        }
    }
    const key_b64 = pubkey_b64 orelse return false;

    const key_der = crypto.base64Decode(allocator, key_b64) catch return false;
    defer allocator.free(key_der);

    // Build seal signing input: all prior ARC headers (relaxed canonicalized)
    // in order (AAR, AMS, AS for each prior instance), plus current AAR + AMS
    const signing_input = buildSealSigningInput(allocator, set, prior_sets) catch return false;
    defer allocator.free(signing_input);

    // Decode signature
    const sig_bytes = crypto.base64Decode(allocator, set.seal_signature) catch return false;
    defer allocator.free(sig_bytes);

    // Verify with RSA-SHA256
    const pkey = crypto.loadRsaPublicKeyDer(key_der, min_key_bits, null) catch |err| {
        reason.* = switch (err) {
            error.RsaKeyTooSmall => "ARC-Seal signed with an RSA key below the minimum size",
            error.NotRsaPublicKey => "ARC-Seal key record p= is not an RSA key",
            else => null,
        };
        return false;
    };
    defer crypto.freePublicKey(pkey);

    return crypto.rsaVerify(pkey, signing_input, sig_bytes) catch false;
}

/// Build the seal signing input per RFC 8617 §5.1.1.
/// Order: for each instance 1..i, canonicalize AAR, AMS, AS headers.
/// For the current instance (last in prior_sets), include AAR + AMS but NOT AS
/// (the seal signs over everything except itself).
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
    const stripped = stripBValue(allocator, as_full) catch as_full;
    defer if (stripped.ptr != as_full.ptr) allocator.free(stripped);

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

// =============================================================================
// Tests
// =============================================================================

test "validateChain empty" {
    const sets: []const arc.ArcSet = &.{};
    const headers: []const arc.Header = &.{};
    const result = validateChain(std.testing.allocator, undefined, sets, headers, "", crypto.RFC8301_MIN_RSA_BITS);
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
    const result = validateChain(std.testing.allocator, undefined, &sets, headers, "", crypto.RFC8301_MIN_RSA_BITS);
    try std.testing.expectEqual(arc.ChainValidation.fail, result.status);
    try std.testing.expectEqualStrings("ARC-Seal cv must be pass for i>1", result.failure_reason.?);
}
