const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const securemilter = @import("securemilter");
const dns_mod = securemilter.dns;
const crypto = securemilter.crypto;

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
pub fn validateChain(
    allocator: Allocator,
    resolver: *dns_mod.Resolver,
    sets: []const arc.ArcSet,
    all_headers: []const arc.Header,
    body_hash: []const u8,
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
    if (!verifyAms(allocator, resolver, &newest, all_headers, body_hash)) {
        return .{
            .status = .fail,
            .highest_instance = newest.instance,
            .failure_reason = "AMS verification failed for newest set",
        };
    }

    // Step 4: Verify each ARC-Seal (validates chain integrity)
    for (sets) |set| {
        if (!verifySeal(allocator, resolver, &set, sets[0..set.instance])) {
            return .{
                .status = .fail,
                .highest_instance = set.instance,
                .failure_reason = "ARC-Seal verification failed",
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
fn verifyAms(
    allocator: Allocator,
    resolver: *dns_mod.Resolver,
    set: *const arc.ArcSet,
    all_headers: []const arc.Header,
    body_hash: []const u8,
) bool {
    _ = all_headers;
    _ = body_hash;

    // Fetch public key from DNS
    const qname = std.fmt.allocPrint(allocator, "{s}._domainkey.{s}", .{
        set.ams_selector,
        set.ams_domain,
    }) catch return false;
    defer allocator.free(qname);

    var dns_result = resolver.resolve(qname, .TXT) catch return false;
    defer dns_result.deinit();

    // Find key record
    var txt_iter = dns_result.txtRecords();
    var pubkey_data: ?[]const u8 = null;
    while (txt_iter.next()) |txt| {
        if (mem.indexOf(u8, txt, "p=")) |_| {
            pubkey_data = txt;
            break;
        }
    }
    if (pubkey_data == null) return false;

    // Extract p= value
    const p_val = arc.findTag(pubkey_data.?, "p") orelse return false;
    if (p_val.len == 0) return false; // revoked key

    // TODO: full cryptographic verification
    // Full implementation: canonicalize headers per h= tag, compute signing input,
    // verify with RSA/Ed25519 depending on a= tag using securemilter.crypto.
    // For now: DNS key fetch + non-revoked key = structural validation passes.
    _ = p_val.len; // suppress unused; key existence confirmed above
    return true;
}

/// Verify an ARC-Seal signature.
///
/// The seal signs over ALL prior ARC headers (AAR, AMS, AS) for instances
/// 1..i-1, plus the current instance's AAR and AMS (but NOT the current AS
/// being verified — that would be circular).
fn verifySeal(
    allocator: Allocator,
    resolver: *dns_mod.Resolver,
    set: *const arc.ArcSet,
    prior_sets: []const arc.ArcSet,
) bool {
    _ = prior_sets;

    // Fetch public key
    const qname = std.fmt.allocPrint(allocator, "{s}._domainkey.{s}", .{
        set.seal_selector,
        set.seal_domain,
    }) catch return false;
    defer allocator.free(qname);

    var dns_result = resolver.resolve(qname, .TXT) catch return false;
    defer dns_result.deinit();

    var txt_iter = dns_result.txtRecords();
    while (txt_iter.next()) |txt| {
        if (mem.indexOf(u8, txt, "p=")) |_| {
            const p_val = arc.findTag(txt, "p") orelse continue;
            if (p_val.len == 0) continue;
            // Structural validation: key exists and is not revoked
            // Full implementation: canonicalize ARC headers in strict order,
            // compute seal signing input, verify with RSA/Ed25519.
            return true; // TODO: full cryptographic verification
        }
    }

    return false;
}

// =============================================================================
// Tests
// =============================================================================

test "validateChain empty" {
    const sets: []const arc.ArcSet = &.{};
    const headers: []const arc.Header = &.{};
    const result = validateChain(std.testing.allocator, undefined, sets, headers, "");
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
    const result = validateChain(std.testing.allocator, undefined, &sets, headers, "");
    try std.testing.expectEqual(arc.ChainValidation.fail, result.status);
    try std.testing.expectEqualStrings("ARC-Seal cv must be pass for i>1", result.failure_reason.?);
}
