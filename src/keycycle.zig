//! Verify a signature against published key records at one selector.
//!
//! Key-record order is unspecified during rotation, so verification tries bounded
//! candidates until one succeeds.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const securemilter = @import("securemilter");
const dns_mod = securemilter.dns;
const deadline_mod = securemilter.deadline;

const securemilter_crypto = @import("securemilter_crypto");
const crypto = securemilter_crypto.crypto;

const arc = @import("arc.zig");

/// The verdict of checking one signature.
pub const CheckOutcome = enum { pass, fail, dns_temp_error, internal_error };

/// Classify failures from published signature data.
///
/// Only allocation failure is internal; malformed published data fails validation.
pub fn classifyDataError(err: anyerror) CheckOutcome {
    return if (err == error.OutOfMemory) .internal_error else .fail;
}

/// Default and maximum key records tried per selector.
pub const DEFAULT_MAX_KEY_RECORDS: u8 = 3;
pub const MAX_KEY_RECORDS_CEILING: u8 = 8;

/// Per-chain validation limits.
pub const Policy = struct {
    /// Smallest RSA modulus accepted for an AMS or ARC-Seal signature.
    min_key_bits: u32,
    /// Capped at `MAX_KEY_RECORDS_CEILING` during validation.
    max_key_records: u8 = DEFAULT_MAX_KEY_RECORDS,
    /// Chain-validation deadline in milliseconds; zero disables it.
    max_evaluation_ms: i64 = deadline_mod.DEFAULT_MS,
};

/// Header-specific diagnostics for policy-rejected keys.
pub const Labels = struct {
    too_small: []const u8,
    not_rsa: []const u8,
};

pub const AMS_LABELS = Labels{
    .too_small = "AMS signed with an RSA key below the minimum size",
    .not_rsa = "AMS key record p= is not an RSA key",
};

pub const SEAL_LABELS = Labels{
    .too_small = "ARC-Seal signed with an RSA key below the minimum size",
    .not_rsa = "ARC-Seal key record p= is not an RSA key",
};

/// Whether the selector publishes a non-empty `p=` key record.
pub fn hasUsableKey(dns_result: *const dns_mod.resolver.Result) bool {
    var it = dns_result.txtRecords();
    while (it.next()) |txt| {
        if (arc.findTag(txt, "p")) |p| {
            if (p.len > 0) return true;
        }
    }
    return false;
}

/// Try published key records against an already-built signing input.
///
/// Return the first successful verification; otherwise retain the first failure
/// and its diagnostic reason.
pub fn tryKeys(
    allocator: Allocator,
    dns_result: *dns_mod.resolver.Result,
    signing_input: []const u8,
    sig_bytes: []const u8,
    policy: Policy,
    labels: Labels,
    reason: *?[]const u8,
) CheckOutcome {
    const cap = @min(policy.max_key_records, MAX_KEY_RECORDS_CEILING);
    var tried: u8 = 0;
    var held: ?CheckOutcome = null;
    var held_reason: ?[]const u8 = null;

    var txt_iter = dns_result.txtRecords();
    while (txt_iter.next()) |txt| {
        if (tried >= cap) break;
        const key_b64 = arc.findTag(txt, "p") orelse continue;
        if (key_b64.len == 0) continue;
        tried += 1;

        const key_der = crypto.base64Decode(allocator, key_b64) catch |err| {
            if (held == null) held = classifyDataError(err);
            continue;
        };
        defer allocator.free(key_der);

        const pkey = crypto.loadRsaPublicKeyDer(key_der, policy.min_key_bits, null) catch |err| {
            if (held == null) {
                held_reason = switch (err) {
                    error.RsaKeyTooSmall => labels.too_small,
                    error.NotRsaPublicKey => labels.not_rsa,
                    else => null,
                };
                held = classifyDataError(err);
            }
            continue;
        };
        defer crypto.freePublicKey(pkey);

        const ok = crypto.rsaVerify(pkey, signing_input, sig_bytes) catch |err| {
            if (held == null) held = classifyDataError(err);
            continue;
        };
        if (ok) return .pass;

        // A key that simply did not match this signature.
        if (held == null) held = .fail;
    }

    if (held_reason) |r| reason.* = r;
    // A caller normally ensures at least one usable key record exists.
    return held orelse .fail;
}

// =============================================================================
// Tests
// =============================================================================

/// A TXT answer borrowing `data`. Never handed to `Result.deinit`, which would try
/// to free string literals; these tests let the fixture die with the stack frame.
fn txtAnswer(data: []const u8) dns_mod.packet.Answer {
    return .{
        .name = "sel._domainkey.example.org",
        .record_type = @intFromEnum(dns_mod.RecordType.TXT),
        .ttl = 300,
        .data = data,
    };
}

/// Decodes as base64 but is not an SPKI, so it fails to load as a public key.
const JUNK_TXT = "v=DKIM1; k=rsa; p=bm90YWtleWF0YWxs";

test "tryKeys cycles past a decoy record to the one that verifies (A-24)" {
    const allocator = std.testing.allocator;

    var key = crypto.loadRsaKeyFile(
        "test/keys/arc.key",
        crypto.RFC8301_MIN_RSA_BITS,
        .permit_any,
    ) catch return error.SkipZigTest;
    defer key.deinit();

    const signing_input = "arc-message-signature:i=1; a=rsa-sha256; d=example.org";
    const sig = try crypto.rsaSign(allocator, key.rsa_pkey.?, signing_input);
    defer allocator.free(sig);

    const good_p = try crypto.publicKeySpkiBase64(allocator, &key);
    defer allocator.free(good_p);
    const good_txt = try std.fmt.allocPrint(allocator, "v=DKIM1; k=rsa; p={s}", .{good_p});
    defer allocator.free(good_txt);

    // The decoy is listed first (before A-24):
    // committed to whichever record DNS returned first and never looked further.
    var answers = [_]dns_mod.packet.Answer{ txtAnswer(JUNK_TXT), txtAnswer(good_txt) };
    var result = dns_mod.resolver.Result{ .answers = &answers, .allocator = allocator };

    var reason: ?[]const u8 = null;
    try std.testing.expectEqual(CheckOutcome.pass, tryKeys(
        allocator,
        &result,
        signing_input,
        sig,
        .{ .min_key_bits = crypto.RFC8301_MIN_RSA_BITS },
        AMS_LABELS,
        &reason,
    ));

    // Teeth, and the reason this test is worth having: capped at a single record
    // the decoy is all that is seen and the verdict flips. So the pass above was
    // genuinely carried by the second record rather than by the first happening to
    // work -- and the cap is proven honoured rather than merely declared.
    var capped_reason: ?[]const u8 = null;
    try std.testing.expectEqual(CheckOutcome.fail, tryKeys(
        allocator,
        &result,
        signing_input,
        sig,
        .{ .min_key_bits = crypto.RFC8301_MIN_RSA_BITS, .max_key_records = 1 },
        AMS_LABELS,
        &capped_reason,
    ));
}

test "tryKeys holds the FIRST failure, so a later record cannot rename it (A-24)" {
    const allocator = std.testing.allocator;

    var key = crypto.loadRsaKeyFile(
        "test/keys/arc.key",
        crypto.RFC8301_MIN_RSA_BITS,
        .permit_any,
    ) catch return error.SkipZigTest;
    defer key.deinit();

    const good_p = try crypto.publicKeySpkiBase64(allocator, &key);
    defer allocator.free(good_p);
    const real_txt = try std.fmt.allocPrint(allocator, "v=DKIM1; k=rsa; p={s}", .{good_p});
    defer allocator.free(real_txt);

    // A floor above the fixture's real modulus, which turns the *valid* record into
    // an `RsaKeyTooSmall` -- a failure that does carry a named reason.
    const impossible_floor: u32 = 8192;

    // Junk first. The named reason belongs to the second record and must not be
    // reported, because the operator will go and look at the first one. This is
    // what distinguishes `if (held == null)` from `if (held_reason == null)`.
    {
        var answers = [_]dns_mod.packet.Answer{ txtAnswer(JUNK_TXT), txtAnswer(real_txt) };
        var result = dns_mod.resolver.Result{ .answers = &answers, .allocator = allocator };
        var reason: ?[]const u8 = null;
        const outcome = tryKeys(allocator, &result, "input", "sig", .{
            .min_key_bits = impossible_floor,
        }, AMS_LABELS, &reason);
        try std.testing.expectEqual(CheckOutcome.fail, outcome);
        try std.testing.expect(reason == null);
    }

    // The same two records the other way round, and now the named reason is the
    // first one, so it is exactly what should be reported.
    {
        var answers = [_]dns_mod.packet.Answer{ txtAnswer(real_txt), txtAnswer(JUNK_TXT) };
        var result = dns_mod.resolver.Result{ .answers = &answers, .allocator = allocator };
        var reason: ?[]const u8 = null;
        const outcome = tryKeys(allocator, &result, "input", "sig", .{
            .min_key_bits = impossible_floor,
        }, AMS_LABELS, &reason);
        try std.testing.expectEqual(CheckOutcome.fail, outcome);
        try std.testing.expect(reason != null);
        try std.testing.expectEqualStrings(AMS_LABELS.too_small, reason.?);
    }
}

test "the seal labels are used when the seal path refuses a key (A-24)" {
    const allocator = std.testing.allocator;

    var key = crypto.loadRsaKeyFile(
        "test/keys/arc.key",
        crypto.RFC8301_MIN_RSA_BITS,
        .permit_any,
    ) catch return error.SkipZigTest;
    defer key.deinit();

    const good_p = try crypto.publicKeySpkiBase64(allocator, &key);
    defer allocator.free(good_p);
    const real_txt = try std.fmt.allocPrint(allocator, "v=DKIM1; k=rsa; p={s}", .{good_p});
    defer allocator.free(real_txt);

    var answers = [_]dns_mod.packet.Answer{txtAnswer(real_txt)};
    var result = dns_mod.resolver.Result{ .answers = &answers, .allocator = allocator };

    var reason: ?[]const u8 = null;
    _ = tryKeys(allocator, &result, "input", "sig", .{
        .min_key_bits = 8192,
    }, SEAL_LABELS, &reason);

    // Naming the wrong header would send an operator to the wrong hop, which is why
    // the wording is a parameter rather than a constant inside the loop.
    try std.testing.expect(reason != null);
    try std.testing.expectEqualStrings(SEAL_LABELS.too_small, reason.?);
}

test "hasUsableKey ignores records with no p= and empty p=" {
    const allocator = std.testing.allocator;

    var none = [_]dns_mod.packet.Answer{
        txtAnswer("v=DKIM1; k=rsa"),
        txtAnswer("v=DKIM1; k=rsa; p="),
    };
    var no_key = dns_mod.resolver.Result{ .answers = &none, .allocator = allocator };
    try std.testing.expect(!hasUsableKey(&no_key));

    // A revoked key (p= empty) followed by a live one is still usable.
    var some = [_]dns_mod.packet.Answer{
        txtAnswer("v=DKIM1; k=rsa; p="),
        txtAnswer(JUNK_TXT),
    };
    var has_key = dns_mod.resolver.Result{ .answers = &some, .allocator = allocator };
    try std.testing.expect(hasUsableKey(&has_key));
}
