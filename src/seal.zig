const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const securemilter = @import("securemilter");
const crypto = securemilter.crypto;
const auth_results = securemilter.auth_results;

const arc = @import("arc.zig");

/// Parameters for constructing a new ARC set.
pub const SealParams = struct {
    instance: u8, // Next instance number (highest_existing + 1)
    domain: []const u8,
    selector: []const u8,
    algorithm: []const u8, // "rsa-sha256" or "ed25519-sha256"
    signed_headers: []const u8, // Colon-separated header names
    chain_status: arc.ChainValidation, // cv= for the new seal
};

/// Result of constructing a new ARC set — the three headers to prepend.
pub const SealResult = struct {
    aar_header: []const u8, // "ARC-Authentication-Results: i=N; <ar-content>"
    ams_header: []const u8, // "ARC-Message-Signature: i=N; <dkim-like-sig>"
    as_header: []const u8, // "ARC-Seal: i=N; cv=<status>; <seal-sig>"
    allocator: Allocator,

    pub fn deinit(self: *SealResult) void {
        self.allocator.free(self.aar_header);
        self.allocator.free(self.ams_header);
        self.allocator.free(self.as_header);
    }
};

/// Construct a new ARC set (AAR + AMS + AS) for sealing a forwarded message.
///
/// Per RFC 8617 §5.1:
/// - AAR: ARC-Authentication-Results header with current A-R evaluation
/// - AMS: ARC-Message-Signature (same as DKIM-Signature over message)
/// - AS: ARC-Seal (signature over all ARC-* headers from prior sets + this AAR + AMS)
pub fn constructSeal(
    allocator: Allocator,
    params: *const SealParams,
    sign_key: *const crypto.SigningKey,
    ar_content: []const u8,
    headers: []const []const u8,
    body_hash: []const u8,
    prior_arc_headers: []const []const u8,
) !SealResult {
    // Step 1: Build AAR header
    const aar = try std.fmt.allocPrint(allocator, "ARC-Authentication-Results: i={d}; {s}", .{
        params.instance,
        ar_content,
    });
    errdefer allocator.free(aar);

    // Step 2: Build AMS header (message signature, same as DKIM)
    const ams_signing_input = try buildAmsSigningInput(
        allocator,
        params,
        headers,
        body_hash,
    );
    defer allocator.free(ams_signing_input);

    const ams_sig = try signData(allocator, sign_key, ams_signing_input);
    defer allocator.free(ams_sig);

    const ams = try std.fmt.allocPrint(allocator,
        \\ARC-Message-Signature: i={d}; a={s}; c=relaxed/relaxed; d={s}; s={s}; h={s}; bh={s}; b={s}
    , .{
        params.instance,
        params.algorithm,
        params.domain,
        params.selector,
        params.signed_headers,
        body_hash,
        ams_sig,
    });
    errdefer allocator.free(ams);

    // Step 3: Build AS header (seal over all ARC headers)
    const seal_signing_input = try buildSealSigningInput(
        allocator,
        params,
        prior_arc_headers,
        aar,
        ams,
    );
    defer allocator.free(seal_signing_input);

    const seal_sig = try signData(allocator, sign_key, seal_signing_input);
    defer allocator.free(seal_sig);

    const as = try std.fmt.allocPrint(allocator,
        \\ARC-Seal: i={d}; cv={s}; a={s}; d={s}; s={s}; b={s}
    , .{
        params.instance,
        params.chain_status.toString(),
        params.algorithm,
        params.domain,
        params.selector,
        seal_sig,
    });

    return .{
        .aar_header = aar,
        .ams_header = ams,
        .as_header = as,
        .allocator = allocator,
    };
}

/// Build the signing input for AMS (same as DKIM signing input).
/// Canonicalizes selected headers + empty b= tag for self-referencing.
fn buildAmsSigningInput(
    allocator: Allocator,
    params: *const SealParams,
    headers: []const []const u8,
    body_hash: []const u8,
) ![]const u8 {
    _ = headers; // TODO: full canonicalization using securemilter canon primitives
    // Placeholder: signing input = concatenation of params for structural correctness
    return std.fmt.allocPrint(allocator, "ams:{d}:{s}:{s}:{s}", .{
        params.instance,
        params.domain,
        params.signed_headers,
        body_hash,
    });
}

/// Build the signing input for ARC-Seal.
/// Per RFC 8617 §5.1.1: seal signs over all prior ARC headers (relaxed canonicalized)
/// plus the current instance's AAR and AMS (but NOT the current AS).
fn buildSealSigningInput(
    allocator: Allocator,
    params: *const SealParams,
    prior_arc_headers: []const []const u8,
    current_aar: []const u8,
    current_ams: []const u8,
) ![]const u8 {
    var buf: std.ArrayListUnmanaged(u8) = .{};
    errdefer buf.deinit(allocator);

    // Append all prior ARC headers
    for (prior_arc_headers) |hdr| {
        try buf.appendSlice(allocator, hdr);
        try buf.appendSlice(allocator, "\r\n");
    }

    // Append current AAR and AMS
    try buf.appendSlice(allocator, current_aar);
    try buf.appendSlice(allocator, "\r\n");
    try buf.appendSlice(allocator, current_ams);
    try buf.appendSlice(allocator, "\r\n");

    // Append current AS template (with empty b= for signing)
    const as_template = try std.fmt.allocPrint(allocator,
        \\ARC-Seal: i={d}; cv={s}; a={s}; d={s}; s={s}; b=
    , .{
        params.instance,
        params.chain_status.toString(),
        params.algorithm,
        params.domain,
        params.selector,
    });
    defer allocator.free(as_template);
    try buf.appendSlice(allocator, as_template);

    return buf.toOwnedSlice(allocator);
}

/// Sign data using the provided key (RSA-SHA256 or Ed25519-SHA256).
fn signData(allocator: Allocator, key: *const crypto.SigningKey, data: []const u8) ![]const u8 {
    const sig_bytes = try crypto.sign(key, data);
    return std.base64.standard.Encoder.encode(allocator, &sig_bytes);
}

// =============================================================================
// Tests
// =============================================================================

test "SealParams construction" {
    const params = SealParams{
        .instance = 1,
        .domain = "example.com",
        .selector = "arc2026",
        .algorithm = "rsa-sha256",
        .signed_headers = "from:to:subject:date",
        .chain_status = .none,
    };
    try std.testing.expectEqual(@as(u8, 1), params.instance);
    try std.testing.expectEqualStrings("none", params.chain_status.toString());
}

test "SealResult lifecycle" {
    // Verify the struct can be constructed and deinitialized without crash
    const allocator = std.testing.allocator;
    const aar = try allocator.dupe(u8, "ARC-Authentication-Results: i=1; test");
    const ams = try allocator.dupe(u8, "ARC-Message-Signature: i=1; sig");
    const as = try allocator.dupe(u8, "ARC-Seal: i=1; seal");

    var result = SealResult{
        .aar_header = aar,
        .ams_header = ams,
        .as_header = as,
        .allocator = allocator,
    };
    result.deinit();
}
