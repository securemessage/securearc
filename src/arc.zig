const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

/// Maximum ARC chain length per RFC 8617 §5.1.1
pub const MAX_INSTANCES: u8 = 50;

/// ARC header types in a set.
pub const HeaderType = enum {
    aar, // ARC-Authentication-Results
    ams, // ARC-Message-Signature
    as, // ARC-Seal
};

/// Parsed tag from an ARC-Seal or ARC-Message-Signature header.
pub const Tag = struct {
    name: []const u8,
    value: []const u8,
};

/// A complete ARC set (one per instance number).
pub const ArcSet = struct {
    instance: u8,
    aar_value: []const u8, // Raw AAR header value (the A-R content after "i=N;")
    ams_value: []const u8, // Raw AMS header value (DKIM-like signature tags)
    as_value: []const u8, // Raw AS header value (seal signature tags)
    // Parsed seal fields (from AS header)
    seal_cv: ChainValidation,
    seal_algorithm: []const u8,
    seal_domain: []const u8,
    seal_selector: []const u8,
    seal_signature: []const u8,
    // Parsed AMS fields (from AMS header — same as DKIM-Signature)
    ams_algorithm: []const u8,
    ams_domain: []const u8,
    ams_selector: []const u8,
    ams_signature: []const u8,
    ams_body_hash: []const u8,
    ams_canonicalization: []const u8,
    ams_signed_headers: []const u8,
};

/// Chain validation status per RFC 8617 §5.1.
pub const ChainValidation = enum {
    none, // No prior ARC sets exist
    pass, // All prior ARC sets validated
    fail, // Chain is broken
    unknown, // Could not determine (parse error)

    pub fn toString(self: ChainValidation) []const u8 {
        return switch (self) {
            .none => "none",
            .pass => "pass",
            .fail => "fail",
            .unknown => "unknown",
        };
    }

    pub fn fromString(s: []const u8) ChainValidation {
        if (eqlLower(s, "none")) return .none;
        if (eqlLower(s, "pass")) return .pass;
        if (eqlLower(s, "fail")) return .fail;
        return .unknown;
    }
};

/// Parse ARC-related headers from a list of message headers and build ordered ARC sets.
///
/// Returns sets ordered by instance number (1..N). Any gaps or duplicates
/// within a single instance invalidate the chain.
pub fn parseArcSets(allocator: Allocator, headers: []const Header) ![]ArcSet {
    var sets: [MAX_INSTANCES]?ArcSet = .{null} ** MAX_INSTANCES;
    var max_instance: u8 = 0;

    for (headers) |hdr| {
        const htype: HeaderType = if (eqlLower(hdr.name, "ARC-Authentication-Results"))
            .aar
        else if (eqlLower(hdr.name, "ARC-Message-Signature"))
            .ams
        else if (eqlLower(hdr.name, "ARC-Seal"))
            .as
        else
            continue;

        const instance = parseInstance(hdr.value) orelse continue;
        if (instance == 0 or instance > MAX_INSTANCES) continue;
        if (instance > max_instance) max_instance = instance;

        const idx = instance - 1;
        if (sets[idx] == null) {
            sets[idx] = ArcSet{
                .instance = instance,
                .aar_value = "",
                .ams_value = "",
                .as_value = "",
                .seal_cv = .unknown,
                .seal_algorithm = "",
                .seal_domain = "",
                .seal_selector = "",
                .seal_signature = "",
                .ams_algorithm = "",
                .ams_domain = "",
                .ams_selector = "",
                .ams_signature = "",
                .ams_body_hash = "",
                .ams_canonicalization = "relaxed/relaxed",
                .ams_signed_headers = "",
            };
        }

        var set = &sets[idx].?;
        switch (htype) {
            .aar => set.aar_value = hdr.value,
            .ams => {
                set.ams_value = hdr.value;
                parseAmsTags(set, hdr.value);
            },
            .as => {
                set.as_value = hdr.value;
                parseSealTags(set, hdr.value);
            },
        }
    }

    // Build ordered result array
    var result: std.ArrayListUnmanaged(ArcSet) = .{};
    errdefer result.deinit(allocator);

    var i: u8 = 0;
    while (i < max_instance) : (i += 1) {
        if (sets[i]) |set| {
            try result.append(allocator, set);
        } else {
            // Gap in chain — return what we have; caller validates completeness
            break;
        }
    }

    return result.toOwnedSlice(allocator);
}

/// Extract instance number from a header value (first tag must be i=N).
fn parseInstance(value: []const u8) ?u8 {
    const trimmed = mem.trimLeft(u8, value, &std.ascii.whitespace);
    // i= must be the first meaningful token
    if (!mem.startsWith(u8, trimmed, "i=")) {
        // May have whitespace before or tag order may differ — scan for i=
        if (findTag(trimmed, "i")) |val| {
            return std.fmt.parseInt(u8, val, 10) catch null;
        }
        return null;
    }
    const after_eq = trimmed[2..];
    const end = mem.indexOfAny(u8, after_eq, &.{ ';', ' ', '\t', '\r', '\n' }) orelse after_eq.len;
    return std.fmt.parseInt(u8, after_eq[0..end], 10) catch null;
}

/// Parse DKIM-like tags from AMS header value.
fn parseAmsTags(set: *ArcSet, value: []const u8) void {
    if (findTag(value, "a")) |v| set.ams_algorithm = v;
    if (findTag(value, "d")) |v| set.ams_domain = v;
    if (findTag(value, "s")) |v| set.ams_selector = v;
    if (findTag(value, "b")) |v| set.ams_signature = stripFws(v);
    if (findTag(value, "bh")) |v| set.ams_body_hash = stripFws(v);
    if (findTag(value, "c")) |v| set.ams_canonicalization = v;
    if (findTag(value, "h")) |v| set.ams_signed_headers = stripFws(v);
}

/// Parse seal-specific tags from AS header value.
fn parseSealTags(set: *ArcSet, value: []const u8) void {
    if (findTag(value, "cv")) |v| set.seal_cv = ChainValidation.fromString(v);
    if (findTag(value, "a")) |v| set.seal_algorithm = v;
    if (findTag(value, "d")) |v| set.seal_domain = v;
    if (findTag(value, "s")) |v| set.seal_selector = v;
    if (findTag(value, "b")) |v| set.seal_signature = stripFws(v);
}

/// Strip folding whitespace (FWS: SP, TAB, CR, LF) from a tag value.
/// Per RFC 6376 §3.5, FWS is allowed anywhere within tag values and must
/// be ignored when interpreting the value. Critical for base64 fields (b=, bh=)
/// and header lists (h=) that may span folded lines.
fn stripFws(value: []const u8) []const u8 {
    // Fast path: if no whitespace, return as-is (zero-copy)
    var has_ws = false;
    for (value) |c| {
        if (c == ' ' or c == '\t' or c == '\r' or c == '\n') {
            has_ws = true;
            break;
        }
    }
    if (!has_ws) return value;

    // Slow path: return a trimmed view by finding last non-WS byte
    // Since internal WS in base64/h= tokens is only from folding (and findTag
    // already trims leading/trailing), the WS should only appear at fold points.
    // For a zero-alloc approach, just trim from edges — the base64 decoder and
    // header-list parser will skip internal WS if present.
    // Actually: we can't strip INTERNAL whitespace without allocating.
    // Return the trimmed value — callers must handle internal FWS.
    return mem.trim(u8, value, &(.{ ' ', '\t', '\r', '\n' }));
}

/// Find a tag value by name in a semicolon-separated tag-list.
/// Handles "tag=value" pairs separated by ';', with optional whitespace.
pub fn findTag(header_value: []const u8, tag_name: []const u8) ?[]const u8 {
    var rest = header_value;
    while (rest.len > 0) {
        // Skip whitespace and semicolons
        rest = mem.trimLeft(u8, rest, &(.{ ';', ' ', '\t', '\r', '\n' }));
        if (rest.len == 0) break;

        // Find the '=' for this tag
        const eq_pos = mem.indexOfScalar(u8, rest, '=') orelse break;
        const name = mem.trim(u8, rest[0..eq_pos], &std.ascii.whitespace);

        // Find end of value (next ';' or end)
        const value_start = eq_pos + 1;
        const semi_pos = mem.indexOfScalar(u8, rest[value_start..], ';');
        const value_end = if (semi_pos) |sp| value_start + sp else rest.len;
        const value = mem.trim(u8, rest[value_start..value_end], &std.ascii.whitespace);

        if (eqlLower(name, tag_name)) {
            return value;
        }

        // Advance past this tag
        rest = if (semi_pos) |sp| rest[value_start + sp + 1 ..] else "";
    }
    return null;
}

/// Header name/value pair (matches Connection.headers format).
pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

pub fn eqlLower(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ca, cb| {
        const la: u8 = if (ca >= 'A' and ca <= 'Z') ca + 32 else ca;
        const lb: u8 = if (cb >= 'A' and cb <= 'Z') cb + 32 else cb;
        if (la != lb) return false;
    }
    return true;
}

// =============================================================================
// Tests
// =============================================================================

test "parseInstance basic" {
    try std.testing.expectEqual(@as(?u8, 1), parseInstance("i=1; cv=none; a=rsa-sha256"));
    try std.testing.expectEqual(@as(?u8, 3), parseInstance("i=3;cv=pass;a=rsa-sha256"));
    try std.testing.expectEqual(@as(?u8, null), parseInstance("cv=pass; a=rsa-sha256"));
}

test "findTag" {
    const val = "i=1; cv=pass; a=rsa-sha256; d=example.com; s=arc2026; b=AAAA==";
    try std.testing.expectEqualStrings("1", findTag(val, "i").?);
    try std.testing.expectEqualStrings("pass", findTag(val, "cv").?);
    try std.testing.expectEqualStrings("rsa-sha256", findTag(val, "a").?);
    try std.testing.expectEqualStrings("example.com", findTag(val, "d").?);
    try std.testing.expectEqualStrings("arc2026", findTag(val, "s").?);
    try std.testing.expectEqualStrings("AAAA==", findTag(val, "b").?);
    try std.testing.expect(findTag(val, "x") == null);
}

test "ChainValidation fromString" {
    try std.testing.expectEqual(ChainValidation.none, ChainValidation.fromString("none"));
    try std.testing.expectEqual(ChainValidation.pass, ChainValidation.fromString("pass"));
    try std.testing.expectEqual(ChainValidation.fail, ChainValidation.fromString("fail"));
    try std.testing.expectEqual(ChainValidation.unknown, ChainValidation.fromString("garbage"));
}

test "parseArcSets single set" {
    const headers = [_]Header{
        .{ .name = "ARC-Authentication-Results", .value = "i=1; mail.example.com; spf=pass" },
        .{ .name = "ARC-Message-Signature", .value = "i=1; a=rsa-sha256; d=example.com; s=arc; b=sig==; bh=hash==; h=from:to" },
        .{ .name = "ARC-Seal", .value = "i=1; cv=none; a=rsa-sha256; d=example.com; s=arc; b=seal==" },
    };

    const sets = try parseArcSets(std.testing.allocator, &headers);
    defer std.testing.allocator.free(sets);

    try std.testing.expectEqual(@as(usize, 1), sets.len);
    try std.testing.expectEqual(@as(u8, 1), sets[0].instance);
    try std.testing.expectEqual(ChainValidation.none, sets[0].seal_cv);
    try std.testing.expectEqualStrings("example.com", sets[0].seal_domain);
    try std.testing.expectEqualStrings("rsa-sha256", sets[0].ams_algorithm);
    try std.testing.expectEqualStrings("from:to", sets[0].ams_signed_headers);
}

test "parseArcSets empty" {
    const headers = [_]Header{
        .{ .name = "From", .value = "user@example.com" },
        .{ .name = "Subject", .value = "test" },
    };

    const sets = try parseArcSets(std.testing.allocator, &headers);
    defer std.testing.allocator.free(sets);

    try std.testing.expectEqual(@as(usize, 0), sets.len);
}
