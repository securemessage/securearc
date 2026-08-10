const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const securemilter = @import("securemilter");
const cfws = securemilter.cfws;

const securemilter_crypto = @import("securemilter_crypto");
const sig_header = securemilter_crypto.sig_header;

/// Maximum ARC chain length per RFC 8617 §5.1.1
pub const MAX_INSTANCES: u8 = 50;

/// ARC header types in a set. The values index the per-instance duplicate
/// tracking in parseArcSets.
pub const HeaderType = enum(u2) {
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
    /// Whether a space followed the colon on the AMS header field itself.
    /// The AMS is part of its own signing input, so validating it under
    /// `c=simple` hashes this field verbatim and the separator has to be the
    /// real one (audit D-23).
    ams_had_space: bool = true,
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

/// Chain errors: RFC 8617 §5.1.2 requires `cv=fail` for any incomplete or too-long
/// chain. Validating a partial prefix asserts a verdict over a chain not attached.
pub const ChainError = error{
    /// An instance number between 1 and the highest one seen is missing.
    ChainGap,
    /// An instance carries the same ARC header twice.
    DuplicateHeader,
    /// An instance number above MAX_INSTANCES.
    ChainTooLong,
    /// An instance is missing its AAR, AMS or AS.
    IncompleteSet,
    /// An ARC header whose i= tag is absent, zero or unparseable.
    MalformedInstance,
    /// An AMS or AS whose tag list violates RFC 6376 §3.2 -- a tag name that is
    /// not `ALPHA *ALNUMPUNC`, a duplicated tag name, an interior empty
    /// tag-spec, or a spec with no `=`.
    MalformedTagList,
};

/// True when an ARC-Seal already on the message records `cv=fail`.
///
/// RFC 8617 §5.1.3 is unambiguous: *"A message can have only one Authenticated
/// Received Chain on it at a time. Once broken, the chain cannot be continued, as the
/// chain of custody is no longer valid, and responsibility for the message has been
/// lost."* So a hop that finds `cv=fail` already recorded must add no ARC set —
/// there is nothing left to extend, and a set appended to a terminated chain claims
/// custody of a message whose custody has already been lost.
///
/// **This is a narrower question than "does the chain validate".** A chain can fail
/// validation here and now for many reasons — a tampered AMS, an unreachable key —
/// and in those cases the correct action is to seal `cv=fail`, which is what records
/// the break for the next hop. What this predicate detects is a break some *earlier*
/// hop already recorded. Conflating the two would stop us marking newly detected
/// failures, which is the opposite mistake and a worse one.
///
/// The ValiMail signing suite separates the two cases directly: `i1_base_fail` and
/// `i2_base_fail` expect a `cv=fail` set to be added, while `no_additional_sig` —
/// whose newest existing seal already says `cv=fail` — expects no set at all.
pub fn chainAlreadyBroken(sets: []const ArcSet) bool {
    for (sets) |set| if (set.seal_cv == .fail) return true;
    return false;
}

/// Human-readable ChainError reason suitable for A-R header text.
pub fn describeChainError(err: anyerror) []const u8 {
    return switch (err) {
        error.ChainGap => "broken ARC chain: missing instance",
        error.DuplicateHeader => "broken ARC chain: duplicate header in instance",
        error.ChainTooLong => "broken ARC chain: too many instances",
        error.IncompleteSet => "broken ARC chain: incomplete instance",
        error.MalformedInstance => "broken ARC chain: malformed i= tag",
        error.MalformedTagList => "broken ARC chain: malformed tag list",
        else => "broken ARC chain",
    };
}

/// Parse ARC-related headers from a list of message headers and build ordered ARC sets.
///
/// Returns sets ordered by instance number, 1..N with no gaps, each complete.
/// Anything else is a ChainError: the caller must report `cv=fail` rather than
/// validate a subset of the chain the message actually carries.
pub fn parseArcSets(allocator: Allocator, headers: []const Header) ![]ArcSet {
    var sets: [MAX_INSTANCES]?ArcSet = .{null} ** MAX_INSTANCES;
    var seen: [MAX_INSTANCES][3]bool = .{.{ false, false, false }} ** MAX_INSTANCES;
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

        const instance = parseInstance(hdr.value) orelse return error.MalformedInstance;
        if (instance == 0) return error.MalformedInstance;
        if (instance > MAX_INSTANCES) return error.ChainTooLong;
        if (instance > max_instance) max_instance = instance;

        // RFC 8617 §5.1.1: exactly one of each header per instance.
        const slot = @intFromEnum(htype);
        if (seen[instance - 1][slot]) return error.DuplicateHeader;
        seen[instance - 1][slot] = true;

        const idx = instance - 1;
        if (sets[idx] == null) {
            sets[idx] = ArcSet{
                .instance = instance,
                .aar_value = "",
                .ams_value = "",
                .as_value = "",
                .ams_had_space = true,
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
            // The AAR is NOT validated as a tag list. Its ABNF is
            // `instance [CFWS] ";" authserv-id ... resinfo` (RFC 8617 §4.1.1) --
            // an Authentication-Results field behind an i= tag, not a
            // `tag=value` list -- so RFC 6376 §3.2 does not apply to it and
            // applying it anyway would reject every real chain.
            .aar => set.aar_value = hdr.value,
            .ams => {
                // RFC 8617 §4.1.2: the AMS "has the same syntax and semantics as
                // the DKIM-Signature field", so its tag list must satisfy
                // RFC 6376 §3.2. A list that does not is a broken chain rather
                // than an absent one, the same reasoning as a missing instance.
                sig_header.validateTagList(hdr.value) catch return error.MalformedTagList;
                set.ams_value = hdr.value;
                set.ams_had_space = hdr.had_space;
                parseAmsTags(set, hdr.value);
            },
            .as => {
                // RFC 8617 §4.1.3 gives the AS the same tag-list syntax.
                sig_header.validateTagList(hdr.value) catch return error.MalformedTagList;
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
        const set = sets[i] orelse return error.ChainGap;
        if (set.aar_value.len == 0 or set.ams_value.len == 0 or set.as_value.len == 0) {
            return error.IncompleteSet;
        }
        try result.append(allocator, set);
    }

    return result.toOwnedSlice(allocator);
}

/// The instance number of an ARC header field (audit A-11).
///
/// RFC 8617 gives all three ARC header fields the same shape, with `instance`
/// lifted **out** of the tag list and placed before the semicolon:
///
///     instance     = [CFWS] %s"i" [CFWS] "=" [CFWS] position
///     position     = 1*2DIGIT                         ; 1 - 50
///     arc-info     = instance [CFWS] ";" authres-payload
///     arc-ams-info = instance [CFWS] ";" tag-list
///     arc-as-info  = instance [CFWS] ";" tag-list
///
/// So `i=` is not a member of the tag list at all, and the grammar requires it
/// first. A naive `startsWith("i=")` test is too strict, since `[CFWS]` is
/// permitted in three places and CFWS includes parenthesised comments, and too
/// lenient once it falls through to a bare scan for `i=` anywhere in the field.
///
/// This parses the production properly and *keeps* a by-name fallback for
/// anything that does not match. The fallback is a deliberate interop
/// concession, not an oversight: OpenARC never checks the position at all --
/// `arc_parse_header_field` does only RFC 5322 field-level syntax and the value
/// is fetched by name with `arc_param_get(set, "i")` -- so enforcing the grammar
/// would make us reject chains the reference implementation accepts, on an
/// Experimental protocol, for no security gain. The instance is range-checked by
/// the caller either way, and duplicate tags are already refused (A-16, A-17),
/// so a late `i=` is not more forgeable.
///
/// Note `%s"i"`: RFC 7405 makes that a case-*sensitive* match, so `I=1` is not an
/// instance tag. `findTag` is case-sensitive too, since A-17.
fn parseInstance(value: []const u8) ?u8 {
    if (parseInstanceProduction(value)) |n| return n;

    // Not where the grammar puts it. Accepted anyway, to match OpenARC.
    if (findTag(value, "i")) |val| return std.fmt.parseInt(u8, val, 10) catch null;
    return null;
}

/// `instance [CFWS] ";"` exactly as the ABNF spells it, or null.
fn parseInstanceProduction(value: []const u8) ?u8 {
    var i = cfws.skip(value, 0);

    if (i >= value.len or value[i] != 'i') return null;
    i = cfws.skip(value, i + 1);

    if (i >= value.len or value[i] != '=') return null;
    i = cfws.skip(value, i + 1);

    // 1*2DIGIT. Bounded at two so `i=100` does not silently read as 10 and then
    // leave `0` dangling -- it fails here and takes the fallback, which reads
    // 100 and lets the caller reject it as over-length.
    const start = i;
    while (i < value.len and i - start < 2 and std.ascii.isDigit(value[i])) i += 1;
    if (i == start) return null;
    const n = std.fmt.parseInt(u8, value[start..i], 10) catch return null;

    // The production continues `[CFWS] ";"`. Requiring it is what rejects a
    // third digit, and what keeps this from matching some other tag that merely
    // happens to begin with `i`.
    const after = cfws.skip(value, i);
    if (after >= value.len or value[after] != ';') return null;

    return n;
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

    // Internal WS in a base64/h= token comes only from folding, so trimming the
    // edges is enough without allocating; callers (the base64 decoder and the
    // header-list parser) skip any internal FWS that remains.
    return mem.trim(u8, value, &(.{ ' ', '\t', '\r', '\n' }));
}

/// Find a tag value by name in a semicolon-separated tag-list.
///
/// An alias, not a second body: the tag scanner lives in
/// `securemilter_crypto.sig_header` because a DKIM signature, an ARC set and a
/// DNS key record are all the same RFC 6376 §3.2 tag list. Kept exported under
/// this name because `chain.zig` reads `p=` out of a key record through it.
pub const findTag = sig_header.findTag;

/// Header name/value pair (matches Connection.headers format).
pub const Header = struct {
    name: []const u8,
    value: []const u8,
    /// Whether a space followed the colon on the wire. Mirrors
    /// `Connection.Header.had_space`, and must keep mirroring it: this type
    /// exists so `arc.zig` need not depend on the milter transport, but a field
    /// the copy drops is a field the AMS hash gets wrong under `c=simple`
    /// (audit D-23). Defaults to the classic MTA behaviour.
    had_space: bool = true,

    /// Rebuild the field as it appeared on the wire. See
    /// `Connection.Header.render`.
    pub fn render(self: Header, allocator: std.mem.Allocator) ![]u8 {
        return std.fmt.allocPrint(allocator, "{s}:{s}{s}", .{
            self.name,
            if (self.had_space) " " else "",
            self.value,
        });
    }
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

test "A-11: CFWS is allowed everywhere the instance production allows it" {
    // `instance = [CFWS] %s\"i\" [CFWS] \"=\" [CFWS] position`. Each of these is a
    // conformant ARC header field and must parse; a literal `i=` prefix test
    // would miss them all and refuse chains the RFC permits (audit A-11).
    try std.testing.expectEqual(@as(?u8, 1), parseInstance("(set 1) i=1; cv=none"));
    try std.testing.expectEqual(@as(?u8, 1), parseInstance("i = 1 ; cv=none"));
    try std.testing.expectEqual(@as(?u8, 2), parseInstance("i (why not) = 2; cv=pass"));
    try std.testing.expectEqual(@as(?u8, 7), parseInstance("  \t i=7;cv=pass"));
    // Folding whitespace, which is what a real header carries once unfolded.
    try std.testing.expectEqual(@as(?u8, 4), parseInstance("\r\n i=4; cv=none"));
    // Nested comments are still one comment.
    try std.testing.expectEqual(@as(?u8, 5), parseInstance("(a (b) c) i=5; cv=none"));
}

test "A-11: the instance tag is case-sensitive" {
    // RFC 7405 %s makes `%s\"i\"` a case-sensitive literal, and findTag has been
    // case-sensitive since A-17, so neither path may accept `I=`.
    try std.testing.expectEqual(@as(?u8, null), parseInstance("I=1; cv=none"));
}

test "A-11: a tag merely beginning with i is not the instance" {
    // The production requires `=` (modulo CFWS) straight after the `i`. Without
    // the trailing-`;` and next-character checks this could latch onto the wrong
    // tag entirely and report someone else's value as the instance.
    try std.testing.expectEqual(@as(?u8, 1), parseInstance("instance=5; i=1; cv=none"));
}

test "A-11: position is 1*2DIGIT, and a longer number still reaches the caller" {
    // `position` is at most two digits, so `i=100` does not match the production.
    // It must not be truncated to 10 -- that would silently graft a header onto
    // the wrong ARC set. It falls through to the fallback, which reads 100, and
    // the caller rejects it with ChainTooLong against MAX_INSTANCES.
    try std.testing.expectEqual(@as(?u8, 100), parseInstance("i=100; cv=none"));
    try std.testing.expectEqual(@as(?u8, 50), parseInstance("i=50; cv=none"));
}

test "A-11: an instance outside the production is still accepted, matching OpenARC" {
    // Deliberate, not an oversight. OpenARC fetches the instance by name with
    // `arc_param_get(set, \"i\")` and never checks its position, so refusing this
    // would cv=fail chains the reference implementation validates. If this ever
    // flips to null, that is the strictness decision being taken on purpose.
    try std.testing.expectEqual(@as(?u8, 2), parseInstance("a=rsa-sha256; i=2; cv=pass"));
    try std.testing.expectEqual(@as(?u8, 3), parseInstance("cv=pass; a=rsa-sha256; i=3"));
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

test "parseArcSets rejects a gap in the chain" {
    // The A-4 exploit: a genuine i=1 set with a garbage i=3 set prepended.
    // Truncating to [i=1] and validating it asserts arc=pass over a chain the
    // message does not have.
    const headers = [_]Header{
        .{ .name = "ARC-Authentication-Results", .value = "i=3; evil.test; spf=pass" },
        .{ .name = "ARC-Message-Signature", .value = "i=3; a=rsa-sha256; d=evil.test; s=x; b=QUFBQQ==; bh=QUFBQQ==; h=from" },
        .{ .name = "ARC-Seal", .value = "i=3; cv=pass; a=rsa-sha256; d=evil.test; s=x; b=QUFBQQ==" },
        .{ .name = "ARC-Authentication-Results", .value = "i=1; mail.example.com; spf=pass" },
        .{ .name = "ARC-Message-Signature", .value = "i=1; a=rsa-sha256; d=example.com; s=arc; b=sig==; bh=hash==; h=from" },
        .{ .name = "ARC-Seal", .value = "i=1; cv=none; a=rsa-sha256; d=example.com; s=arc; b=seal==" },
    };

    try std.testing.expectError(error.ChainGap, parseArcSets(std.testing.allocator, &headers));
}

test "parseArcSets rejects a duplicated header within an instance" {
    const headers = [_]Header{
        .{ .name = "ARC-Authentication-Results", .value = "i=1; mail.example.com; spf=pass" },
        .{ .name = "ARC-Message-Signature", .value = "i=1; a=rsa-sha256; d=example.com; s=arc; b=sig==; bh=hash==; h=from" },
        .{ .name = "ARC-Seal", .value = "i=1; cv=none; a=rsa-sha256; d=example.com; s=arc; b=seal==" },
        // A second seal for the same instance: which one is the chain?
        .{ .name = "ARC-Seal", .value = "i=1; cv=pass; a=rsa-sha256; d=evil.test; s=x; b=QUFBQQ==" },
    };

    try std.testing.expectError(error.DuplicateHeader, parseArcSets(std.testing.allocator, &headers));
}

test "parseArcSets rejects an incomplete instance" {
    const headers = [_]Header{
        .{ .name = "ARC-Authentication-Results", .value = "i=1; mail.example.com; spf=pass" },
        .{ .name = "ARC-Seal", .value = "i=1; cv=none; a=rsa-sha256; d=example.com; s=arc; b=seal==" },
    };

    try std.testing.expectError(error.IncompleteSet, parseArcSets(std.testing.allocator, &headers));
}

test "parseArcSets rejects an instance above the chain limit" {
    const headers = [_]Header{
        .{ .name = "ARC-Seal", .value = "i=51; cv=pass; a=rsa-sha256; d=evil.test; s=x; b=QUFBQQ==" },
    };

    try std.testing.expectError(error.ChainTooLong, parseArcSets(std.testing.allocator, &headers));
}

test "parseArcSets rejects a malformed instance tag" {
    const missing = [_]Header{
        .{ .name = "ARC-Seal", .value = "cv=pass; a=rsa-sha256; d=evil.test; s=x; b=QUFBQQ==" },
    };
    try std.testing.expectError(error.MalformedInstance, parseArcSets(std.testing.allocator, &missing));

    const zero = [_]Header{
        .{ .name = "ARC-Seal", .value = "i=0; cv=pass; a=rsa-sha256; d=evil.test; s=x; b=QUFBQQ==" },
    };
    try std.testing.expectError(error.MalformedInstance, parseArcSets(std.testing.allocator, &zero));
}

test "parseArcSets accepts a complete two-instance chain" {
    const headers = [_]Header{
        .{ .name = "ARC-Authentication-Results", .value = "i=2; relay.test; spf=pass" },
        .{ .name = "ARC-Message-Signature", .value = "i=2; a=rsa-sha256; d=relay.test; s=arc; b=s2==; bh=h2==; h=from" },
        .{ .name = "ARC-Seal", .value = "i=2; cv=pass; a=rsa-sha256; d=relay.test; s=arc; b=seal2==" },
        .{ .name = "ARC-Authentication-Results", .value = "i=1; mail.example.com; spf=pass" },
        .{ .name = "ARC-Message-Signature", .value = "i=1; a=rsa-sha256; d=example.com; s=arc; b=sig==; bh=hash==; h=from" },
        .{ .name = "ARC-Seal", .value = "i=1; cv=none; a=rsa-sha256; d=example.com; s=arc; b=seal==" },
    };

    const sets = try parseArcSets(std.testing.allocator, &headers);
    defer std.testing.allocator.free(sets);

    try std.testing.expectEqual(@as(usize, 2), sets.len);
    try std.testing.expectEqual(@as(u8, 1), sets[0].instance);
    try std.testing.expectEqual(@as(u8, 2), sets[1].instance);
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

test "findTag matches tag names case sensitively (RFC 6376 3.2)" {
    // "Tags MUST be interpreted in a case-sensitive manner." A mis-cased tag is
    // a DIFFERENT tag, not the same one written oddly, so the tag it was meant
    // to be is absent.
    const mis_cased = "i=1; cv=none; a=rsa-sha256; d=example.org; S=dummy; t=12345";
    try std.testing.expect(findTag(mis_cased, "s") == null);
    try std.testing.expectEqualStrings("dummy", findTag(mis_cased, "S").?);

    // Matching case-insensitively would let an ARC-Seal carrying `S=` be read as
    // having a selector and verify against a key it never actually named. The
    // suite case is `as_format_tags_key_case`.
    const correct = "i=1; cv=none; a=rsa-sha256; d=example.org; s=dummy";
    try std.testing.expectEqualStrings("dummy", findTag(correct, "s").?);
}

test "parseArcSets rejects tag lists RFC 6376 3.2 forbids" {
    const a = std.testing.allocator;
    const good_ams = "i=1; a=rsa-sha256; c=relaxed/relaxed; d=e.org; s=d; bh=x; b=y; h=from";

    // A duplicated tag anywhere in the set breaks the chain, rather than the set
    // being silently accepted with one of the two values winning.
    {
        const headers = [_]Header{
            .{ .name = "ARC-Authentication-Results", .value = "i=1; e.org; spf=pass" },
            .{ .name = "ARC-Message-Signature", .value = good_ams },
            .{ .name = "ARC-Seal", .value = "i=1; cv=none; a=rsa-sha256; d=e.org; s=d; s=d; b=y" },
        };
        try std.testing.expectError(error.MalformedTagList, parseArcSets(a, &headers));
    }

    // A tag name that is not ALPHA *ALNUMPUNC.
    {
        const headers = [_]Header{
            .{ .name = "ARC-Authentication-Results", .value = "i=1; e.org; spf=pass" },
            .{ .name = "ARC-Message-Signature", .value = good_ams },
            .{ .name = "ARC-Seal", .value = "i=1; cv=none; a=rsa-sha256; d=e.org; s=d; _=; b=y" },
        };
        try std.testing.expectError(error.MalformedTagList, parseArcSets(a, &headers));
    }

    // An interior empty tag-spec.
    {
        const headers = [_]Header{
            .{ .name = "ARC-Authentication-Results", .value = "i=1; e.org; spf=pass" },
            .{ .name = "ARC-Message-Signature", .value = good_ams },
            .{ .name = "ARC-Seal", .value = "i=1; cv=none; a=rsa-sha256; d=e.org; s=d;; b=y" },
        };
        try std.testing.expectError(error.MalformedTagList, parseArcSets(a, &headers));
    }

    // A trailing ";" is explicitly allowed by the ABNF and must NOT break it --
    // the suite case is `as_format_tags_trail_sc`, which expects pass.
    {
        const headers = [_]Header{
            .{ .name = "ARC-Authentication-Results", .value = "i=1; e.org; spf=pass" },
            .{ .name = "ARC-Message-Signature", .value = good_ams },
            .{ .name = "ARC-Seal", .value = "i=1; cv=none; a=rsa-sha256; d=e.org; s=d; b=y;" },
        };
        const sets = try parseArcSets(a, &headers);
        defer a.free(sets);
        try std.testing.expectEqual(@as(usize, 1), sets.len);
    }

    // The AAR is not a tag list and must not be validated as one: its ABNF is an
    // Authentication-Results field behind an i= tag. Checking it would reject
    // every real chain.
    {
        const headers = [_]Header{
            .{ .name = "ARC-Authentication-Results", .value = "i=1; e.org; spf=pass smtp.mailfrom=a@e.org; dkim=pass (1024-bit key) header.i=@e.org" },
            .{ .name = "ARC-Message-Signature", .value = good_ams },
            .{ .name = "ARC-Seal", .value = "i=1; cv=none; a=rsa-sha256; d=e.org; s=d; b=y" },
        };
        const sets = try parseArcSets(a, &headers);
        defer a.free(sets);
        try std.testing.expectEqual(@as(usize, 1), sets.len);
    }
}
