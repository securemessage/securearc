//! Turning a message file into the view of a message a *milter* receives.
//!
//! Extracted from `check.zig` when `seal_cli.zig` needed the identical operation.
//! Sharing it is not tidiness — **if the two tools parsed files differently, one of
//! them would stop predicting the daemon while still reporting a conformance
//! score**, and the two scores would no longer be comparable. That failure has
//! already happened twice on this project, both times arriving disguised as a pile
//! of product defects: the `c=simple/*` cases in the ARC validation suite, and the
//! DNS server in the DKIM suite that served key records one character at a time.
//!
//! The rules encoded here are deliberate models of production, each documented at
//! its site: CRLF normalisation, folding preserved, and one space dropped after the
//! colon. Anything a milter does not do, this must not do either.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

/// One header field as the MTA hands it over: name, and value with the single
/// separating space already removed.
///
/// Structurally identical to both `arc.Header` and
/// `securemilter.connection.Header`, and deliberately its own type: this module
/// sits below both and should not have to pick one. Callers convert, which is a
/// field-for-field copy.
pub const Field = struct {
    name: []const u8,
    value: []const u8,
};

/// A parsed message: header fields in order, plus the body. Owns its storage.
pub const Message = struct {
    fields: []const Field,
    body: []const u8,
    arena: std.heap.ArenaAllocator,

    pub fn deinit(self: *Message) void {
        self.arena.deinit();
    }
};

/// Split an RFC 5322 message into header fields and a body.
///
/// Folded values keep their line breaks. That is not a convenience: DKIM and ARC
/// relaxed canonicalization is defined as an operation *on* the folded form, and
/// the milter receives values from Postfix with folding intact, so unfolding here
/// would test a canonicalizer against input it never sees in production.
///
/// Line endings are normalised to CRLF first. A message arrives over SMTP with
/// CRLF, both canonicalizations in RFC 6376 §3.4 are specified in terms of it, and
/// the ValiMail YAML carries bare LF purely because that is how YAML block scalars
/// work. Converting here rather than tolerating LF further down keeps the
/// conformance run testing the same byte sequence a real message produces.
/// **If cases fail with a body-hash mismatch, check this first.**
pub fn parseMessage(allocator: Allocator, raw: []const u8) !Message {
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const a = arena.allocator();

    const text = try toCrlf(a, raw);

    // Header section ends at the first empty line. A message with no empty line
    // is all headers and an empty body.
    const sep = mem.indexOf(u8, text, "\r\n\r\n");
    const header_block = if (sep) |s| text[0..s] else text;
    const body = if (sep) |s| text[s + 4 ..] else "";

    var fields: std.ArrayListUnmanaged(Field) = .{};

    // Walk the header block, starting a new field on a line that does not begin
    // with WSP and folding the rest into the value.
    var field_start: ?usize = null;
    var i: usize = 0;
    while (i <= header_block.len) {
        const line_end = mem.indexOfPos(u8, header_block, i, "\r\n") orelse header_block.len;
        const line = header_block[i..line_end];
        const is_continuation = line.len > 0 and (line[0] == ' ' or line[0] == '\t');

        if (!is_continuation and field_start != null) {
            try appendField(a, &fields, header_block[field_start.?..i]);
            field_start = null;
        }
        if (line.len > 0 and !is_continuation) field_start = i;

        if (line_end >= header_block.len) break;
        i = line_end + 2;
    }
    if (field_start) |s| try appendField(a, &fields, header_block[s..]);

    return .{
        .fields = try fields.toOwnedSlice(a),
        .body = body,
        .arena = arena,
    };
}

/// Record one complete field, trailing CRLF trimmed, split at the first colon.
///
/// A field with no colon is skipped rather than guessed at: it is not a header
/// field, and inventing a name for it would put a fabricated entry into the list
/// the signature covers.
///
/// **The space after the colon is dropped, on purpose.** A milter receives header
/// values from the MTA with leading whitespace already removed unless it negotiates
/// `SMFIP_HDR_LEADSPC`, which no daemon in this suite does — see the sendmail
/// `xxfi_header` documentation, and `ProtocolFlags.header_leading_space` in
/// `securemilter-lib`, which is defined and never requested. Keeping the space here
/// would hand the verifier a byte sequence production never produces, and `simple`
/// header canonicalization — which hashes the field verbatim — would disagree for
/// every case.
///
/// Exactly *one* space is removed, which is what production models today. Whether
/// the MTA removes one or all of the leading WSP is the unresolved half of audit
/// D-23; if it removes all, this line and the six production sites it mirrors are
/// all wrong together, which is the point of them being one rule in one place.
///
/// Continuation lines keep their own leading whitespace, which is also what the MTA
/// delivers.
fn appendField(
    a: Allocator,
    fields: *std.ArrayListUnmanaged(Field),
    field_raw: []const u8,
) !void {
    const field = mem.trimRight(u8, field_raw, "\r\n");
    if (field.len == 0) return;
    const colon = mem.indexOfScalar(u8, field, ':') orelse return;
    var value = field[colon + 1 ..];
    if (value.len > 0 and (value[0] == ' ' or value[0] == '\t')) value = value[1..];
    try fields.append(a, .{
        .name = field[0..colon],
        .value = value,
    });
}

/// Normalise CR, LF and CRLF to CRLF.
pub fn toCrlf(a: Allocator, raw: []const u8) ![]const u8 {
    var out: std.ArrayListUnmanaged(u8) = .{};
    try out.ensureTotalCapacity(a, raw.len + raw.len / 8 + 2);
    var i: usize = 0;
    while (i < raw.len) {
        const c = raw[i];
        if (c == '\r') {
            try out.appendSlice(a, "\r\n");
            i += if (i + 1 < raw.len and raw[i + 1] == '\n') 2 else 1;
        } else if (c == '\n') {
            try out.appendSlice(a, "\r\n");
            i += 1;
        } else {
            try out.append(a, c);
            i += 1;
        }
    }
    return out.toOwnedSlice(a);
}

test "one space after the colon is removed, further whitespace is data" {
    const a = std.testing.allocator;
    var msg = try parseMessage(a, "From: a@b.c\r\nX-Two:  two spaces\r\nX-None:none\r\n\r\nbody\r\n");
    defer msg.deinit();

    try std.testing.expectEqual(@as(usize, 3), msg.fields.len);
    try std.testing.expectEqualStrings("a@b.c", msg.fields[0].value);
    // The second space survives. See appendField: whether that matches the MTA is
    // audit D-23's open question, and this test pins what we currently model so a
    // change to it has to be deliberate.
    try std.testing.expectEqualStrings(" two spaces", msg.fields[1].value);
    try std.testing.expectEqualStrings("none", msg.fields[2].value);
    try std.testing.expectEqualStrings("body\r\n", msg.body);
}

test "folding is preserved and bare LF is normalised" {
    const a = std.testing.allocator;
    var msg = try parseMessage(a, "Subject: one\n\ttwo\nFrom: x@y\n\nb\n");
    defer msg.deinit();

    try std.testing.expectEqual(@as(usize, 2), msg.fields.len);
    try std.testing.expectEqualStrings("one\r\n\ttwo", msg.fields[0].value);
    try std.testing.expectEqualStrings("x@y", msg.fields[1].value);
}

test "a field with no colon is skipped rather than guessed at" {
    const a = std.testing.allocator;
    var msg = try parseMessage(a, "From: a@b\r\ngarbage-no-colon\r\nTo: c@d\r\n\r\n");
    defer msg.deinit();

    try std.testing.expectEqual(@as(usize, 2), msg.fields.len);
    try std.testing.expectEqualStrings("From", msg.fields[0].name);
    try std.testing.expectEqualStrings("To", msg.fields[1].name);
}
