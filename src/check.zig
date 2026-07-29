//! `securearc-check` — validate the ARC chain of a message file and print the result.
//!
//! Exists so ARC chain validation can be driven by an external conformance suite
//! the way `securespf-check` lets the RFC 7208 suite drive SPF evaluation. The
//! ValiMail `arc_test_suite` is written against exactly this interface: give it a
//! message and a nameserver, get back `none`, `pass` or `fail`.
//!
//! It deliberately calls the same `arc.parseArcSets` and `chain.validateChain`
//! the milter calls, in the same order and with the same treatment of a chain
//! that fails to parse, so that a conformance result is a statement about the
//! shipped verifier rather than about a parallel implementation written to pass
//! tests. `flow.doVerify` is not reused directly only because it needs a live
//! milter `Connection`.

const std = @import("std");
const mem = std.mem;
const posix = std.posix;
const process = std.process;
const Allocator = mem.Allocator;

const securemilter = @import("securemilter");
const dns_mod = securemilter.dns;

const arc = @import("arc.zig");
const chain = @import("chain.zig");

fn writeOut(data: []const u8) void {
    _ = posix.write(posix.STDOUT_FILENO, data) catch {};
}

fn writeErr(data: []const u8) void {
    _ = posix.write(posix.STDERR_FILENO, data) catch {};
}

fn fatal(msg: []const u8) void {
    writeErr("securearc-check: ");
    writeErr(msg);
    writeErr("\n");
    process.exit(2);
}

const Usage =
    \\Usage: securearc-check [options] <message-file>
    \\
    \\Validate the ARC chain of an RFC 5322 message and print the chain
    \\validation value: none, pass or fail.
    \\
    \\Options:
    \\  -f <file>        Message file (may also be given positionally)
    \\  -n <nameserver>  DNS nameserver (default: 127.0.0.1)
    \\  -p <port>        DNS nameserver port (default: 53)
    \\  -b <bits>        Minimum RSA key bits accepted (default: 1024)
    \\  -v               Verbose: also print the failure reason and instance count
    \\  -h               Show this help
    \\
    \\Exit status is 0 whenever a verdict was reached, including "fail" — the
    \\verdict goes to stdout. A non-zero status means the tool could not run.
    \\
;

/// Largest message accepted. Generous for a conformance suite whose cases are a
/// few kilobytes, and bounded so a stray argument cannot exhaust memory.
const MAX_MESSAGE_BYTES = 8 * 1024 * 1024;

/// A parsed message: header fields in order, plus the body.
const Message = struct {
    headers: []const arc.Header,
    body: []const u8,
    arena: std.heap.ArenaAllocator,

    fn deinit(self: *Message) void {
        self.arena.deinit();
    }
};

/// Split an RFC 5322 message into header fields and a body.
///
/// Folded values keep their line breaks. That is not a convenience: DKIM and ARC
/// relaxed canonicalization is defined as an operation *on* the folded form, and
/// the milter receives values from Postfix with folding intact, so unfolding
/// here would test a canonicalizer against input it never sees in production.
///
/// Line endings are normalised to CRLF first. A message arrives over SMTP with
/// CRLF, both canonicalizations in RFC 6376 §3.4 are specified in terms of it,
/// and the suite's YAML carries bare LF purely because that is how YAML block
/// scalars work. Converting here rather than tolerating LF further down keeps
/// the conformance run testing the same byte sequence a real message produces.
/// **If cases fail with a body-hash mismatch, check this first.**
fn parseMessage(allocator: Allocator, raw: []const u8) !Message {
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const a = arena.allocator();

    const text = try toCrlf(a, raw);

    // Header section ends at the first empty line. A message with no empty line
    // is all headers and an empty body.
    const sep = mem.indexOf(u8, text, "\r\n\r\n");
    const header_block = if (sep) |s| text[0..s] else text;
    const body = if (sep) |s| text[s + 4 ..] else "";

    var headers: std.ArrayListUnmanaged(arc.Header) = .{};

    // Walk the header block, starting a new field on a line that does not begin
    // with WSP and folding the rest into the value.
    var field_start: ?usize = null;
    var i: usize = 0;
    while (i <= header_block.len) {
        const line_end = mem.indexOfPos(u8, header_block, i, "\r\n") orelse header_block.len;
        const line = header_block[i..line_end];
        const is_continuation = line.len > 0 and (line[0] == ' ' or line[0] == '\t');

        if (!is_continuation and field_start != null) {
            try appendField(a, &headers, header_block[field_start.?..i]);
            field_start = null;
        }
        if (line.len > 0 and !is_continuation) field_start = i;

        if (line_end >= header_block.len) break;
        i = line_end + 2;
    }
    if (field_start) |s| try appendField(a, &headers, header_block[s..]);

    return .{
        .headers = try headers.toOwnedSlice(a),
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
/// values from the MTA with leading whitespace already removed unless it
/// negotiates `SMFIP_HDR_LEADSPC`, which no daemon in this suite does — see the
/// sendmail `xxfi_header` documentation, and `ProtocolFlags.header_leading_space`
/// in `securemilter-lib`, which is defined and never requested. Keeping the space
/// here would hand the verifier a byte sequence production never produces, and
/// `simple` header canonicalization — which hashes the field verbatim — would
/// disagree for every case.
///
/// Continuation lines keep their own leading whitespace, which is also what the
/// MTA delivers.
fn appendField(
    a: Allocator,
    headers: *std.ArrayListUnmanaged(arc.Header),
    field_raw: []const u8,
) !void {
    const field = mem.trimRight(u8, field_raw, "\r\n");
    if (field.len == 0) return;
    const colon = mem.indexOfScalar(u8, field, ':') orelse return;
    var value = field[colon + 1 ..];
    if (value.len > 0 and (value[0] == ' ' or value[0] == '\t')) value = value[1..];
    try headers.append(a, .{
        .name = field[0..colon],
        .value = value,
    });
}

/// Normalise CR, LF and CRLF to CRLF.
fn toCrlf(a: Allocator, raw: []const u8) ![]const u8 {
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

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var args = process.args();
    _ = args.next();

    var path: ?[]const u8 = null;
    var nameserver: []const u8 = "127.0.0.1";
    // Exposed for the same reason securespf-check exposes it: the conformance
    // suite serves its own zone on a high port, which cannot bind 53 unprivileged.
    var port: u16 = 53;
    var min_key_bits: u32 = 1024;
    var verbose = false;

    while (args.next()) |a| {
        if (mem.eql(u8, a, "-h") or mem.eql(u8, a, "--help")) {
            writeOut(Usage);
            return;
        } else if (mem.eql(u8, a, "-f")) {
            path = args.next() orelse return fatal("missing argument for -f");
        } else if (mem.eql(u8, a, "-n")) {
            nameserver = args.next() orelse return fatal("missing argument for -n");
        } else if (mem.eql(u8, a, "-p")) {
            const raw = args.next() orelse return fatal("missing argument for -p");
            port = std.fmt.parseInt(u16, raw, 10) catch return fatal("-p must be a port number");
        } else if (mem.eql(u8, a, "-b")) {
            const raw = args.next() orelse return fatal("missing argument for -b");
            min_key_bits = std.fmt.parseInt(u32, raw, 10) catch return fatal("-b must be a number");
        } else if (mem.eql(u8, a, "-v")) {
            verbose = true;
        } else if (a.len > 0 and a[0] == '-') {
            return fatal("unknown option (use -h for help)");
        } else {
            path = a;
        }
    }

    const msg_path = path orelse return fatal("a message file is required (use -h for help)");

    const raw = std.fs.cwd().readFileAlloc(allocator, msg_path, MAX_MESSAGE_BYTES) catch |err| {
        writeErr("securearc-check: cannot read ");
        writeErr(msg_path);
        writeErr(": ");
        writeErr(@errorName(err));
        writeErr("\n");
        process.exit(2);
    };
    defer allocator.free(raw);

    var msg = parseMessage(allocator, raw) catch return fatal("out of memory parsing message");
    defer msg.deinit();

    const ns_slice: []const []const u8 = &.{nameserver};
    var resolver = dns_mod.Resolver.init(allocator, .{
        .nameservers = ns_slice,
        .port = port,
        .timeout_ms = 5000,
        .retries = 2,
    });
    defer resolver.deinit();

    // Mirror flow.doVerify exactly, including the order of these three cases.
    //
    // A chain that fails to parse is `fail`, not `none` (RFC 8617 §5.1.2): a
    // sender that could downgrade a broken chain to "unsealed" by malforming it
    // would defeat the point of the chain. The conformance suite tests that
    // distinction directly, which is why the check tool must not simplify it.
    const sets = arc.parseArcSets(allocator, msg.headers) catch |err| {
        if (err == error.OutOfMemory) return fatal("out of memory parsing ARC sets");
        writeOut("fail");
        if (verbose) {
            writeOut(" reason=");
            writeOut(arc.describeChainError(err));
        }
        writeOut("\n");
        return;
    };
    defer allocator.free(sets);

    if (sets.len == 0) {
        writeOut("none\n");
        return;
    }

    const result = chain.validateChain(
        allocator,
        &resolver,
        sets,
        msg.headers,
        msg.body,
        min_key_bits,
    );

    // An unevaluable chain is reported as `temperror`, distinct from `fail`.
    // A verifier that collapsed the two would be the A-12 defect, and a suite
    // run that silently accepted `fail` for a DNS outage would be scoring the
    // wrong thing.
    switch (result.evaluation) {
        .complete => writeOut(chainToString(result.status)),
        .dns_temp_error => writeOut("temperror"),
        .internal_error => writeOut("internalerror"),
    }
    if (verbose) {
        var buf: [256]u8 = undefined;
        const extra = std.fmt.bufPrint(&buf, " i={d} reason={s}", .{
            result.highest_instance,
            result.failure_reason orelse "-",
        }) catch " (detail unavailable)";
        writeOut(extra);
    }
    writeOut("\n");
}

/// `unknown` is deliberately given its own token rather than being folded into
/// one of the three cv values. It means "no determination was made", and
/// `validateChain` only pairs it with a non-`complete` evaluation — so seeing it
/// here would be an invariant violation, not a verdict. Printing something the
/// suite cannot match makes that loud instead of scoring it as a pass or a fail.
fn chainToString(v: arc.ChainValidation) []const u8 {
    return switch (v) {
        .none => "none",
        .pass => "pass",
        .fail => "fail",
        .unknown => "unknown",
    };
}
